/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/jibuf.h>

#include <arpa/inet.h>

/*! \addtogroup jibuf Osmocom Jitter Buffer
 *  @{
 */

/*! \file jibuf.c
 *  \brief Osmocom Jitter Buffer helpers
 */

/* Sampling rate (in Hz) */
/* TODO: SAMPLE RATE can be guessed from rtp.p_type */
#define SAMPLES_PER_PKT 160
#define SAMPLE_RATE 8000

/* TUNABLE PARAMETERS: */

/* default {min,max}_delay values if set_{min,max}_delay() is never called */
#define JIBUF_DEFAULT_MIN_DELAY_MS 60
#define JIBUF_DEFAULT_MAX_DELAY_MS 200

/* How frequently (num of input packets) do we reselect a new reference? */
#define JIBUF_REFERENCE_TS_FREQ 60

/* How frequently (num of input packets) do we check if we should adapt the
 * buffer size (threshold_delay) ? */
#define JIBUF_BUFFER_RECALC_FREQ 40
/* How many pkts should be dropped at max every JIBUF_BUFFER_RECALC_FREQ input
 * pkts? */
#define JIBUF_ALLOWED_PKT_DROP 3
/* How many consecutive pkts can be dropped before triggering a buffer size incr ? */
#define JIBUF_ALLOWED_PKT_CONSECUTIVE_DROP 1
/* How much do we incr/decr the buffer size every time we recalculate it? */
#define JIBUF_BUFFER_INC_STEP 20
#define JIBUF_BUFFER_DEC_STEP 5

/* weight of each new packet in calculation of clock skew */
#define JIBUF_SKEW_WEIGHT ((double)1/32)

struct osmo_jibuf_msgb_cb {
	struct timeval ts;
	unsigned long *old_cb;
};

#define JIBUF_MSGB_CB(__msgb) ((struct osmo_jibuf_msgb_cb *)&((__msgb)->cb[0]))

static void ms2timeval(struct timeval *ts, uint32_t ms)
{
	ts->tv_sec = ms / 1000;
	ts->tv_usec = (ms % 1000) * 1000;
}

static uint32_t timeval2ms(const struct timeval *ts)
{
	return ts->tv_sec * 1000 + ts->tv_usec / 1000;
}

static int clock_gettime_timeval(clockid_t clk_id, struct timeval *tp)
{
	struct timespec now;
	int n;

	n = osmo_clock_gettime(clk_id, &now);
	tp->tv_sec = now.tv_sec;
	tp->tv_usec = now.tv_nsec / 1000;

	return n;
}

static struct timeval *msgb_scheduled_ts(const struct msgb *msg)
{
	struct osmo_jibuf_msgb_cb *jbcb = JIBUF_MSGB_CB(msg);
	return &jbcb->ts;
}

/* Add msgb to the list sorted by its scheduled output ts */
static void llist_add_sorted(struct msgb *msg, struct llist_head *msg_list)
{
	struct msgb *cur;
	struct timeval *msg_ts = msgb_scheduled_ts(msg);

	/* TODO: not sure if I need to use _safe here */
	llist_for_each_entry(cur, msg_list, list) {
		struct timeval *cur_ts = msgb_scheduled_ts(cur);
		if (timercmp(msg_ts, cur_ts, <)) {
			__llist_add(&msg->list, cur->list.prev, &cur->list);
			return;
		}
	}

	/* we reached the end, add to the tail: */
	llist_add_tail(&msg->list, msg_list);

}

static void enqueue_pkt(struct osmo_jibuf *jb, struct msgb  *msg, bool is_syncpoint)
{
	struct msgb *cur;
	struct timeval *msg_ts;

	if (!is_syncpoint) {
		llist_add_sorted(msg, &jb->msg_list);
		return;
	}

	/* syncpoints change the reference timings, and as such they can provoke
	   out of order enqueuing of this packet and its followups with regards
	   to the already stored packets which may be scheduled for later times.
	   We thus need to adapt dequeue time for the already stored pkts to be
	   dequeued before the syncpoint pkt. See OS#3262 for related scenarios.
	*/

	msg_ts = msgb_scheduled_ts(msg);

	llist_for_each_entry(cur, &jb->msg_list, list) {
		struct timeval *cur_ts = msgb_scheduled_ts(cur);
		if (timercmp(msg_ts, cur_ts, <))
			*cur_ts = *msg_ts;
	}
	/* syncpoint goes always to the end since we moved all older packets
	   before it */
	llist_add_tail(&msg->list, &jb->msg_list);
}

static bool msg_get_marker(struct msgb *msg)
{
	/* TODO: make it more generic as a callback so that different types of
	 * pkts can be used ? */
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	return rtph->marker;
}

static uint16_t msg_get_sequence(struct msgb *msg)
{
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	return ntohs(rtph->sequence);
}

static uint32_t msg_get_timestamp(struct msgb *msg)
{
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	return ntohl(rtph->timestamp);
}

static int32_t samples2ms(int32_t samples)
{
	/* XXX: SAMPLE RATE can be guessed from rtp.p_type */
	return samples * 1000 / SAMPLE_RATE;
}

/* Calculates pkt delay related to reference pkt. Similar concept to D(i,j) as
 * defined in RFC3550 (RTP). */
static int calc_pkt_rel_delay(struct osmo_jibuf *jb, struct msgb *msg)
{
	uint32_t current_rx_ts = timeval2ms(&jb->last_enqueue_time);
	uint32_t current_tx_ts = msg_get_timestamp(msg);

	return samples2ms((current_tx_ts - jb->ref_tx_ts)) - (current_rx_ts - jb->ref_rx_ts);
}

static bool msg_is_in_sequence(struct osmo_jibuf *jb, struct msgb *msg)
{
	uint32_t current_tx_ts = msg_get_timestamp(msg);
	uint16_t current_seq = msg_get_sequence(msg);
	return (current_tx_ts - jb->ref_tx_ts) == (current_seq - jb->ref_tx_seq)*SAMPLES_PER_PKT;
}

/* If packet contains a mark -> start of talkspurt.
 * A lot of packets may have been suppressed by the sender before it,
 * so let's take it as a reference
 * If packet timestamp is not aligned with sequence
 * number, then we are most probaly starting a talkspurt */
static bool msg_is_syncpoint(struct osmo_jibuf *jb, struct msgb* msg)
{
	bool res = msg_get_marker(msg) || !msg_is_in_sequence(jb, msg);
	if(res)
		LOGP(DLMIB, LOGL_DEBUG, "syncpoint: %"PRIu16": marker=%d in_seq=%d\n",
			msg_get_sequence(msg), msg_get_marker(msg), msg_is_in_sequence(jb, msg));
	return res;
}

static void msg_set_as_reference(struct osmo_jibuf *jb, struct msgb *msg)
{
	jb->ref_rx_ts = timeval2ms(&jb->last_enqueue_time);
	jb->ref_tx_ts = msg_get_timestamp(msg);
	jb->ref_tx_seq = msg_get_sequence(msg);
	jb->skew_us = 0;

	LOGP(DLJIBUF, LOGL_DEBUG, "New reference (seq=%"PRIu16" rx=%"PRIu32 \
		" tx=%"PRIu32")\n", jb->ref_tx_seq, jb->ref_rx_ts, jb->ref_tx_ts);
}

static void dequeue_msg(struct osmo_jibuf *jb, struct msgb *msg)
{
	unsigned long *old_cb = JIBUF_MSGB_CB(msg)->old_cb;
	memcpy(msg->cb, old_cb, sizeof(msg->cb));
	talloc_free(old_cb);
	llist_del(&msg->list);

	jb->dequeue_cb(msg, jb->dequeue_cb_data);
}

static void timer_expired(void *data)
{
	struct osmo_jibuf *jb = (struct osmo_jibuf*) data;
		struct timeval delay_ts, now;
		struct msgb *msg, *next;

	llist_for_each_entry_safe(msg, next, &jb->msg_list, list) {
	struct timeval *msg_ts = msgb_scheduled_ts(msg);
			clock_gettime_timeval(CLOCK_MONOTONIC, &now);
	if (timercmp(msg_ts, &now, >)) {
				jb->next_dequeue_time = *msg_ts;
				timersub(msg_ts, &now, &delay_ts);
				osmo_timer_schedule(&jb->timer,
					delay_ts.tv_sec, delay_ts.tv_usec);
				return;
			}

			dequeue_msg(jb, msg);
	}

	/* XXX: maybe  try to tune the threshold based on the calculated output jitter? */
	/* XXX: try to find holes in the list and create fake pkts to improve the
		 jitter when packets do not arrive on time */
}

static void recalc_clock_skew(struct osmo_jibuf *jb, int32_t rel_delay)
{
	if(!jb->skew_enabled)
		return;

	jb->skew_us = (int32_t) (rel_delay * 1000 * JIBUF_SKEW_WEIGHT + jb->skew_us * (1.0 - JIBUF_SKEW_WEIGHT));
}

static void recalc_threshold_delay(struct osmo_jibuf *jb)
{

	/* Recalculate every JIBUF_RECALC_FREQ_PKTS handled packets, or if we have too
		 many consecutive drops */
	uint32_t sum_pkts = jb->stats.total_enqueued + jb->stats.total_dropped +
								jb->last_dropped;

	if (jb->consecutive_drops <= JIBUF_ALLOWED_PKT_CONSECUTIVE_DROP &&
					sum_pkts % JIBUF_BUFFER_RECALC_FREQ != 0)
		return;

	if (jb->consecutive_drops > JIBUF_ALLOWED_PKT_CONSECUTIVE_DROP ||
					jb->last_dropped > JIBUF_ALLOWED_PKT_DROP)
		jb->threshold_delay = OSMO_MIN(
					jb->threshold_delay + JIBUF_BUFFER_INC_STEP,
					jb->max_delay);
	else
		jb->threshold_delay = OSMO_MAX(
					jb->threshold_delay - JIBUF_BUFFER_DEC_STEP,
					jb->min_delay);
	LOGP(DLJIBUF, LOGL_DEBUG, "New threshold: %u ms (freq=%d dropped=%d/%d consecutive=%d/%d)\n",
			jb->threshold_delay, JIBUF_BUFFER_RECALC_FREQ,
			jb->last_dropped, JIBUF_ALLOWED_PKT_DROP,
			jb->consecutive_drops, JIBUF_ALLOWED_PKT_CONSECUTIVE_DROP);

	jb->stats.total_dropped += jb->last_dropped;
	jb->last_dropped = 0;

}

//----------------------------------

/*! \brief Allocate a new jitter buffer instance
 *  \return the new allocated instance
 */
struct osmo_jibuf *osmo_jibuf_alloc(void *talloc_ctx)
{
	struct osmo_jibuf *jb;
	jb = talloc_zero(talloc_ctx, struct osmo_jibuf);

	jb->min_delay = JIBUF_DEFAULT_MIN_DELAY_MS;
	jb->max_delay = JIBUF_DEFAULT_MAX_DELAY_MS;
	jb->threshold_delay = jb->min_delay;

	INIT_LLIST_HEAD(&jb->msg_list);

	jb->timer.cb = timer_expired;
	jb->timer.data = jb;

	return jb;
}

/*! \brief Destroy a previously allocated jitter buffer instance
 *  \param[in] jb Previously allocated (non-null) jitter buffer instance
 *
 * All the queued packets are dequeued before deleting the instance.
 */
void osmo_jibuf_delete(struct osmo_jibuf *jb)
{
	struct msgb *msg, *tmp;
	osmo_timer_del(&jb->timer);
	llist_for_each_entry_safe(msg, tmp, &jb->msg_list, list)
		dequeue_msg(jb, msg);

	talloc_free(jb);
}

/*! \brief Try to enqueue a packet into the jitter buffer
 *  \param[in] jb jitter buffer instance
 *  \param[in] msg msgb to enqueue, containing an RTP packet
 *  \return <0 if the packet was dropped, 0 otherwise
 *
 * This function calculates the delay for the enqueued packet. If the delay is
 * bigger than the current buffer size, the function returns -1 and the caller
 * owns the packet again and can free it if required. If the packet is enqueued,
 * 0 is returned and the exact same packet (ownership transfer, no copy is made)
 * will be available again through the dequeue_cb() when the queue timer for
 * this packet expires.
 */
int osmo_jibuf_enqueue(struct osmo_jibuf *jb, struct msgb *msg)
{
	int rel_delay, delay;
	struct timeval delay_ts, sched_ts;
	bool is_syncpoint;

	clock_gettime_timeval(CLOCK_MONOTONIC, &jb->last_enqueue_time);

	/* Check if it's time to sync, ie. start of talkspurt */
	is_syncpoint = !jb->started || msg_is_syncpoint(jb, msg);
	if (is_syncpoint) {
		jb->started = true;
		msg_set_as_reference(jb, msg);
		rel_delay = 0;
	} else {
		rel_delay = calc_pkt_rel_delay(jb, msg);
		recalc_clock_skew(jb, rel_delay);
	}

	/* Avoid time skew with sender (or drop-everything state),
	   reselect a new reference from time to time */
	//if ((int)(msg_get_sequence(msg) - jb->ref_tx_seq) > JIBUF_REFERENCE_TS_FREQ)
	//	msg_set_as_reference(jb, msg);

	delay = jb->threshold_delay + rel_delay - jb->skew_us/1000;

	/* packet too late, let's drop it and incr buffer size if encouraged */
	if (delay < 0) {
		jb->last_dropped++;
		jb->consecutive_drops++;

		LOGP(DLJIBUF, LOGL_DEBUG, "dropped %u > %u (seq=%"PRIu16" ts=%"PRIu32")\n",
			rel_delay, jb->threshold_delay, msg_get_sequence(msg),
			msg_get_timestamp(msg));

		recalc_threshold_delay(jb);
		return -1;
	} else {
		jb->consecutive_drops = 0;
		jb->stats.total_enqueued++;
	}

	ms2timeval(&delay_ts, (uint32_t) delay);
	timeradd(&jb->last_enqueue_time, &delay_ts, &sched_ts);

	LOGP(DLJIBUF, LOGL_DEBUG, "enqueuing packet seq=%"PRIu16" rel=%d delay=%d" \
		" skew=%d thres=%d {%lu.%06lu -> %lu.%06lu} %s\n",
		msg_get_sequence(msg), rel_delay, delay, jb->skew_us, jb->threshold_delay,
		jb->last_enqueue_time.tv_sec, jb->last_enqueue_time.tv_usec,
		sched_ts.tv_sec, sched_ts.tv_usec, msg_get_marker(msg)? "M" : "");

	/* Add scheduled dequeue time in msg->cb so we can check it later */
	unsigned long *old_cb = talloc_memdup(jb->talloc_ctx, msg->cb, sizeof(msg->cb));
	struct osmo_jibuf_msgb_cb *jbcb = JIBUF_MSGB_CB(msg);
	jbcb->ts = sched_ts;
	jbcb->old_cb = old_cb;

	enqueue_pkt(jb, msg, is_syncpoint);

	/* See if updating the timer is needed: */
	if (!osmo_timer_pending(&jb->timer) ||
			timercmp(&sched_ts, &jb->next_dequeue_time, <))  {
		jb->next_dequeue_time = sched_ts;
		osmo_timer_schedule(&jb->timer, 0, delay * 1000);
	}

	/* Let's check packet loss stats to see if buffer_size must be changed */
	recalc_threshold_delay(jb);

	return 0;
}

/*! \brief Check whether the jitter buffer instance has packets queued or not.
 *  \param[in] jb jitter buffer instance
 *  \return true if the queue is empty, false otherwise.
 */
bool osmo_jibuf_empty(struct osmo_jibuf *jb)
{
	return llist_empty(&jb->msg_list);
}

/*! \brief Set minimum buffer size for the jitter buffer
 *  \param[in] jb jitter buffer instance
 *  \param[in] min_delay Minimum buffer size, as in minimum delay in milliseconds
 */
void osmo_jibuf_set_min_delay(struct osmo_jibuf *jb, uint32_t min_delay)
{
	jb->min_delay = min_delay ? min_delay : JIBUF_DEFAULT_MIN_DELAY_MS;
	jb->threshold_delay = OSMO_MAX(jb->min_delay, jb->threshold_delay);
}

/*! \brief Set maximum buffer size for the jitter buffer
 *  \param[in] jb jitter buffer instance
 *  \param[in] max_delay Maximum buffer size, as in maximum delay in milliseconds
 */
void osmo_jibuf_set_max_delay(struct osmo_jibuf *jb, uint32_t max_delay)
{
	jb->max_delay = max_delay ? max_delay : JIBUF_DEFAULT_MAX_DELAY_MS;
	jb->threshold_delay = OSMO_MIN(jb->max_delay, jb->threshold_delay);
}

/*! \brief Toggle use of skew detection and compensation mechanism
 *  \param[in] jb jitter buffer instance
 *  \param[in] enable Whether to enable or not (default) the skew estimation and compensation mechanism
 *
 * When this function is called, the estimated skew is reset.
 */
void osmo_jibuf_enable_skew_compensation(struct osmo_jibuf *jb, bool enable)
{
	jb->skew_enabled = enable;
	jb->skew_us = 0;
}

/*! \brief Set dequeue callback for the jitter buffer
 *  \param[in] jb jitter buffer instance
 *  \param[in] dequeue_cb function pointer to call back when the dequeue timer for a given packet expires
 *  \param[in] cb_data data pointer to be passed to dequeue_cb together with the msgb.
 */
void osmo_jibuf_set_dequeue_cb(struct osmo_jibuf *jb, osmo_jibuf_dequeue_cb
						dequeue_cb, void* cb_data)
{
	jb->dequeue_cb = dequeue_cb;
	jb->dequeue_cb_data = cb_data;
}

/*! @} */
