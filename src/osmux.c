/*
 * (C) 2012-2017 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 * (C) 2015-2017 by sysmocom - s.f.m.c. GmbH
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include <arpa/inet.h>

/*! \addtogroup osmux Osmocom Multiplex Protocol
 *  @{
 *
 *  This code implements a variety of utility functions related to the
 *  OSMUX user-plane multiplexing protocol, an efficient alternative to
 *  plain UDP/RTP streams for voice transport in back-haul of cellular
 *  networks.
 *
 *  For information about the OSMUX protocol design, please see the
 *  OSMUX reference manual at
 *  http://ftp.osmocom.org/docs/latest/osmux-reference.pdf
 */

/*! \file osmux.c
 *  \brief Osmocom multiplex protocol helpers
 */

/* This allows you to debug osmux message transformations (spamming) */
#if 0
#define DEBUG_MSG		0
#endif

/* delta time between two RTP messages (in microseconds) */
#define DELTA_RTP_MSG		20000
/* delta time between two RTP messages (in samples, 8kHz) */
#define DELTA_RTP_TIMESTAMP	160

static void *osmux_ctx;

static uint32_t osmux_get_payload_len(struct osmux_hdr *osmuxh)
{
	return osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1);
}

static uint32_t osmux_ft_dummy_size(uint8_t amr_ft, uint8_t batch_factor)
{
	return sizeof(struct osmux_hdr) + (osmo_amr_bytes(amr_ft) * batch_factor);
}

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh;
next:
	osmuxh = NULL;
	if (msg->len > sizeof(struct osmux_hdr)) {
		size_t len;

		osmuxh = (struct osmux_hdr *)msg->data;

		switch (osmuxh->ft) {
		case OSMUX_FT_VOICE_AMR:
			break;
		case OSMUX_FT_DUMMY:
			len = osmux_ft_dummy_size(osmuxh->amr_ft, osmuxh->ctr + 1);
			if (msgb_length(msg) < len) {
				LOGP(DLMUX, LOGL_ERROR, "Discarding bad Dummy FT: %s\n",
					osmo_hexdump(msg->data, msgb_length(msg)));
				return NULL;
			}
			msgb_pull(msg, len);
			goto next;
		default:
			LOGP(DLMUX, LOGL_ERROR, "Discarding unsupported Osmux FT %d\n",
			     osmuxh->ft);
			return NULL;
		}
		if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
			LOGP(DLMUX, LOGL_ERROR, "Discarding bad AMR FT %d\n",
			     osmuxh->amr_ft);
			return NULL;
		}

		len = osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1) +
			sizeof(struct osmux_hdr);

		if (msgb_length(msg) < len) {
			LOGP(DLMUX, LOGL_ERROR,
				"Discarding malformed OSMUX message: %s\n",
				osmo_hexdump(msg->data, msgb_length(msg)));
			return NULL;
		}

		msgb_pull(msg, len);
	} else if (msg->len > 0) {
		LOGP(DLMUX, LOGL_ERROR,
			"remaining %d bytes, broken osmuxhdr?\n", msg->len);
	}

	return osmuxh;
}

static struct msgb *
osmux_rebuild_rtp(struct osmux_out_handle *h, struct osmux_hdr *osmuxh,
		  void *payload, int payload_len, bool first_pkt)
{
	struct msgb *prev_msg, *out_msg;
	struct timespec *prev_ts, *out_ts;
	struct rtp_hdr *rtph;
	struct amr_hdr *amrh;
	struct timespec delta = { .tv_sec = 0, .tv_nsec = DELTA_RTP_MSG*1000 };

	out_msg = msgb_alloc(sizeof(struct rtp_hdr) +
			     sizeof(struct amr_hdr) +
			     osmo_amr_bytes(osmuxh->amr_ft),
			     "OSMUX test");
	if (out_msg == NULL)
		return NULL;

	/* Reconstruct RTP header */
	rtph = (struct rtp_hdr *)out_msg->data;
	rtph->csrc_count = 0;
	rtph->extension = 0;
	rtph->version = RTP_VERSION;
	rtph->payload_type = h->rtp_payload_type;
	/* ... emulate timestamp and ssrc */
	rtph->timestamp = htonl(h->rtp_timestamp);
	rtph->sequence = htons(h->rtp_seq);
	rtph->ssrc = htonl(h->rtp_ssrc);
	/* rtp packet with the marker bit is always guaranteed to be the first
	 * one. We want to notify with marker in 2 scenarios:
	 * 1- Sender told us through osmux frame rtp_m.
	 * 2- Sntermediate osmux frame lost (seq gap), otherwise rtp receiver only sees
	 *    steady increase of delay
	 */
	rtph->marker = first_pkt &&
			(osmuxh->rtp_m || (osmuxh->seq != h->osmux_seq_ack + 1));

	msgb_put(out_msg, sizeof(struct rtp_hdr));

	/* Reconstruct AMR header */
	amrh = (struct amr_hdr *)out_msg->tail;
	amrh->cmr = osmuxh->amr_cmr;
	amrh->f = osmuxh->amr_f;
	amrh->ft = osmuxh->amr_ft;
	amrh->q = osmuxh->amr_q;

	msgb_put(out_msg, sizeof(struct amr_hdr));

	/* add AMR speech data */
	memcpy(out_msg->tail, payload, payload_len);
	msgb_put(out_msg, payload_len);

	/* bump last RTP sequence number and timestamp that has been used */
	h->rtp_seq++;
	h->rtp_timestamp += DELTA_RTP_TIMESTAMP;

	out_ts = ((struct timespec *)&((out_msg)->cb[0]));
	if (first_pkt || llist_empty(&h->list)) {
		osmo_clock_gettime(CLOCK_MONOTONIC, out_ts);
	} else {
		prev_msg = llist_last_entry(&h->list, struct msgb, list);
		prev_ts = ((struct timespec *)&((prev_msg)->cb[0]));
		timespecadd(prev_ts, &delta, out_ts);
	}

	return out_msg;
}

static void osmux_xfrm_output_trigger(void *data)
{
	struct osmux_out_handle *h = data;
	struct timespec delay_ts, now;
	struct msgb *msg, *next;

	llist_for_each_entry_safe(msg, next, &h->list, list) {
		osmo_clock_gettime(CLOCK_MONOTONIC, &now);
		struct timespec *msg_ts = ((struct timespec *)&((msg)->cb[0]));
		if (timespeccmp(msg_ts, &now, >)) {
			timespecsub(msg_ts, &now, &delay_ts);
			osmo_timer_schedule(&h->timer,
				delay_ts.tv_sec, delay_ts.tv_nsec / 1000);
			return;
		}

		/* Transmit the rtp packet */
		llist_del(&msg->list);
		if (h->tx_cb)
			h->tx_cb(msg, h->data);
		else
			msgb_free(msg);
	}
}

/*! \brief Generate RTP packets from osmux frame AMR payload set and schedule
 *         them for transmission at appropiate time.
 *  \param[in] h the osmux out handle handling a specific CID
 *  \param[in] osmuxh Buffer pointing to osmux frame header structure and AMR payload
 *  \return Number of generated RTP packets
 *
 * The osmux frame passed to this function must be of the type OSMUX_FT_VOICE_AMR.
 * The generated RTP packets are kept into h's internal list and sent to the
 * callback configured through osmux_xfrm_output_set_tx_cb when are ready to be
 * transmitted according to schedule.
 */
int osmux_xfrm_output_sched(struct osmux_out_handle *h, struct osmux_hdr *osmuxh)
{
	struct timespec now, *msg_ts;
	struct msgb *msg;
	int i;
	bool was_empty = llist_empty(&h->list);

	if (!was_empty) {
		/* If we received new data it means we are behind schedule and
		 * we should flush all previous quickly */
		osmo_clock_gettime(CLOCK_MONOTONIC, &now);
		llist_for_each_entry(msg, &h->list, list) {
			msg_ts = ((struct timespec *)&((msg)->cb[0]));
			*msg_ts = now;
		}
		osmo_timer_schedule(&h->timer, 0, 0);
	}

	for (i=0; i<osmuxh->ctr+1; i++) {
		struct rtp_hdr *rtph;

		msg = osmux_rebuild_rtp(h, osmuxh,
					osmux_get_payload(osmuxh) +
					i * osmo_amr_bytes(osmuxh->amr_ft),
					osmo_amr_bytes(osmuxh->amr_ft), !i);
		if (msg == NULL)
			continue;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			continue;

		llist_add_tail(&msg->list, &h->list);
	}

	/* Update last seen seq number: */
	h->osmux_seq_ack = osmuxh->seq;

	/* In case list is still empty after parsing messages, no need to rearm */
	if(was_empty && !llist_empty(&h->list))
		osmux_xfrm_output_trigger(h);
	return i;
}

/*! \brief Flush all scheduled RTP packets still pending to be transmitted
 *  \param[in] h the osmux out handle to flush
 *
 * This function will immediately call the transmit callback for all queued RTP
 * packets, making sure the list ends up empty. It will also stop all internal
 * timers to make sure the osmux_out_handle can be dropped or re-used by calling
 * osmux_xfrm_output on it.
 */
void osmux_xfrm_output_flush(struct osmux_out_handle *h)
{
	struct msgb *msg, *next;

	if (osmo_timer_pending(&h->timer))
		osmo_timer_del(&h->timer);

	llist_for_each_entry_safe(msg, next, &h->list, list) {
		llist_del(&msg->list);
		if (h->tx_cb)
			h->tx_cb(msg, h->data);
		else
			msgb_free(msg);
	}
}

struct osmux_batch {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	circuit_list;
	unsigned int		remaining_bytes;
	uint8_t			seq;
	uint32_t		nmsgs;
	int			ndummy;
};

struct osmux_circuit {
	struct llist_head	head;
	int			ccid;
	struct llist_head	msg_list;
	int			nmsgs;
	int			dummy;
};

static int osmux_batch_enqueue(struct msgb *msg, struct osmux_circuit *circuit,
				uint8_t batch_factor)
{
	/* Validate amount of messages per batch. The counter field of the
	 * osmux header is just 3 bits long, so make sure it doesn't overflow.
	 */
	if (circuit->nmsgs >= batch_factor || circuit->nmsgs >= 8) {
		struct rtp_hdr *rtph;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			return -1;

		LOGP(DLMUX, LOGL_DEBUG, "Batch is full for RTP sssrc=%u\n", rtph->ssrc);
		return -1;
	}

	llist_add_tail(&msg->list, &circuit->msg_list);
	circuit->nmsgs++;
	return 0;
}

static void osmux_batch_dequeue(struct msgb *msg, struct osmux_circuit *circuit)
{
	llist_del(&msg->list);
	circuit->nmsgs--;
}

static void osmux_circuit_del_msgs(struct osmux_batch *batch, struct osmux_circuit *circuit)
{
	struct msgb *cur, *tmp;
	llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
		osmux_batch_dequeue(cur, circuit);
		msgb_free(cur);
		batch->nmsgs--;
	}
}

struct osmux_input_state {
	struct msgb	*out_msg;
	struct msgb	*msg;
	struct rtp_hdr	*rtph;
	struct amr_hdr	*amrh;
	uint32_t	amr_payload_len;
	int		ccid;
	int		add_osmux_hdr;
};

static int osmux_batch_put(struct osmux_batch *batch,
			   struct osmux_input_state *state)
{
	struct osmux_hdr *osmuxh;

	if (state->add_osmux_hdr) {
		osmuxh = (struct osmux_hdr *)state->out_msg->tail;
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->rtp_m = osmuxh->rtp_m || state->rtph->marker;
		osmuxh->amr_f = state->amrh->f;
		osmuxh->amr_q= state->amrh->q;
		osmuxh->seq = batch->seq++;
		osmuxh->circuit_id = state->ccid;
		osmuxh->amr_cmr = state->amrh->cmr;
		osmuxh->amr_ft = state->amrh->ft;
		msgb_put(state->out_msg, sizeof(struct osmux_hdr));

		/* annotate current osmux header */
		batch->osmuxh = osmuxh;
	} else {
		if (batch->osmuxh->ctr == 0x7) {
			LOGP(DLMUX, LOGL_ERROR, "cannot add msg=%p, "
			     "too many messages for this RTP ssrc=%u\n",
			     state->msg, state->rtph->ssrc);
			return 0;
		}
		batch->osmuxh->ctr++;
	}

	memcpy(state->out_msg->tail, osmo_amr_get_payload(state->amrh),
	       state->amr_payload_len);
	msgb_put(state->out_msg, state->amr_payload_len);

	return 0;
}

static int osmux_xfrm_encode_amr(struct osmux_batch *batch,
				 struct osmux_input_state *state)
{
	uint32_t amr_len;

	state->amrh = osmo_rtp_get_payload(state->rtph, state->msg, &amr_len);
	if (state->amrh == NULL)
		return -1;

	state->amr_payload_len = amr_len - sizeof(struct amr_hdr);

	if (osmux_batch_put(batch, state) < 0)
		return -1;

	return 0;
}

static void osmux_encode_dummy(struct osmux_batch *batch, uint8_t batch_factor,
			       struct osmux_input_state *state)
{
	struct osmux_hdr *osmuxh;
	/* TODO: This should be configurable at some point. */
	uint32_t payload_size = osmux_ft_dummy_size(AMR_FT_3, batch_factor) -
				sizeof(struct osmux_hdr);

	osmuxh = (struct osmux_hdr *)state->out_msg->tail;
	osmuxh->ft = OSMUX_FT_DUMMY;
	osmuxh->ctr = batch_factor - 1;
	osmuxh->amr_f = 0;
	osmuxh->amr_q= 0;
	osmuxh->seq = 0;
	osmuxh->circuit_id = state->ccid;
	osmuxh->amr_cmr = 0;
	osmuxh->amr_ft = AMR_FT_3;
	msgb_put(state->out_msg, sizeof(struct osmux_hdr));

	memset(state->out_msg->tail, 0xff, payload_size);
	msgb_put(state->out_msg, payload_size);
}

static struct msgb *osmux_build_batch(struct osmux_batch *batch,
				      uint32_t batch_size, uint8_t batch_factor)
{
	struct msgb *batch_msg;
	struct osmux_circuit *circuit;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "Now building batch\n");
#endif

	batch_msg = msgb_alloc(batch_size, "osmux");
	if (batch_msg == NULL) {
		LOGP(DLMUX, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	llist_for_each_entry(circuit, &batch->circuit_list, head) {
		struct msgb *cur, *tmp;
		int ctr = 0;

		if (circuit->dummy) {
			struct osmux_input_state state = {
				.out_msg	= batch_msg,
				.ccid		= circuit->ccid,
			};
			osmux_encode_dummy(batch, batch_factor, &state);
			continue;
		}

		llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
			struct osmux_input_state state = {
				.msg		= cur,
				.out_msg	= batch_msg,
				.ccid		= circuit->ccid,
			};
#ifdef DEBUG_MSG
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), cur);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMUX, LOGL_DEBUG, "to BSC-NAT: %s\n", buf);
#endif

			state.rtph = osmo_rtp_get_hdr(cur);
			if (state.rtph == NULL)
				return NULL;

			if (ctr == 0) {
#ifdef DEBUG_MSG
				LOGP(DLMUX, LOGL_DEBUG, "add osmux header\n");
#endif
				state.add_osmux_hdr = 1;
			}

			osmux_xfrm_encode_amr(batch, &state);
			osmux_batch_dequeue(cur, circuit);
			msgb_free(cur);
			ctr++;
			batch->nmsgs--;
		}
	}
	return batch_msg;
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "invoking delivery function\n");
#endif
	batch_msg = osmux_build_batch(batch, h->batch_size, h->batch_factor);
	if (!batch_msg)
		return;
	h->stats.output_osmux_msgs++;
	h->stats.output_osmux_bytes += batch_msg->len;

	h->deliver(batch_msg, h->data);
	osmo_timer_del(&batch->timer);
	batch->remaining_bytes = h->batch_size;

	if (batch->ndummy) {
		osmo_timer_schedule(&batch->timer, 0,
				    h->batch_factor * DELTA_RTP_MSG);
	}
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "osmux_batch_timer_expired\n");
#endif
	osmux_xfrm_input_deliver(h);
}

static int osmux_rtp_amr_payload_len(struct msgb *msg, struct rtp_hdr *rtph)
{
	struct amr_hdr *amrh;
	unsigned int amr_len;
	int amr_payload_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	if (!osmo_amr_ft_valid(amrh->ft))
		return -1;

	amr_payload_len = amr_len - sizeof(struct amr_hdr);

	/* The AMR payload does not fit with what we expect */
	if (osmo_amr_bytes(amrh->ft) != amr_payload_len) {
		LOGP(DLMUX, LOGL_ERROR,
		     "Bad AMR frame, expected %zd bytes, got %d bytes\n",
		     osmo_amr_bytes(amrh->ft), amr_len);
		return -1;
	}
	return amr_payload_len;
}

static void osmux_replay_lost_packets(struct osmux_circuit *circuit,
				      struct rtp_hdr *cur_rtph, int batch_factor)
{
	int16_t diff;
	struct msgb *last;
	struct rtp_hdr *rtph;
	int i;

	/* Have we see any RTP packet in this batch before? */
	if (llist_empty(&circuit->msg_list))
		return;

	/* Get last RTP packet seen in this batch */
	last = llist_entry(circuit->msg_list.prev, struct msgb, list);
	rtph = osmo_rtp_get_hdr(last);
	if (rtph == NULL)
		return;

	diff = ntohs(cur_rtph->sequence) - ntohs(rtph->sequence);

	/* Lifesaver: make sure bugs don't spawn lots of clones */
	if (diff > 16)
		diff = 16;

	/* If diff between last RTP packet seen and this one is > 1,
	 * then we lost several RTP packets, let's replay them.
	 */
	for (i=1; i<diff; i++) {
		struct msgb *clone;

		/* Clone last RTP packet seen */
		clone = msgb_alloc(last->data_len, "RTP clone");
		if (!clone)
			continue;

		memcpy(clone->data, last->data, last->len);
		msgb_put(clone, last->len);

		/* The original RTP message has been already sanity check. */
		rtph = osmo_rtp_get_hdr(clone);

		/* Adjust sequence number and timestamp */
		rtph->sequence = htons(ntohs(rtph->sequence) + i);
		rtph->timestamp = htonl(ntohl(rtph->timestamp) +
					DELTA_RTP_TIMESTAMP);

		/* No more room in this batch, skip padding with more clones */
		if (osmux_batch_enqueue(clone, circuit, batch_factor) < 0) {
			msgb_free(clone);
			break;
		}

		LOGP(DLMUX, LOGL_ERROR, "adding cloned RTP\n");
	}
}

static struct osmux_circuit *
osmux_batch_find_circuit(struct osmux_batch *batch, int ccid)
{
	struct osmux_circuit *circuit;

	llist_for_each_entry(circuit, &batch->circuit_list, head) {
		if (circuit->ccid == ccid)
			return circuit;
	}
	return NULL;
}

static struct osmux_circuit *
osmux_batch_add_circuit(struct osmux_batch *batch, int ccid, int dummy,
			uint8_t batch_factor)
{
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit != NULL) {
		LOGP(DLMUX, LOGL_ERROR, "circuit %u already exists!\n", ccid);
		return NULL;
	}

	circuit = talloc_zero(osmux_ctx, struct osmux_circuit);
	if (circuit == NULL) {
		LOGP(DLMUX, LOGL_ERROR, "OOM on circuit %u\n", ccid);
		return NULL;
	}

	circuit->ccid = ccid;
	INIT_LLIST_HEAD(&circuit->msg_list);
	llist_add_tail(&circuit->head, &batch->circuit_list);

	if (dummy) {
		circuit->dummy = dummy;
		batch->ndummy++;
		if (!osmo_timer_pending(&batch->timer))
			osmo_timer_schedule(&batch->timer, 0,
					    batch_factor * DELTA_RTP_MSG);
	}
	return circuit;
}

static void osmux_batch_del_circuit(struct osmux_batch *batch, struct osmux_circuit *circuit)
{
	if (circuit->dummy)
		batch->ndummy--;
	llist_del(&circuit->head);
	osmux_circuit_del_msgs(batch, circuit);
	talloc_free(circuit);
}

static int
osmux_batch_add(struct osmux_batch *batch, uint32_t batch_factor, struct msgb *msg,
		struct rtp_hdr *rtph, int ccid)
{
	int bytes = 0, amr_payload_len;
	struct osmux_circuit *circuit;
	struct msgb *cur;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (!circuit)
		return -1;

	/* We've seen the first RTP message, disable dummy padding */
	if (circuit->dummy) {
		circuit->dummy = 0;
		batch->ndummy--;
	}
	amr_payload_len = osmux_rtp_amr_payload_len(msg, rtph);
	if (amr_payload_len < 0)
		return -1;

	/* First check if there is room for this message in the batch */
	bytes += amr_payload_len;
	if (circuit->nmsgs == 0)
		bytes += sizeof(struct osmux_hdr);

	/* No room, sorry. You'll have to retry */
	if (bytes > batch->remaining_bytes)
		return 1;

	/* Init of talkspurt (RTP M marker bit) needs to be in the first AMR slot
	 * of the OSMUX packet, enforce sending previous batch if required:
	 */
	if (rtph->marker && circuit->nmsgs != 0)
		return 1;


	/* Extra validation: check if this message already exists, should not
	 * happen but make sure we don't propagate duplicated messages.
	 */
	llist_for_each_entry(cur, &circuit->msg_list, list) {
		struct rtp_hdr *rtph2 = osmo_rtp_get_hdr(cur);
		if (rtph2 == NULL)
			return -1;

		/* Already exists message with this sequence, skip */
		if (rtph2->sequence == rtph->sequence) {
			LOGP(DLMUX, LOGL_ERROR, "already exists "
				"message with seq=%u, skip it\n",
				rtph->sequence);
			return -1;
		}
	}
	/* Handle RTP packet loss scenario */
	osmux_replay_lost_packets(circuit, rtph, batch_factor);

	/* This batch is full, force batch delivery */
	if (osmux_batch_enqueue(msg, circuit, batch_factor) < 0)
		return 1;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "adding msg with ssrc=%u to batch\n",
		rtph->ssrc);
#endif

	/* Update remaining room in this batch */
	batch->remaining_bytes -= bytes;

	if (batch->nmsgs == 0) {
#ifdef DEBUG_MSG
		LOGP(DLMUX, LOGL_DEBUG, "osmux start timer batch\n");
#endif
		osmo_timer_schedule(&batch->timer, 0,
				    batch_factor * DELTA_RTP_MSG);
	}
	batch->nmsgs++;

	return 0;
}

/**
 * osmux_xfrm_input - add RTP message to OSmux batch
 * \param msg: RTP message that you want to batch into one OSmux message
 *
 * If 0 is returned, this indicates that the message has been batched or that
 * an error occured and we have skipped the message. If 1 is returned, you
 * have to invoke osmux_xfrm_input_deliver and try again.
 *
 * The function takes care of releasing the messages in case of error and
 * when building the batch.
 */
int osmux_xfrm_input(struct osmux_in_handle *h, struct msgb *msg, int ccid)
{
	int ret;
	struct rtp_hdr *rtph;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	/* Ignore too big RTP/RTCP messages, most likely forged. Sanity check
	 * to avoid a possible forever loop in the caller.
	 */
	if (msg->len > h->batch_size - sizeof(struct osmux_hdr)) {
		msgb_free(msg);
		return 0;
	}

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		msgb_free(msg);
		return 0;
	}

	switch(rtph->payload_type) {
		case RTP_PT_RTCP:
			msgb_free(msg);
			return 0;
		default:
			/* The RTP payload type is dynamically allocated,
			 * although we use static ones. Assume that we always
			 * receive AMR traffic.
			 */

			/* Add this RTP to the OSMUX batch */
			ret = osmux_batch_add(batch, h->batch_factor,
					      msg, rtph, ccid);
			if (ret < 0) {
				/* Cannot put this message into the batch.
				 * Malformed, duplicated, OOM. Drop it and tell
				 * the upper layer that we have digest it.
				 */
				msgb_free(msg);
				return 0;
			}

			h->stats.input_rtp_msgs++;
			h->stats.input_rtp_bytes += msg->len;
			break;
	}
	return ret;
}

void osmux_xfrm_input_init(struct osmux_in_handle *h)
{
	struct osmux_batch *batch;

	/* Default to osmux packet size if not specified */
	if (h->batch_size == 0)
		h->batch_size = OSMUX_BATCH_DEFAULT_MAX;

	batch = talloc_zero(osmux_ctx, struct osmux_batch);
	if (batch == NULL)
		return;

	INIT_LLIST_HEAD(&batch->circuit_list);
	batch->remaining_bytes = h->batch_size;
	osmo_timer_setup(&batch->timer, osmux_batch_timer_expired, h);

	h->internal_data = (void *)batch;

	LOGP(DLMUX, LOGL_DEBUG, "initialized osmux input converter\n");
}

/*! \brief Set transmission callback to call when a generated RTP packet is to be transmitted
 *  \param[in] h the osmux out handle handling a specific CID
 *  \param[in] osmuxh Buffer pointing to osmux frame header structure and AMR payload
 *  \return Number of generated RTP packets
 *
 * This Function sets the callback called by the interal timer set by
 * osmux_xfrm_out_sched function.
 */
void osmux_xfrm_output_set_tx_cb(struct osmux_out_handle *h,
				void (*tx_cb)(struct msgb *msg, void *data),
				void *data)
{
	h->tx_cb = tx_cb;
	h->data = data;
}

int osmux_xfrm_input_open_circuit(struct osmux_in_handle *h, int ccid,
				  int dummy)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	return osmux_batch_add_circuit(batch, ccid, dummy, h->batch_factor) ? 0 : -1;
}

void osmux_xfrm_input_close_circuit(struct osmux_in_handle *h, int ccid)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit == NULL)
		return;

	osmux_batch_del_circuit(batch, circuit);
}

void osmux_xfrm_input_fini(struct osmux_in_handle *h)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit, *next;

	llist_for_each_entry_safe(circuit, next, &batch->circuit_list, head)
		osmux_batch_del_circuit(batch, circuit);

	osmo_timer_del(&batch->timer);
	talloc_free(batch);
}

struct osmux_tx_handle {
	struct osmo_timer_list	timer;
	struct msgb		*msg;
	void			(*tx_cb)(struct msgb *msg, void *data);
	void			*data;
};

void osmux_xfrm_output_init2(struct osmux_out_handle *h, uint32_t rtp_ssrc, uint8_t rtp_payload_type)
{
	memset(h, 0, sizeof(*h));
	h->rtp_seq = (uint16_t)random();
	h->rtp_timestamp = (uint32_t)random();
	h->rtp_ssrc = rtp_ssrc;
	h->rtp_payload_type = rtp_payload_type;
	INIT_LLIST_HEAD(&h->list);
	osmo_timer_setup(&h->timer, osmux_xfrm_output_trigger, h);
}

void osmux_xfrm_output_init(struct osmux_out_handle *h, uint32_t rtp_ssrc)
{
	/* backward compatibility with old users, where 98 was harcoded in osmux_rebuild_rtp()  */
	osmux_xfrm_output_init2(h, rtp_ssrc, 98);
}

#define SNPRINTF_BUFFER_SIZE(ret, remain, offset)	\
	if (ret < 0)					\
		ret = 0;				\
	offset += ret;					\
	if (ret > remain)				\
		ret = remain;				\
	remain -= ret;

static int osmux_snprintf_header(char *buf, size_t size, struct osmux_hdr *osmuxh)
{
	unsigned int remain = size, offset = 0;
	int ret;

	ret = snprintf(buf, remain, "OSMUX seq=%03u ccid=%03u "
				 "ft=%01u ctr=%01u "
				 "amr_f=%01u amr_q=%01u "
				 "amr_ft=%02u amr_cmr=%02u",
			osmuxh->seq, osmuxh->circuit_id,
			osmuxh->ft, osmuxh->ctr,
			osmuxh->amr_f, osmuxh->amr_q,
			osmuxh->amr_ft, osmuxh->amr_cmr);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int osmux_snprintf_payload(char *buf, size_t size,
				  const uint8_t *payload, int payload_len)
{
	unsigned int remain = size, offset = 0;
	int ret, i;

	ret = snprintf(buf + offset, remain, "[ ");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	for (i=0; i<payload_len; i++) {
		ret = snprintf(buf + offset, remain, "%02x ", payload[i]);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	ret = snprintf(buf + offset, remain, "]");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

/*! Print osmux header fields and payload from msg into buffer buf.
 *  \param[out] buf buffer to store the output into
 *  \param[in] len length of buf in bytes
 *  \param[in] msgb message buffer containing one or more osmux frames
 *  \returns the number of characters printed (excluding the null byte used to end output to strings).
 *
 * If the output was truncated due to this limit, then the return value is the number of characters
 * (excluding the terminating null byte) which would have been written to the final string if enough
 * space had been available.
 */
int osmux_snprintf(char *buf, size_t size, struct msgb *msg)
{
	unsigned int remain = size;
	unsigned int msg_off = 0;
	struct osmux_hdr *osmuxh;
	unsigned int offset = 0;
	int msg_len = msg->len;
	uint32_t payload_len;
	int ret;

	if (size)
		buf[0] = '\0';

	while (msg_len > 0) {
		if (msg_len < sizeof(struct osmux_hdr)) {
			LOGP(DLMUX, LOGL_ERROR,
			     "No room for OSMUX header: only %d bytes\n",
			     msg_len);
			return -1;
		}
		osmuxh = (struct osmux_hdr *)((uint8_t *)msg->data + msg_off);
		if (msg_off) {
			ret = snprintf(buf + offset, remain, ", ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
		ret = osmux_snprintf_header(buf + offset, remain, osmuxh);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		msg_off += sizeof(struct osmux_hdr);
		msg_len -= sizeof(struct osmux_hdr);

		switch (osmuxh->ft) {
		case OSMUX_FT_SIGNAL:
			ret = snprintf(buf + offset, remain, "[signal]");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			return -1;
		case OSMUX_FT_DUMMY:
		case OSMUX_FT_VOICE_AMR:
			if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
				LOGP(DLMUX, LOGL_ERROR, "Bad AMR FT %d, skipping\n",
				     osmuxh->amr_ft);
				return -1;
			}

			payload_len = osmux_get_payload_len(osmuxh);

			if (msg_len < payload_len) {
				LOGP(DLMUX, LOGL_ERROR,
				     "No room for OSMUX payload: only %d bytes\n",
				     msg_len);
				return -1;
			}

			if (osmuxh->ft == OSMUX_FT_VOICE_AMR) {
				ret = snprintf(buf + offset, remain, " ");
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
				ret = osmux_snprintf_payload(buf + offset, remain,
							     osmux_get_payload(osmuxh),
							     payload_len);
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			}

			msg_off += payload_len;
			msg_len -= payload_len;
			break;
		default:
			LOGP(DLMUX, LOGL_ERROR, "Unknown OSMUX ft value %d\n",
			     osmuxh->ft);
			return -1;
		}
	}
	return offset;
}

/*! @} */
