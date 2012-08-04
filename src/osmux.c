/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
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
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include <arpa/inet.h>

#define DEBUG_TIMING		1

/* XXX: this needs to be defined in libosmocore */
#define DOSMUX 0

/* XXX: MTU - iphdr (20 bytes) - udphdr (8 bytes) */
#define OSMUX_BATCH_MAX		1472

/* XXX: make this configurable */
#define OSMUX_BATCH_FACTOR	4

/* delta time between two RTP messages */
#define DELTA_RTP_MSG		20000

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh = NULL;

	if (msg->len > sizeof(struct osmux_hdr)) {
		osmuxh = (struct osmux_hdr *)msg->data;

		msgb_pull(msg, sizeof(struct osmux_hdr) +
			  (osmo_amr_bytes(osmuxh->amr_cmr) * (osmuxh->ctr+1)));
	} else if (msg->len > 0) {
		LOGP(DOSMUX, LOGL_ERROR,
			"remaining %d bytes, broken osmuxhdr?\n", msg->len);
	}

	return osmuxh;
}

static struct msgb *
osmux_rebuild_rtp(struct osmux_out_handle *h,
		  struct osmux_hdr *osmuxh, void *payload, int payload_len)
{
	struct msgb *out_msg;
	struct rtp_hdr *rtph;
	struct amr_hdr *amrh;

	out_msg = msgb_alloc(sizeof(struct rtp_hdr) +
			     sizeof(struct amr_hdr) +
			     osmo_amr_bytes(osmuxh->amr_cmr),
			     "OSMUX test");
	if (out_msg == NULL)
		return NULL;

	/* Reconstruct RTP header */
	rtph = (struct rtp_hdr *)out_msg->data;
	rtph->csrc_count = (sizeof(struct amr_hdr) +
				osmo_amr_bytes(osmuxh->amr_cmr)) >> 2;
	rtph->extension = 0;
	rtph->version = RTP_VERSION;
	rtph->payload_type = 98;
	/* ... emulate timestamp and ssrc */
	rtph->timestamp = htonl(h->rtp_timestamp);
	rtph->sequence = htons(h->rtp_seq);
	rtph->ssrc = osmuxh->circuit_id;

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
	h->rtp_timestamp++;

	return out_msg;
}

int osmux_xfrm_output(struct osmux_hdr *osmuxh, struct osmux_out_handle *h,
		      struct llist_head *list)
{
	struct msgb *msg;
	int i;

	INIT_LLIST_HEAD(list);

	for (i=0; i<osmuxh->ctr+1; i++) {
		msg = osmux_rebuild_rtp(h, osmuxh,
					osmux_get_payload(osmuxh) +
					i * osmo_amr_bytes(osmuxh->amr_cmr),
					osmo_amr_bytes(osmuxh->amr_cmr));
		if (msg == NULL)
			break;

		LOGP(DOSMUX, LOGL_DEBUG, "extracted RTP message from batch "
					 "msg=%p\n", msg);

		llist_add_tail(&msg->list, list);
	}
	return i;
}

static struct osmux_batch {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	msgb_list;
	unsigned int		remaining_bytes;
	uint8_t			seq;
} batch;

static int
osmux_batch_add(struct msgb *out_msg, struct msgb *msg, struct rtp_hdr *rtph,
		struct amr_hdr *amrh, uint32_t amr_payload_len,
		uint8_t circuit_id, int add_osmux_header)
{
	struct osmux_hdr *osmuxh;

	if (add_osmux_header) {
		osmuxh = (struct osmux_hdr *)out_msg->tail;
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->amr_f = amrh->f;
		osmuxh->amr_q= amrh->q;
		osmuxh->seq = batch.seq++;
		osmuxh->circuit_id = circuit_id;
		osmuxh->amr_cmr = amrh->cmr;
		osmuxh->amr_ft = amrh->ft;
		msgb_put(out_msg, sizeof(struct osmux_hdr));

		/* annotate current osmux header */
		batch.osmuxh = osmuxh;
	} else
		batch.osmuxh->ctr++;

	memcpy(out_msg->tail, osmo_amr_get_payload(amrh), amr_payload_len);
	msgb_put(out_msg, amr_payload_len);

	return 0;
}

static int
osmux_xfrm_encode_amr(struct msgb *out_msg,
		      struct rtp_hdr *rtph, struct msgb *msg,
		      int add_osmux_header)
{
	struct amr_hdr *amrh;
	uint32_t amr_len;
	uint32_t amr_payload_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	amr_payload_len = amr_len - sizeof(struct amr_hdr);

	if (osmux_batch_add(out_msg, msg, rtph, amrh, amr_payload_len, 0,
			    add_osmux_header) < 0)
		return -1;

	return 0;
}

static struct msgb *osmux_build_batch(void)
{
	struct msgb *cur, *tmp, *batch_msg;
	uint32_t last_rtp_ssrc;
	int last_rtp_ssrc_set = 0, add_osmux_hdr = 1;
	int i=0;

	batch_msg = msgb_alloc(OSMUX_BATCH_MAX, "OSMUX");
	if (batch_msg == NULL) {
		LOGP(DOSMUX, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	LOGP(DOSMUX, LOGL_DEBUG, "Now building batch\n");

	llist_for_each_entry_safe(cur, tmp, &batch.msgb_list, list) {
		struct rtp_hdr *rtph;

		LOGP(DOSMUX, LOGL_DEBUG,
			"building message (%p) into batch (%d)\n", cur, ++i);

		rtph = osmo_rtp_get_hdr(cur);
		if (rtph == NULL)
			return NULL;

		if (last_rtp_ssrc_set)
			add_osmux_hdr = (last_rtp_ssrc == rtph->ssrc);

		osmux_xfrm_encode_amr(batch_msg, rtph, cur, add_osmux_hdr);

		last_rtp_ssrc_set = 1;
		last_rtp_ssrc = rtph->ssrc;

		llist_del(&cur->list);
		msgb_free(cur);
	}
	return batch_msg;
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;

	LOGP(DOSMUX, LOGL_DEBUG, "invoking delivery function\n");
	batch_msg = osmux_build_batch();
	h->deliver(batch_msg);
	msgb_free(batch_msg);
	osmo_timer_del(&batch.timer);
	batch.remaining_bytes = OSMUX_BATCH_MAX;
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

	LOGP(DOSMUX, LOGL_DEBUG, "received message from stream\n");
	osmux_xfrm_input_deliver(h);
}

static int osmux_rtp_amr_payload_len(struct msgb *msg, struct rtp_hdr *rtph)
{
	struct amr_hdr *amrh;
	unsigned int amr_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	return amr_len - sizeof(struct amr_hdr);
}

static int osmux_msgb_batch_queue_add(struct msgb *msg)
{
	struct rtp_hdr *rtph;
	struct msgb *cur;
	int found = 0, bytes = 0;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return -1;

	llist_for_each_entry(cur, &batch.msgb_list, list) {
		struct rtp_hdr *rtph2;

		rtph2 = osmo_rtp_get_hdr(msg);
		if (rtph2 == NULL)
			return -1;

		/* inset messages in order based on the RTP SSRC */
		if (rtph->ssrc < rtph2->ssrc)
			continue;
		if (rtph->ssrc == rtph2->ssrc) {
			found = 1;
			continue;
		}

		bytes += osmux_rtp_amr_payload_len(msg, rtph);
		if (!found)
			bytes += sizeof(struct osmux_hdr);

		/* Still room in this batch for this message? if there is not
		 * then deliver current batch.
		 */
		if (bytes > batch.remaining_bytes)
			return 1;

		batch.remaining_bytes -= bytes;
		llist_add(&msg->list, &cur->list);

		LOGP(DOSMUX, LOGL_DEBUG, "adding to batch (%p)\n", msg);

		return 0;
	}
	/*
	 * ... adding to the tail or empty list case.
	 */
	bytes += osmux_rtp_amr_payload_len(msg, rtph);
	if (!found)
		bytes += sizeof(struct osmux_hdr);

	/* Still room in this batch for this message? if there is not
	 * then deliver current batch.
	 */
	if (bytes > batch.remaining_bytes)
		return 1;

	batch.remaining_bytes -= bytes;
	llist_add_tail(&msg->list, &batch.msgb_list);

	LOGP(DOSMUX, LOGL_DEBUG, "adding to batch (%p)\n", msg);

	return 0;
}

/**
 * osmux_xfrm_input - add RTP message to OSmux batch
 * \param msg: RTP message that you want to batch into one OSmux message
 *
 * This function returns -1 on error. If 0 is returned, this indicates
 * that the message has been batched. If 1 is returned, you have to
 * invoke osmux_xfrm_input_deliver and try again.
 */
int osmux_xfrm_input(struct msgb *msg)
{
	int ret;
	struct rtp_hdr *rtph;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return -1;

	switch(rtph->payload_type) {
		case RTP_PT_RTCP:
			return 0;
		case RTP_PT_AMR:
			/* This is the first message in the batch, start the
			 * batch timer to deliver it.
			 */
			if (llist_empty(&batch.msgb_list)) {
				LOGP(DOSMUX, LOGL_DEBUG,
					"osmux start timer batch\n");

				osmo_timer_schedule(&batch.timer, 0,
					OSMUX_BATCH_FACTOR * DELTA_RTP_MSG);
			}
			ret = osmux_msgb_batch_queue_add(msg);
			break;
		default:
			/* Only AMR supported so far, sorry. */
			ret = -1;
			break;
	}
	return ret;
}

void osmux_xfrm_input_init(struct osmux_in_handle *h)
{
	LOGP(DOSMUX, LOGL_DEBUG, "initialized osmux input converter\n");
	INIT_LLIST_HEAD(&batch.msgb_list);
	batch.remaining_bytes = OSMUX_BATCH_MAX;
	batch.timer.cb = osmux_batch_timer_expired;
	batch.timer.data = h;
}

struct osmux_tx_handle {
	struct osmo_timer_list	timer;
	struct msgb		*msg;
	void			(*tx_cb)(struct msgb *msg, void *data);
	void			*data;
#ifdef DEBUG_TIMING
	struct timeval		start;
#endif
};

static void osmux_tx_cb(void *data)
{
	struct osmux_tx_handle *h = data;
#ifdef DEBUG_TIMING
	struct timeval now, diff;

	gettimeofday(&now, NULL);
	timersub(&now, &h->start, &diff);
	LOGP(DOSMUX, LOGL_DEBUG, "difference %lu.%.6lu\n",
		diff.tv_sec, diff.tv_usec);
#endif

	h->tx_cb(h->msg, h->data);

	talloc_free(h);
}

static void
osmux_tx(struct msgb *msg, struct timeval *when,
	 void (*tx_cb)(struct msgb *msg, void *data), void *data)
{
	struct osmux_tx_handle *h;

	h = talloc_zero(NULL, struct osmux_tx_handle);
	if (h == NULL)
		return;

	h->msg = msg;
	h->tx_cb = tx_cb;
	h->data = data;
	h->timer.cb = osmux_tx_cb;
	h->timer.data = h;

#ifdef DEBUG_TIMING
	gettimeofday(&h->start, NULL);
#endif
	/* send it now */
	if (when->tv_sec == 0 && when->tv_usec == 0) {
		osmux_tx_cb(h);
		return;
	}
	osmo_timer_schedule(&h->timer, when->tv_sec, when->tv_usec);
}

void
osmux_tx_sched(struct llist_head *list, struct timeval *when,
	       void (*tx_cb)(struct msgb *msg, void *data), void *data)
{
	struct msgb *cur, *tmp;
	struct timeval delta = { .tv_sec = 0, .tv_usec = DELTA_RTP_MSG };

	llist_for_each_entry_safe(cur, tmp, list, list) {

		LOGP(DOSMUX, LOGL_DEBUG, "scheduled transmision in %lu.%6lu "
			"seconds, msg=%p\n", when->tv_sec, when->tv_usec, cur);

		osmux_tx(cur, when, tx_cb, NULL);
		timeradd(when, &delta, when);
		llist_del(&cur->list);
	}
}
