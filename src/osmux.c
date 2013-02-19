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

/* XXX: MTU - iphdr (20 bytes) - udphdr (8 bytes) */
#define OSMUX_BATCH_MAX		1472

/* delta time between two RTP messages */
#define DELTA_RTP_MSG		16000
#define DELTA_RTP_TIMESTAMP	160

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh = NULL;

	if (msg->len > sizeof(struct osmux_hdr)) {
		osmuxh = (struct osmux_hdr *)msg->data;

		msgb_pull(msg, sizeof(struct osmux_hdr) +
			  (osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1)));
	} else if (msg->len > 0) {
		LOGP(DLMIB, LOGL_ERROR,
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
	uint32_t ssrc_from_ccid = osmuxh->circuit_id;
	char buf[4096];

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
	rtph->payload_type = 98;
	/* ... emulate timestamp and ssrc */
	rtph->timestamp = htonl(h->rtp_timestamp);
	rtph->sequence = htons(h->rtp_seq);
	rtph->ssrc = htonl(ssrc_from_ccid);

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

	osmo_rtp_snprintf(buf, sizeof(buf), out_msg);
	LOGP(DLMIB, LOGL_DEBUG, "%s\n", buf);

	return out_msg;
}

int osmux_xfrm_output(struct osmux_hdr *osmuxh, struct osmux_out_handle *h,
		      struct llist_head *list)
{
	struct msgb *msg;
	int i;

	INIT_LLIST_HEAD(list);

	for (i=0; i<osmuxh->ctr+1; i++) {
		struct rtp_hdr *rtph;
		char buf[4096];

		msg = osmux_rebuild_rtp(h, osmuxh,
					osmux_get_payload(osmuxh) +
					i * osmo_amr_bytes(osmuxh->amr_ft),
					osmo_amr_bytes(osmuxh->amr_ft));
		if (msg == NULL)
			continue;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			continue;

		osmo_rtp_snprintf(buf, sizeof(buf), msg);
		LOGP(DLMIB, LOGL_DEBUG, "extracted: %s\n", buf);
		llist_add_tail(&msg->list, list);
	}
	return i;
}

struct osmux_batch {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	node_list;
	unsigned int		remaining_bytes;
	uint8_t			seq;
};

static int
osmux_batch_put(struct osmux_in_handle *h, struct msgb *out_msg,
		struct msgb *msg, struct rtp_hdr *rtph,
		struct amr_hdr *amrh, uint32_t amr_payload_len,
		int ccid, int add_osmux_header)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_hdr *osmuxh;

	if (add_osmux_header) {
		osmuxh = (struct osmux_hdr *)out_msg->tail;
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->amr_f = amrh->f;
		osmuxh->amr_q= amrh->q;
		osmuxh->seq = batch->seq++;
		osmuxh->circuit_id = ccid;
		osmuxh->amr_cmr = amrh->cmr;
		osmuxh->amr_ft = amrh->ft;
		msgb_put(out_msg, sizeof(struct osmux_hdr));

		/* annotate current osmux header */
		batch->osmuxh = osmuxh;
	} else {
		if (batch->osmuxh->ctr == 0x7) {
			LOGP(DLMIB, LOGL_ERROR, "cannot add msg=%p, "
				"too many messages for this RTP ssrc=%u\n",
				msg, rtph->ssrc);
			return 0;
		}
		batch->osmuxh->ctr++;
	}

	memcpy(out_msg->tail, osmo_amr_get_payload(amrh), amr_payload_len);
	msgb_put(out_msg, amr_payload_len);

	return 0;
}

static int
osmux_xfrm_encode_amr(struct osmux_in_handle *h,
		      struct msgb *out_msg,
		      struct rtp_hdr *rtph, struct msgb *msg,
		      int ccid, int add_osmux_header)
{
	struct amr_hdr *amrh;
	uint32_t amr_len;
	uint32_t amr_payload_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	amr_payload_len = amr_len - sizeof(struct amr_hdr);

	if (osmux_batch_put(h, out_msg, msg, rtph, amrh, amr_payload_len,
			    ccid, add_osmux_header) < 0)
		return -1;

	return 0;
}

struct batch_list_node {
	struct llist_head	head;
	uint32_t		ssrc;
	int			ccid;
	struct llist_head	list;
};

static struct msgb *osmux_build_batch(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct batch_list_node *node, *tnode;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	LOGP(DLMIB, LOGL_DEBUG, "Now building batch\n");

	batch_msg = msgb_alloc(OSMUX_BATCH_MAX, "OSMUX");
	if (batch_msg == NULL) {
		LOGP(DLMIB, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	llist_for_each_entry_safe(node, tnode, &batch->node_list, head) {
		struct msgb *cur, *tmp;
		int ctr = 0;

		llist_for_each_entry_safe(cur, tmp, &node->list, list) {
			struct rtp_hdr *rtph;
			char buf[4096];
			int add_osmux_hdr = 0;

			osmo_rtp_snprintf(buf, sizeof(buf), cur);
			LOGP(DLMIB, LOGL_DEBUG, "built: %s\n", buf);

			rtph = osmo_rtp_get_hdr(cur);
			if (rtph == NULL)
				return NULL;

			if (ctr == 0) {
				LOGP(DLMIB, LOGL_DEBUG, "add osmux header\n");
				add_osmux_hdr = 1;
			}

			osmux_xfrm_encode_amr(h, batch_msg, rtph, cur,
						node->ccid, add_osmux_hdr);
			llist_del(&cur->list);
			msgb_free(cur);
			ctr++;
		}
		llist_del(&node->head);
		talloc_free(node);
	}
	return batch_msg;
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	LOGP(DLMIB, LOGL_DEBUG, "invoking delivery function\n");
	batch_msg = osmux_build_batch(h);
	h->deliver(batch_msg, h->data);
	osmo_timer_del(&batch->timer);
	batch->remaining_bytes = OSMUX_BATCH_MAX;
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

	LOGP(DLMIB, LOGL_DEBUG, "osmux_batch_timer_expired\n");
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

static int
osmux_batch_add(struct osmux_batch *batch, struct msgb *msg, int ccid)
{
	struct rtp_hdr *rtph;
	struct batch_list_node *node;
	int found = 0, bytes = 0;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return 0;

	/* Yes, there is room. Check if we have more message with same ssrc */
	llist_for_each_entry(node, &batch->node_list, head) {
		if (node->ssrc == rtph->ssrc) {
			found = 1;
			break;
		}
	}

	/* First check if there is room for this message in the batch */
	bytes += osmux_rtp_amr_payload_len(msg, rtph);
	if (!found)
		bytes += sizeof(struct osmux_hdr);

	/* No room, sorry. You'll have to retry */
	if (bytes > batch->remaining_bytes)
		return 1;

	if (found) {
		struct msgb *cur;

		/* Extra validation: check if this message already exists,
		 * should not happen but make sure we don't propagate
		 * duplicated messages.
		 */
		llist_for_each_entry(cur, &node->list, list) {
			struct rtp_hdr *rtph2 = osmo_rtp_get_hdr(cur);
			if (rtph2 == NULL)
				return 0;

			/* Already exists message with this sequence, skip */
			if (rtph2->sequence == rtph->sequence) {
				LOGP(DLMIB, LOGL_DEBUG, "already exists "
					"message with seq=%u, skip it\n",
					rtph->sequence);
				return 0;
			}
		}
	} else {
		/* This is the first message with that ssrc we've seen */
		node = talloc_zero(NULL, struct batch_list_node);
		if (node == NULL)
			return 0;

		node->ccid = ccid;
		node->ssrc = rtph->ssrc;
		INIT_LLIST_HEAD(&node->list);
		llist_add_tail(&node->head, &batch->node_list);
	}

	LOGP(DLMIB, LOGL_DEBUG, "adding msg with ssrc=%u to batch\n",
		rtph->ssrc);
	llist_add_tail(&msg->list, &node->list);

	/* Update remaining room in this batch */
	batch->remaining_bytes -= bytes;

	return 0;
}

/**
 * osmux_xfrm_input - add RTP message to OSmux batch
 * \param msg: RTP message that you want to batch into one OSmux message
 *
 * If 0 is returned, this indicates that the message has been batched or that
 * an error occured and we have skipped the message. If 1 is returned, you
 * have to invoke osmux_xfrm_input_deliver and try again.
 */
int osmux_xfrm_input(struct osmux_in_handle *h, struct msgb *msg, int ccid)
{
	int ret;
	struct rtp_hdr *rtph;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return 0;

	switch(rtph->payload_type) {
		case RTP_PT_RTCP:
			return 0;
		case RTP_PT_AMR:
			/* This is the first message in the batch, start the
			 * batch timer to deliver it.
			 */
			if (llist_empty(&batch->node_list)) {
				LOGP(DLMIB, LOGL_DEBUG,
					"osmux start timer batch\n");

				osmo_timer_schedule(&batch->timer, 0,
					h->batch_factor * DELTA_RTP_MSG);
			}
			ret = osmux_batch_add(batch, msg, ccid);
			break;
		default:
			/* Only AMR supported so far, sorry. */
			ret = 0;
			break;
	}
	return ret;
}

void osmux_xfrm_input_init(struct osmux_in_handle *h)
{
	struct osmux_batch *batch;

	LOGP(DLMIB, LOGL_DEBUG, "initialized osmux input converter\n");

	batch = talloc_zero(NULL, struct osmux_batch);
	if (batch == NULL)
		return;

	INIT_LLIST_HEAD(&batch->node_list);
	batch->remaining_bytes = OSMUX_BATCH_MAX;
	batch->timer.cb = osmux_batch_timer_expired;
	batch->timer.data = h;

	h->internal_data = (void *)batch;
}

struct osmux_tx_handle {
	struct osmo_timer_list	timer;
	struct msgb		*msg;
	void			(*tx_cb)(struct msgb *msg, void *data);
	void			*data;
#ifdef DEBUG_TIMING
	struct timeval		start;
	struct timeval		when;
#endif
};

static void osmux_tx_cb(void *data)
{
	struct osmux_tx_handle *h = data;
#ifdef DEBUG_TIMING
	struct timeval now, diff;

	gettimeofday(&now, NULL);
	timersub(&now, &h->start, &diff);
	timersub(&diff,&h->when, &diff);
	LOGP(DLMIB, LOGL_DEBUG, "we are lagging %lu.%.6lu in scheduled "
		"transmissions\n", diff.tv_sec, diff.tv_usec);
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
	h->when.tv_sec = when->tv_sec;
	h->when.tv_usec = when->tv_usec;
#endif
	/* send it now */
	if (when->tv_sec == 0 && when->tv_usec == 0) {
		osmux_tx_cb(h);
		return;
	}
	osmo_timer_schedule(&h->timer, when->tv_sec, when->tv_usec);
}

void
osmux_tx_sched(struct llist_head *list,
	       void (*tx_cb)(struct msgb *msg, void *data), void *data)
{
	struct msgb *cur, *tmp;
	struct timeval delta = { .tv_sec = 0, .tv_usec = DELTA_RTP_MSG };
	struct timeval when;

	timerclear(&when);

	llist_for_each_entry_safe(cur, tmp, list, list) {

		LOGP(DLMIB, LOGL_DEBUG, "scheduled transmision in %lu.%6lu "
			"seconds, msg=%p\n", when.tv_sec, when.tv_usec, cur);

		osmux_tx(cur, &when, tx_cb, data);
		timeradd(&when, &delta, &when);
		llist_del(&cur->list);
	}
}

void osmux_xfrm_output_init(struct osmux_out_handle *h)
{
	h->rtp_seq = (uint16_t)random();
	h->rtp_timestamp = (uint32_t)random();
}
