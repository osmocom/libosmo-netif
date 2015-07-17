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

/* This allows you to debug timing reconstruction in the output path */
#if 0
#define DEBUG_TIMING		0
#endif

/* This allows you to debug osmux message transformations (spamming) */
#if 0
#define DEBUG_MSG		0
#endif

/* delta time between two RTP messages */
#define DELTA_RTP_MSG		16000
#define DELTA_RTP_TIMESTAMP	160

static void *osmux_ctx;

struct osmux_hdr *osmux_get_hdr(struct msgb *msg)
{
	struct osmux_hdr *osmuxh = (struct osmux_hdr *)msg->data;

	if (msg->len < sizeof(struct osmux_hdr)) {
		DEBUGPC(DLMUX, "received OSMUX frame too short (len = %d)\n",
			msg->len);
		return NULL;
	}
	return osmuxh;
}

static uint32_t osmux_get_payload_len(struct osmux_hdr *osmuxh)
{
	return osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1);
}

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh = NULL;

	if (msg->len > sizeof(struct osmux_hdr)) {
		size_t len;

		osmuxh = (struct osmux_hdr *)msg->data;

		if (osmuxh->ft != OSMUX_FT_VOICE_AMR) {
			LOGP(DLMIB, LOGL_ERROR, "Discarding unsupported Osmux FT %d\n",
			     osmuxh->ft);
			return NULL;
		}
		if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
			LOGP(DLMIB, LOGL_ERROR, "Discarding bad AMR FT %d\n",
			     osmuxh->amr_ft);
			return NULL;
		}

		len = osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1) +
			sizeof(struct osmux_hdr);

		if (len > msg->len) {
			LOGP(DLMIB, LOGL_ERROR, "Discarding malformed "
						"OSMUX message\n");
			return NULL;
		}

		msgb_pull(msg, len);
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
	rtph->ssrc = htonl(h->rtp_ssrc);

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

		msg = osmux_rebuild_rtp(h, osmuxh,
					osmux_get_payload(osmuxh) +
					i * osmo_amr_bytes(osmuxh->amr_ft),
					osmo_amr_bytes(osmuxh->amr_ft));
		if (msg == NULL)
			continue;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			continue;

#ifdef DEBUG_MSG
		{
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), msg);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMIB, LOGL_DEBUG, "to BTS: %s\n", buf);
		}
#endif
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

struct batch_list_node {
	struct llist_head	head;
	int			ccid;
	struct llist_head	list;
	int			nmsgs;
};

static int osmux_batch_enqueue(struct msgb *msg, struct batch_list_node *node)
{
	/* Too many messages per batch, discard it. The counter field of the
	 * osmux header is just 3 bits long, so make sure it doesn't overflow.
	 */
	if (node->nmsgs >= 8) {
		struct rtp_hdr *rtph;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			return -1;

		LOGP(DLMIB, LOGL_ERROR, "too many messages for this RTP "
					"ssrc=%u\n", rtph->ssrc);
		return -1;
	}

	llist_add_tail(&msg->list, &node->list);
	node->nmsgs++;
	return 0;
}

static void osmux_batch_dequeue(struct msgb *msg, struct batch_list_node *node)
{
	llist_del(&msg->list);
	node->nmsgs--;
}

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

static struct msgb *osmux_build_batch(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct batch_list_node *node, *tnode;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "Now building batch\n");
#endif

	batch_msg = msgb_alloc(h->batch_size, "osmux");
	if (batch_msg == NULL) {
		LOGP(DLMIB, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	llist_for_each_entry_safe(node, tnode, &batch->node_list, head) {
		struct msgb *cur, *tmp;
		int ctr = 0;

		llist_for_each_entry_safe(cur, tmp, &node->list, list) {
			struct rtp_hdr *rtph;
			int add_osmux_hdr = 0;

#ifdef DEBUG_MSG
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), cur);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMIB, LOGL_DEBUG, "to BSC-NAT: %s\n", buf);
#endif

			rtph = osmo_rtp_get_hdr(cur);
			if (rtph == NULL)
				return NULL;

			if (ctr == 0) {
#ifdef DEBUG_MSG
				LOGP(DLMIB, LOGL_DEBUG, "add osmux header\n");
#endif
				add_osmux_hdr = 1;
			}

			osmux_xfrm_encode_amr(h, batch_msg, rtph, cur,
						node->ccid, add_osmux_hdr);
			osmux_batch_dequeue(cur, node);
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

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "invoking delivery function\n");
#endif
	batch_msg = osmux_build_batch(h);

	h->stats.output_osmux_msgs++;
	h->stats.output_osmux_bytes += batch_msg->len;

	h->deliver(batch_msg, h->data);
	osmo_timer_del(&batch->timer);
	batch->remaining_bytes = h->batch_size;
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "osmux_batch_timer_expired\n");
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
		LOGP(DLMIB, LOGL_ERROR,
		     "Bad AMR frame, expected %zd bytes, got %d bytes\n",
		     osmo_amr_bytes(amrh->ft), amr_len);
		return -1;
	}
	return amr_payload_len;
}

static void osmux_replay_lost_packets(struct batch_list_node *node,
				      struct rtp_hdr *cur_rtph)
{
	int16_t diff;
	struct msgb *last;
	struct rtp_hdr *rtph;
	int i;

	/* Have we see any RTP packet in this batch before? */
	if (llist_empty(&node->list))
		return;

	/* Get last RTP packet seen in this batch */
	last = llist_entry(node->list.prev, struct msgb, list);
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
		if (osmux_batch_enqueue(clone, node) < 0) {
			msgb_free(clone);
			break;
		}

		LOGP(DLMIB, LOGL_ERROR, "adding cloned RTP\n");
	}
}

static int
osmux_batch_add(struct osmux_batch *batch, struct msgb *msg,
		struct rtp_hdr *rtph, int ccid)
{
	struct batch_list_node *node;
	int found = 0, bytes = 0, amr_payload_len;

	llist_for_each_entry(node, &batch->node_list, head) {
		if (node->ccid == ccid) {
			found = 1;
			break;
		}
	}

	amr_payload_len = osmux_rtp_amr_payload_len(msg, rtph);
	if (amr_payload_len < 0)
		return -1;

	/* First check if there is room for this message in the batch */
	bytes += amr_payload_len;
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
				return -1;

			/* Already exists message with this sequence, skip */
			if (rtph2->sequence == rtph->sequence) {
				LOGP(DLMIB, LOGL_ERROR, "already exists "
					"message with seq=%u, skip it\n",
					rtph->sequence);
				return -1;
			}
		}
		/* Handle RTP packet loss scenario */
		osmux_replay_lost_packets(node, rtph);

	} else {
		/* This is the first message with that ssrc we've seen */
		node = talloc_zero(osmux_ctx, struct batch_list_node);
		if (node == NULL)
			return -1;

		node->ccid = ccid;
		INIT_LLIST_HEAD(&node->list);
		llist_add_tail(&node->head, &batch->node_list);
	}

	/* This batch is full, force batch delivery */
	if (osmux_batch_enqueue(msg, node) < 0)
		return 1;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "adding msg with ssrc=%u to batch\n",
		rtph->ssrc);
#endif

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
 *
 * The function takes care of releasing the messages in case of error and
 * when building the batch.
 */
int osmux_xfrm_input(struct osmux_in_handle *h, struct msgb *msg, int ccid)
{
	int ret, first_rtp_msg;
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

			/* This is the first message in the batch, start the
			 * batch timer to deliver it.
			 */
			first_rtp_msg = llist_empty(&batch->node_list) ? 1 : 0;

			/* Add this RTP to the OSMUX batch */
			ret = osmux_batch_add(batch, msg, rtph, ccid);
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

			if (first_rtp_msg) {
#ifdef DEBUG_MSG
				LOGP(DLMIB, LOGL_DEBUG,
					"osmux start timer batch\n");
#endif
				osmo_timer_schedule(&batch->timer, 0,
					h->batch_factor * DELTA_RTP_MSG);
			}
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

	INIT_LLIST_HEAD(&batch->node_list);
	batch->remaining_bytes = h->batch_size;
	batch->timer.cb = osmux_batch_timer_expired;
	batch->timer.data = h;

	h->internal_data = (void *)batch;

	LOGP(DLMIB, LOGL_DEBUG, "initialized osmux input converter\n");
}

void osmux_xfrm_input_fini(struct osmux_in_handle *h)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct batch_list_node *node, *next;

	llist_for_each_entry_safe(node, next, &batch->node_list, head) {
		llist_del(&node->head);
		talloc_free(node);
	}
	osmo_timer_del(&batch->timer);
	talloc_free(batch);
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

	h = talloc_zero(osmux_ctx, struct osmux_tx_handle);
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

#ifdef DEBUG_MSG
		LOGP(DLMIB, LOGL_DEBUG, "scheduled transmision in %lu.%6lu "
			"seconds, msg=%p\n", when.tv_sec, when.tv_usec, cur);
#endif
		llist_del(&cur->list);
		osmux_tx(cur, &when, tx_cb, data);
		timeradd(&when, &delta, &when);
	}
}

void osmux_xfrm_output_init(struct osmux_out_handle *h, uint32_t rtp_ssrc)
{
	h->rtp_seq = (uint16_t)random();
	h->rtp_timestamp = (uint32_t)random();
	h->rtp_ssrc = rtp_ssrc;
}

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

static int osmux_snprintf_header(char *buf, size_t size, struct osmux_hdr *osmuxh)
{
	int ret;
	int len = size, offset = 0;

	ret = snprintf(buf, len, "OSMUX seq=%03u ccid=%03u "
				 "ft=%01u ctr=%01u "
				 "amr_f=%01u amr_q=%01u "
				 "amr_ft=%02u amr_cmr=%02u ",
			osmuxh->seq, osmuxh->circuit_id,
			osmuxh->ft, osmuxh->ctr,
			osmuxh->amr_f, osmuxh->amr_q,
			osmuxh->amr_ft, osmuxh->amr_cmr);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int osmux_snprintf_payload(char *buf, size_t size,
				  const uint8_t *payload, int payload_len)
{
	int ret, i;
	int len = size, offset = 0;

	for (i=0; i<payload_len; i++) {
		ret = snprintf(buf+offset, len, "%02x ", payload[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "]");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}


int osmux_snprintf(char *buf, size_t size, struct msgb *msg)
{
	int ret;
	unsigned int offset = 0;
	int msg_len = msg->len, len = size;
	struct osmux_hdr *osmuxh;
	int this_len, msg_off = 0;

	while (msg_len > 0) {
		if (msg_len < sizeof(struct osmux_hdr)) {
			LOGP(DLMIB, LOGL_ERROR,
			     "No room for OSMUX header: only %d bytes\n",
			     msg_len);
			return -1;
		}
		osmuxh = (struct osmux_hdr *)((uint8_t *)msg->data + msg_off);

		if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
			LOGP(DLMIB, LOGL_ERROR, "Bad AMR FT %d, skipping\n",
			     osmuxh->amr_ft);
			return -1;
		}

		ret = osmux_snprintf_header(buf+offset, size, osmuxh);
		if (ret < 0)
			break;
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		this_len = sizeof(struct osmux_hdr) +
			   osmux_get_payload_len(osmuxh);
		msg_off += this_len;

		if (msg_len < this_len) {
			LOGP(DLMIB, LOGL_ERROR,
			     "No room for OSMUX payload: only %d bytes\n",
			     msg_len);
			return -1;
		}

		ret = osmux_snprintf_payload(buf+offset, size,
					     osmux_get_payload(osmuxh),
					     osmux_get_payload_len(osmuxh));
		if (ret < 0)
			break;
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		msg_len -= this_len;
	}

	return offset;
}
