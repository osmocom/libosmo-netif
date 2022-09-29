/*
 * (C) 2012-2017 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 * (C) 2015-2022 by sysmocom - s.f.m.c. GmbH
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

/*! \file osmux_input.c
 *  \brief Osmocom multiplex protocol helpers (input)
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

static uint32_t osmux_ft_dummy_size(uint8_t amr_ft, uint8_t batch_factor)
{
	return sizeof(struct osmux_hdr) + (osmo_amr_bytes(amr_ft) * batch_factor);
}

struct osmux_batch {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	circuit_list;
	unsigned int		remaining_bytes;
	uint32_t		nmsgs;
	int			ndummy;
};

struct osmux_circuit {
	struct llist_head	head;
	int			ccid;
	struct llist_head	msg_list;
	int			nmsgs;
	int			dummy;
	uint8_t			seq;
};

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_batch_enqueue(struct msgb *msg, struct osmux_circuit *circuit,
				uint8_t batch_factor)
{
	/* Validate amount of messages per batch. The counter field of the
	 * osmux header is just 3 bits long, so make sure it doesn't overflow.
	 */
	OSMO_ASSERT(batch_factor <= 8);
	if (circuit->nmsgs >= batch_factor) {
		struct rtp_hdr *rtph;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			return -1;

		LOGP(DLMUX, LOGL_DEBUG, "Batch is full for RTP sssrc=%u\n", rtph->ssrc);
		return 1;
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
	struct osmux_circuit *circuit;
	int		add_osmux_hdr;
};

static int osmux_batch_put(struct osmux_batch *batch,
			   struct osmux_input_state *state)
{
	if (state->add_osmux_hdr) {
		struct osmux_hdr *osmuxh;
		osmuxh = (struct osmux_hdr *)msgb_put(state->out_msg,
						      sizeof(struct osmux_hdr));
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->rtp_m = osmuxh->rtp_m || state->rtph->marker;
		osmuxh->seq = state->circuit->seq++;
		osmuxh->circuit_id = state->circuit->ccid;
		osmuxh->amr_ft = state->amrh->ft;

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
	/* For fields below, we only use the last included in batch and ignore any previous: */
	batch->osmuxh->amr_cmr = state->amrh->cmr;
	batch->osmuxh->amr_f = state->amrh->f;
	batch->osmuxh->amr_q = state->amrh->q;

	memcpy(state->out_msg->tail, osmo_amr_get_payload(state->amrh),
	       state->amr_payload_len);
	msgb_put(state->out_msg, state->amr_payload_len);

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
	osmuxh->amr_q = 0;
	osmuxh->seq = 0;
	osmuxh->circuit_id = state->circuit->ccid;
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
		int prev_amr_ft;

		if (circuit->dummy) {
			struct osmux_input_state state = {
				.out_msg	= batch_msg,
				.circuit	= circuit,
			};
			osmux_encode_dummy(batch, batch_factor, &state);
			continue;
		}

		llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
			struct osmux_input_state state = {
				.msg		= cur,
				.out_msg	= batch_msg,
				.circuit	= circuit,
			};
			uint32_t amr_len;
#ifdef DEBUG_MSG
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), cur);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMUX, LOGL_DEBUG, "to BSC-NAT: %s\n", buf);
#endif

			state.rtph = osmo_rtp_get_hdr(cur);
			if (!state.rtph)
				return NULL;
			state.amrh = osmo_rtp_get_payload(state.rtph, state.msg, &amr_len);
			if (!state.amrh)
				return NULL;
			state.amr_payload_len = amr_len - sizeof(struct amr_hdr);

			if (ctr == 0) {
#ifdef DEBUG_MSG
				LOGP(DLMUX, LOGL_DEBUG, "Add osmux header (First in batch)\n");
#endif
				state.add_osmux_hdr = 1;
			} else if (prev_amr_ft != state.amrh->ft) {
				/* If AMR FT changed, we have to generate an extra batch osmux header: */
#ifdef DEBUG_MSG
				LOGP(DLMUX, LOGL_DEBUG, "Add osmux header (New AMR FT)\n");
#endif
				state.add_osmux_hdr = 1;
			}

			osmux_batch_put(batch, &state);
			osmux_batch_dequeue(cur, circuit);
			prev_amr_ft = state.amrh->ft;
			ctr++;
			msgb_free(cur);
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

static int osmux_rtp_amr_payload_len(struct amr_hdr *amrh, uint32_t amr_len)
{
	int amr_payload_len;

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

/* Last stored AMR FT to be added in the current osmux batch. -1 if none stored yet */
static int osmux_circuit_get_last_stored_amr_ft(struct osmux_circuit *circuit)
{
	struct msgb *last;
	struct rtp_hdr *rtph;
	struct amr_hdr *amrh;
	uint32_t amr_len;
	/* Have we seen any RTP packet in this batch before? */
	if (llist_empty(&circuit->msg_list))
		return -1;
	OSMO_ASSERT(circuit->nmsgs > 0);

	/* Get last RTP packet seen in this batch */
	last = llist_entry(circuit->msg_list.prev, struct msgb, list);
	rtph = osmo_rtp_get_hdr(last);
	amrh = osmo_rtp_get_payload(rtph, last, &amr_len);
	if (amrh == NULL)
		return -1;
	return amrh->ft;

}

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_replay_lost_packets(struct osmux_circuit *circuit,
				      struct rtp_hdr *cur_rtph, int batch_factor)
{
	int16_t diff;
	struct msgb *last;
	struct rtp_hdr *rtph;
	int i, rc;

	/* Have we seen any RTP packet in this batch before? */
	if (llist_empty(&circuit->msg_list))
		return 0;

	/* Get last RTP packet seen in this batch */
	last = llist_entry(circuit->msg_list.prev, struct msgb, list);
	rtph = osmo_rtp_get_hdr(last);
	if (rtph == NULL)
		return -1;

	diff = ntohs(cur_rtph->sequence) - ntohs(rtph->sequence);

	/* Lifesaver: make sure bugs don't spawn lots of clones */
	if (diff > 16)
		diff = 16;

	rc = 0;
	/* If diff between last RTP packet seen and this one is > 1,
	 * then we lost several RTP packets, let's replay them.
	 */
	for (i = 1; i < diff; i++) {
		struct msgb *clone;

		/* Clone last RTP packet seen */
		clone = msgb_alloc(last->data_len, "RTP clone");
		if (!clone)
			continue;

		memcpy(clone->data, last->data, last->len);
		msgb_put(clone, last->len);

		/* The original RTP message has been already sanity checked. */
		rtph = osmo_rtp_get_hdr(clone);

		/* Adjust sequence number and timestamp */
		rtph->sequence = htons(ntohs(rtph->sequence) + i);
		rtph->timestamp = htonl(ntohl(rtph->timestamp) +
					DELTA_RTP_TIMESTAMP);

		/* No more room in this batch, skip padding with more clones */
		rc = osmux_batch_enqueue(clone, circuit, batch_factor);
		if (rc != 0) {
			msgb_free(clone);
			return rc;
		}

		LOGP(DLMUX, LOGL_ERROR, "adding cloned RTP\n");
	}
	return rc;
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

static void osmux_batch_del_circuit(struct osmux_batch *batch, struct osmux_circuit *circuit)
{
	if (circuit->dummy)
		batch->ndummy--;
	llist_del(&circuit->head);
	osmux_circuit_del_msgs(batch, circuit);
	talloc_free(circuit);
}

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int
osmux_batch_add(struct osmux_batch *batch, uint32_t batch_factor, struct msgb *msg,
		struct rtp_hdr *rtph, int ccid)
{
	int bytes = 0, amr_payload_len;
	struct osmux_circuit *circuit;
	struct msgb *cur;
	int rc;
	struct amr_hdr *amrh;
	uint32_t amr_len;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (!circuit)
		return -1;

	/* We've seen the first RTP message, disable dummy padding */
	if (circuit->dummy) {
		circuit->dummy = 0;
		batch->ndummy--;
	}

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;
	amr_payload_len = osmux_rtp_amr_payload_len(amrh, amr_len);
	if (amr_payload_len < 0) {
		LOGP(DLMUX, LOGL_NOTICE, "AMR payload invalid\n");
		return -1;
	}

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

	/* First check if there is room for this message in the batch */
	/* First in batch comes after the batch header: */
	if (circuit->nmsgs == 0)
		bytes += sizeof(struct osmux_hdr);
	/* If AMR FT changes in the middle of current batch a new header is
	 * required to adapt to size change: */
	else if (osmux_circuit_get_last_stored_amr_ft(circuit) != amrh->ft)
		bytes += sizeof(struct osmux_hdr);
	bytes += amr_payload_len;

	/* No room, sorry. You'll have to retry */
	if (bytes > batch->remaining_bytes)
		return 1;

	/* Handle RTP packet loss scenario */
	rc = osmux_replay_lost_packets(circuit, rtph, batch_factor);
	if (rc != 0)
		return rc;

	/* This batch is full, force batch delivery */
	rc = osmux_batch_enqueue(msg, circuit, batch_factor);
	if (rc != 0)
		return rc;

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
 * If 0 is returned, this indicates that the message has been batched and the
 * msgb is now owned by the osmux layer.
 * If negative value is returned, an error occurred and the message has been
 * dropped (and freed).
 * If 1 is returned, you have to invoke osmux_xfrm_input_deliver and try again.
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
		LOGP(DLMUX, LOGL_NOTICE, "RTP payload too big (%u) for configured batch size (%u)\n",
			 msg->len, h->batch_size);
		msgb_free(msg);
		return -1;
	}

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		LOGP(DLMUX, LOGL_NOTICE, "msg not containing an RTP header\n");
		msgb_free(msg);
		return -1;
	}

	switch (rtph->payload_type) {
	case RTP_PT_RTCP:
		LOGP(DLMUX, LOGL_INFO, "Dropping RTCP packet\n");
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
			LOGP(DLMUX, LOGL_DEBUG, "Dropping RTP packet instead of adding to batch\n");
			msgb_free(msg);
			return ret;
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

int osmux_xfrm_input_open_circuit(struct osmux_in_handle *h, int ccid,
				  int dummy)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit != NULL) {
		LOGP(DLMUX, LOGL_ERROR, "circuit %u already exists!\n", ccid);
		return -1;
	}

	circuit = talloc_zero(osmux_ctx, struct osmux_circuit);
	if (circuit == NULL) {
		LOGP(DLMUX, LOGL_ERROR, "OOM on circuit %u\n", ccid);
		return -1;
	}

	circuit->ccid = ccid;
	circuit->seq = h->osmux_seq;
	INIT_LLIST_HEAD(&circuit->msg_list);
	llist_add_tail(&circuit->head, &batch->circuit_list);

	if (dummy) {
		circuit->dummy = dummy;
		batch->ndummy++;
		if (!osmo_timer_pending(&batch->timer))
			osmo_timer_schedule(&batch->timer, 0,
					    h->batch_factor * DELTA_RTP_MSG);
	}
	return 0;
}

void osmux_xfrm_input_close_circuit(struct osmux_in_handle *h, int ccid)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit == NULL) {
		LOGP(DLMUX, LOGL_NOTICE, "Unable to close circuit %d: Not found\n",
		     ccid);
		return;
	}

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

/*! @} */
