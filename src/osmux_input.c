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
#include <inttypes.h>

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

/* This is (struct osmux_in_handle)->internal_data.
 * TODO: API have been defined to access all fields of osmux_in_handle
 * (deprecated osmux_xfrm_input_init()), hence at some point we remove struct
 * osmux_in_handle definition from osmux.h and we move it here internally and
 * merge it with struct osmux_link.
 */
struct osmux_link {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	circuit_list;
	unsigned int		remaining_bytes;
	uint32_t		nmsgs;
	int			ndummy;
	char			*name;
	struct osmux_in_handle *h; /* backpointer to parent object */
};

struct osmux_circuit {
	struct llist_head	head;
	int			ccid;
	struct llist_head	msg_list;
	int			nmsgs;
	int			dummy;
	uint8_t			seq;
	int32_t			last_transmitted_rtp_seq; /* -1 = unset */
	uint32_t		last_transmitted_rtp_ts; /* Check last_transmitted_rtp_seq = -1 to detect unset */
};

/* Used internally to temporarily cache all parsed content of an RTP pkt from user to be transmitted as Osmux */
struct osmux_in_req {
	struct osmux_circuit *circuit;
	struct msgb	*msg;
	struct rtp_hdr	*rtph;
	uint32_t	rtp_payload_len;
	struct amr_hdr	*amrh;
	int		amr_payload_len;
};

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_circuit_enqueue(struct osmux_link *link, struct osmux_circuit *circuit, struct msgb *msg)
{
	/* Validate amount of messages per batch. The counter field of the
	 * osmux header is just 3 bits long, so make sure it doesn't overflow.
	 */
	OSMO_ASSERT(link->h->batch_factor <= 8);
	if (circuit->nmsgs >= link->h->batch_factor) {
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

static void osmux_circuit_dequeue(struct osmux_circuit *circuit, struct msgb *msg)
{
	llist_del(&msg->list);
	circuit->nmsgs--;
}

static void osmux_circuit_del_msgs(struct osmux_link *link, struct osmux_circuit *circuit)
{
	struct msgb *cur, *tmp;
	llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
		osmux_circuit_dequeue(circuit, cur);
		msgb_free(cur);
		link->nmsgs--;
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

static int osmux_link_put(struct osmux_link *link, struct osmux_input_state *state)
{
	uint16_t rtp_seqnum = ntohs(state->rtph->sequence);

	if (state->add_osmux_hdr) {
		bool seq_jump = state->circuit->last_transmitted_rtp_seq != -1 &&
				((state->circuit->last_transmitted_rtp_seq + 1) & 0xffff) != rtp_seqnum;
		struct osmux_hdr *osmuxh;
		osmuxh = (struct osmux_hdr *)msgb_put(state->out_msg,
						      sizeof(struct osmux_hdr));
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->rtp_m = state->rtph->marker || seq_jump;
		osmuxh->seq = state->circuit->seq++;
		osmuxh->circuit_id = state->circuit->ccid;
		osmuxh->amr_ft = state->amrh->ft;

		/* annotate current osmux header */
		link->osmuxh = osmuxh;
	} else {
		if (link->osmuxh->ctr == 0x7) {
			LOGP(DLMUX, LOGL_ERROR, "cannot add msg=%p, "
			     "too many messages for this RTP ssrc=%u\n",
			     state->msg, state->rtph->ssrc);
			return 0;
		}
		link->osmuxh->ctr++;
	}
	/* For fields below, we only use the last included in batch and ignore any previous: */
	link->osmuxh->amr_cmr = state->amrh->cmr;
	link->osmuxh->amr_f = state->amrh->f;
	link->osmuxh->amr_q = state->amrh->q;

	memcpy(state->out_msg->tail, osmo_amr_get_payload(state->amrh),
	       state->amr_payload_len);
	msgb_put(state->out_msg, state->amr_payload_len);

	/* Update circuit state of last transmitted incoming RTP seqnum/ts: */
	state->circuit->last_transmitted_rtp_seq = rtp_seqnum;
	state->circuit->last_transmitted_rtp_ts = ntohl(state->rtph->timestamp);
	return 0;
}

static void osmux_encode_dummy(struct osmux_link *link, struct osmux_input_state *state)
{
	struct osmux_hdr *osmuxh;
	/* TODO: This should be configurable at some point. */
	uint32_t payload_size = osmux_ft_dummy_size(AMR_FT_3, link->h->batch_factor) -
				sizeof(struct osmux_hdr);

	osmuxh = (struct osmux_hdr *)state->out_msg->tail;
	osmuxh->ft = OSMUX_FT_DUMMY;
	osmuxh->ctr = link->h->batch_factor - 1;
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

static struct msgb *osmux_build_batch(struct osmux_link *link)
{
	struct msgb *batch_msg;
	struct osmux_circuit *circuit;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "Now building batch\n");
#endif

	batch_msg = msgb_alloc(link->h->batch_size, "osmux");
	if (batch_msg == NULL) {
		LOGP(DLMUX, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	llist_for_each_entry(circuit, &link->circuit_list, head) {
		struct msgb *cur, *tmp;
		int ctr = 0;
		int prev_amr_ft;

		if (circuit->dummy) {
			struct osmux_input_state state = {
				.out_msg	= batch_msg,
				.circuit	= circuit,
			};
			osmux_encode_dummy(link, &state);
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

			osmux_link_put(link, &state);
			osmux_circuit_dequeue(circuit, cur);
			prev_amr_ft = state.amrh->ft;
			ctr++;
			msgb_free(cur);
			link->nmsgs--;
		}
	}
	return batch_msg;
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct osmux_link *link = (struct osmux_link *)h->internal_data;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "invoking delivery function\n");
#endif
	batch_msg = osmux_build_batch(link);
	if (!batch_msg)
		return;
	h->stats.output_osmux_msgs++;
	h->stats.output_osmux_bytes += batch_msg->len;

	h->deliver(batch_msg, h->data);
	osmo_timer_del(&link->timer);
	link->remaining_bytes = h->batch_size;

	if (link->ndummy)
		osmo_timer_schedule(&link->timer, 0, h->batch_factor * DELTA_RTP_MSG);
}

static void osmux_link_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "osmux_link_timer_expired\n");
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
		     "Bad AMR frame FT=%u, expected %zd bytes, got %d bytes\n",
		     amrh->ft, osmo_amr_bytes(amrh->ft), amr_len);
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

static struct osmux_circuit *
osmux_link_find_circuit(struct osmux_link *link, int ccid)
{
	struct osmux_circuit *circuit;

	llist_for_each_entry(circuit, &link->circuit_list, head) {
		if (circuit->ccid == ccid)
			return circuit;
	}
	return NULL;
}

static void osmux_link_del_circuit(struct osmux_link *link, struct osmux_circuit *circuit)
{
	if (circuit->dummy)
		link->ndummy--;
	llist_del(&circuit->head);
	osmux_circuit_del_msgs(link, circuit);
	talloc_free(circuit);
}

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_link_add(struct osmux_link *link, const struct osmux_in_req *req)
{
	unsigned int needed_bytes = 0;
	int rc;
	/* Init of talkspurt (RTP M marker bit) needs to be in the first AMR slot
	 * of the OSMUX packet, enforce sending previous batch if required:
	 */
	if (req->rtph->marker && req->circuit->nmsgs != 0)
		return 1;

	/* First check if there is room for this message in the batch */
	/* First in batch comes after the batch header: */
	if (req->circuit->nmsgs == 0)
		needed_bytes += sizeof(struct osmux_hdr);
	/* If AMR FT changes in the middle of current batch a new header is
	 * required to adapt to size change: */
	else if (osmux_circuit_get_last_stored_amr_ft(req->circuit) != req->amrh->ft)
		needed_bytes += sizeof(struct osmux_hdr);
	needed_bytes += req->amr_payload_len;

	/* No room, sorry. You'll have to retry */
	if (needed_bytes > link->remaining_bytes)
		return 1;

	/* This batch is full, force batch delivery */
	rc = osmux_circuit_enqueue(link, req->circuit, req->msg);
	if (rc != 0)
		return rc;

#ifdef DEBUG_MSG
	LOGP(DLMUX, LOGL_DEBUG, "adding msg with ssrc=%u to batch\n",
		rtph->ssrc);
#endif

	/* Update remaining room in this batch */
	link->remaining_bytes -= needed_bytes;

	if (link->nmsgs == 0) {
#ifdef DEBUG_MSG
		LOGP(DLMUX, LOGL_DEBUG, "osmux start timer batch\n");
#endif
		osmo_timer_schedule(&link->timer, 0,
				    link->h->batch_factor * DELTA_RTP_MSG);
	}
	link->nmsgs++;

	return 0;
};

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_replay_lost_packets(struct osmux_link *link, const struct osmux_in_req *req)
{
	int16_t diff;
	uint16_t lost_pkts;
	struct msgb *copy_from;
	uint16_t last_seq, cur_seq;
	uint32_t last_ts;
	int i, rc;
	struct osmux_in_req clone_req;

	/* If M bit is set, this is a sync point, so any sort of seq jump is expected and has no real meaning. */
	if (req->rtph->marker)
		return 0;

	/* Have we seen any RTP packet in this batch before? */
	if (llist_empty(&req->circuit->msg_list)) {
		/* Since current batch is empty, it can be assumed:
		 * 1- circuit->last_transmitted_rtp_seq is either unset or really contains the last RTP enqueued
		 * 2- This pkt will generate an osmuxhdr and hence there's no
		 *    restriction on the FT, as opposite to the case where the batch
		 *    is half full
		 * Conclusion:
		 * 1- It is fine using circuit->last_transmitted_rtp_seq as last enqueued RTP header to detect seqnum jumps.
		 * 2- It is fine filling holes at the start of the batch by using current req->rtph.
		 */
		if (req->circuit->last_transmitted_rtp_seq == -1)
			return 0; /* first message in circuit, do nothing */
		copy_from = req->msg;
		last_seq = req->circuit->last_transmitted_rtp_seq;
		last_ts = req->circuit->last_transmitted_rtp_ts;
	} else {
		/* Get last RTP packet seen in this batch, so that we simply keep filling with same osmuxhdr */
		struct rtp_hdr *last_rtph;
		copy_from = llist_entry(req->circuit->msg_list.prev, struct msgb, list);
		last_rtph = osmo_rtp_get_hdr(copy_from);
		if (last_rtph == NULL)
			return -1;
		last_seq = ntohs(last_rtph->sequence);
		last_ts = ntohl(last_rtph->timestamp);
	}
	cur_seq = ntohs(req->rtph->sequence);
	diff = cur_seq - last_seq;

	/* If diff between last RTP packet seen and this one is > 1,
	 * then we lost several RTP packets, let's replay them.
	 */
	if (diff <= 1)
		return 0;
	lost_pkts = diff - 1;

	LOGP(DLMUX, LOGL_INFO, "RTP seq jump detected: %" PRIu16 " -> %" PRIu16 " (%" PRId16
	     " lost packets, %u/%u batched)\n",
	     last_seq, cur_seq, lost_pkts, req->circuit->nmsgs, link->h->batch_factor);

	/* We know we can feed only up to batch_factor before osmux_link_add()
	 * returning 1 signalling "transmission needed, call deliver() and retry".
	 * Hence, it doesn't make sense to even attempt recreating a big number of
	 * RTP packets (>batch_factor).
	 */
	if (lost_pkts > link->h->batch_factor - req->circuit->nmsgs) {
		if (llist_empty(&req->circuit->msg_list)) {
			/* If we are starting a batch, it doesn't make sense to keep filling entire
			 * batches with lost packets, since it could potentially end up in a loop if
			 * the lost_pkts value is huge. Instead, avoid recreating packets and let the
			 * osmux encoder set an M bit on the osmuxhdr when acting upon current req->rtph.
			 */
			return 0;
		}
		lost_pkts = link->h->batch_factor - req->circuit->nmsgs;
	}

	rc = 0;
	clone_req = *req;
	for (i = 0; i < lost_pkts; i++) {
		/* Clone last (or new if last not available) RTP packet seen */
		clone_req.msg = msgb_copy(copy_from, "RTP clone");
		if (!clone_req.msg)
			continue;

		/* The original RTP message has been already sanity checked. */
		clone_req.rtph = osmo_rtp_get_hdr(clone_req.msg);
		clone_req.amrh = osmo_rtp_get_payload(clone_req.rtph, clone_req.msg, &clone_req.rtp_payload_len);
		clone_req.amr_payload_len = osmux_rtp_amr_payload_len(clone_req.amrh, clone_req.rtp_payload_len);

		/* Faking a follow up RTP pkt here, so no Marker bit: */
		clone_req.rtph->marker = false;
		/* Adjust sequence number and timestamp */
		clone_req.rtph->sequence = htons(last_seq + 1 + i);
		clone_req.rtph->timestamp = last_ts + ((1 + i) * DELTA_RTP_TIMESTAMP);
		rc = osmux_link_add(link, &clone_req);
		/* No more room in this batch, skip padding with more clones */
		if (rc != 0) {
			msgb_free(clone_req.msg);
			return rc;
		}
	}
	return rc;
}

/* returns: 1 if batch is full, 0 if batch still not full, negative on error. */
static int osmux_link_handle_rtp_req(struct osmux_link *link, struct osmux_in_req *req)
{
	struct msgb *cur, *next;
	int rc;

	/* We've seen the first RTP message, disable dummy padding */
	if (req->circuit->dummy) {
		req->circuit->dummy = 0;
		link->ndummy--;
	}

	/* Extra validation: check if this message already exists, should not
	 * happen but make sure we don't propagate duplicated messages.
	 */
	llist_for_each_entry_safe(cur, next, &req->circuit->msg_list, list) {
		struct rtp_hdr *rtph2 = osmo_rtp_get_hdr(cur);
		OSMO_ASSERT(rtph2);

		/* Already exists message with this sequence. Let's copy over
		 * the new RTP, since there's the chance that the existing one may
		 * be a forged copy we did when we detected a hole. */
		if (rtph2->sequence == req->rtph->sequence) {
			if (msgb_length(cur) != msgb_length(req->msg)) {
				/* Different packet size, AMR FT may have changed. Let's avoid changing it to
				 * break accounted size to be written (would need new osmux_hdr, etc.) */
				LOGP(DLMUX, LOGL_NOTICE, "RTP pkt with seq=%u and different len %u != %u already exists, skip it\n",
				     ntohs(req->rtph->sequence), msgb_length(cur), msgb_length(req->msg));
				return -1;
			}
			LOGP(DLMUX, LOGL_INFO, "RTP pkt with seq=%u already exists, replace it\n",
				ntohs(req->rtph->sequence));
			__llist_add(&req->msg->list, &cur->list, cur->list.next);
			llist_del(&cur->list);
			msgb_free(cur);
			return 0;
		}
	}

	/* Handle RTP packet loss scenario */
	rc = osmux_replay_lost_packets(link, req);
	if (rc != 0)
		return rc;

	return osmux_link_add(link, req);
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
	struct osmux_link *link = (struct osmux_link *)h->internal_data;
	struct osmux_in_req req = {
		.msg = msg,
		.rtph = osmo_rtp_get_hdr(msg),
		.circuit = osmux_link_find_circuit(link, ccid),
	};

	if (!req.circuit) {
		LOGP(DLMUX, LOGL_INFO, "Couldn't find circuit CID=%u\n", ccid);
		goto err_free;
	}

	if (!req.rtph) {
		LOGP(DLMUX, LOGL_NOTICE, "msg not containing an RTP header\n");
		goto err_free;
	}

	/* Ignore too big RTP/RTCP messages, most likely forged. Sanity check
	 * to avoid a possible forever loop in the caller.
	 */
	if (msg->len > h->batch_size - sizeof(struct osmux_hdr)) {
		LOGP(DLMUX, LOGL_NOTICE, "RTP payload too big (%u) for configured batch size (%u)\n",
			 msg->len, h->batch_size);
		goto err_free;
	}

	switch (req.rtph->payload_type) {
	case RTP_PT_RTCP:
		LOGP(DLMUX, LOGL_INFO, "Dropping RTCP packet\n");
		msgb_free(msg);
		return 0;
	default:
		/* The RTP payload type is dynamically allocated,
		 * although we use static ones. Assume that we always
		 * receive AMR traffic.
		 */
		req.amrh = osmo_rtp_get_payload(req.rtph, req.msg, &req.rtp_payload_len);
		if (req.amrh == NULL)
			goto err_free;
		req.amr_payload_len = osmux_rtp_amr_payload_len(req.amrh, req.rtp_payload_len);
		if (req.amr_payload_len < 0) {
			LOGP(DLMUX, LOGL_NOTICE, "AMR payload invalid\n");
			goto err_free;
		}

		/* Add this RTP to the OSMUX batch */
		ret = osmux_link_handle_rtp_req(link, &req);
		if (ret < 0) {
			/* Cannot put this message into the batch.
				* Malformed, duplicated, OOM. Drop it and tell
				* the upper layer that we have digest it.
				*/
			LOGP(DLMUX, LOGL_DEBUG, "Dropping RTP packet instead of adding to batch\n");
			goto err_free;
		}

		h->stats.input_rtp_msgs++;
		h->stats.input_rtp_bytes += msg->len;
		break;
	}
	return ret;

err_free:
	msgb_free(msg);
	return -1;
}

static int osmux_xfrm_input_talloc_destructor(struct osmux_in_handle *h)
{
	struct osmux_link *link = (struct osmux_link *)h->internal_data;
	struct osmux_circuit *circuit, *next;

	llist_for_each_entry_safe(circuit, next, &link->circuit_list, head)
		osmux_link_del_circuit(link, circuit);

	osmo_timer_del(&link->timer);
	talloc_free(link);
	return 0;
}

/*! \brief Allocate a new osmux in handle (osmux source, tx side)
 *  \param[in] ctx talloc context to use when allocating the returned struct
 *  \return Allocated osmux in handle
 *
 * This object contains configuration and state to handle a group of circuits (trunk),
 * receiving RTP packets from the upper layer (API user) and sending batched &
 * trunked Osmux messages containing all the data of those circuits down the
 * stack outgoing network Osmux messages.
 * Returned pointer can be freed with regular talloc_free, all pending messages
 * in queue and all internal data will be freed. */
static unsigned int next_default_name_idx = 0;
struct osmux_in_handle *osmux_xfrm_input_alloc(void *ctx)
{
	struct osmux_in_handle *h;
	struct osmux_link *link;

	h = talloc_zero(ctx, struct osmux_in_handle);
	OSMO_ASSERT(h);

	h->batch_size = OSMUX_BATCH_DEFAULT_MAX;

	link = talloc_zero(h, struct osmux_link);
	OSMO_ASSERT(link);
	INIT_LLIST_HEAD(&link->circuit_list);
	link->h = h;
	link->remaining_bytes = h->batch_size;
	link->name = talloc_asprintf(link, "input-%u", next_default_name_idx++);
	osmo_timer_setup(&link->timer, osmux_link_timer_expired, h);

	h->internal_data = (void *)link;

	LOGP(DLMUX, LOGL_DEBUG, "[%s] Initialized osmux input converter\n",
	     link->name);

	talloc_set_destructor(h, osmux_xfrm_input_talloc_destructor);
	return h;
}

/* DEPRECATED: Use osmux_xfrm_input_alloc() instead */
void osmux_xfrm_input_init(struct osmux_in_handle *h)
{
	struct osmux_link *link;

	/* Default to osmux packet size if not specified */
	if (h->batch_size == 0)
		h->batch_size = OSMUX_BATCH_DEFAULT_MAX;

	link = talloc_zero(osmux_ctx, struct osmux_link);
	if (link == NULL)
		return;
	INIT_LLIST_HEAD(&link->circuit_list);
	link->h = h;
	link->remaining_bytes = h->batch_size;
	link->name = talloc_asprintf(link, "%u", next_default_name_idx++);
	osmo_timer_setup(&link->timer, osmux_link_timer_expired, h);

	h->internal_data = (void *)link;

	LOGP(DLMUX, LOGL_DEBUG, "[%s] Initialized osmux input converter\n",
	     link->name);
}

int osmux_xfrm_input_set_batch_factor(struct osmux_in_handle *h, uint8_t batch_factor)
{
	if (batch_factor > 8)
		return -1;
	h->batch_factor = batch_factor;
	return 0;
}

void osmux_xfrm_input_set_batch_size(struct osmux_in_handle *h, uint16_t batch_size)
{
	if (batch_size == 0)
		h->batch_size = OSMUX_BATCH_DEFAULT_MAX;
	else
		h->batch_size = batch_size;
}

void osmux_xfrm_input_set_initial_seqnum(struct osmux_in_handle *h, uint8_t osmux_seqnum)
{
	h->osmux_seq = osmux_seqnum;
}

void osmux_xfrm_input_set_deliver_cb(struct osmux_in_handle *h,
				     void (*deliver_cb)(struct msgb *msg, void *data), void *data)
{
	h->deliver = deliver_cb;
	h->data = data;
}

void *osmux_xfrm_input_get_deliver_cb_data(struct osmux_in_handle *h)
{
	return h->data;
}

void osmux_xfrm_input_set_name(struct osmux_in_handle *h, const char *name)
{
	struct osmux_link *link = (struct osmux_link *)h->internal_data;
	osmo_talloc_replace_string(link, &link->name, name);
}

int osmux_xfrm_input_open_circuit(struct osmux_in_handle *h, int ccid,
				  int dummy)
{
	struct osmux_link *link = (struct osmux_link *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_link_find_circuit(link, ccid);
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
	circuit->last_transmitted_rtp_seq = -1; /* field unset */
	INIT_LLIST_HEAD(&circuit->msg_list);
	llist_add_tail(&circuit->head, &link->circuit_list);

	if (dummy) {
		circuit->dummy = dummy;
		link->ndummy++;
		if (!osmo_timer_pending(&link->timer))
			osmo_timer_schedule(&link->timer, 0,
					    h->batch_factor * DELTA_RTP_MSG);
	}
	return 0;
}

void osmux_xfrm_input_close_circuit(struct osmux_in_handle *h, int ccid)
{
	struct osmux_link *link = (struct osmux_link *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_link_find_circuit(link, ccid);
	if (circuit == NULL) {
		LOGP(DLMUX, LOGL_NOTICE, "Unable to close circuit %d: Not found\n",
		     ccid);
		return;
	}

	osmux_link_del_circuit(link, circuit);
}

/* DEPRECATED: Use talloc_free() instead (will call osmux_xfrm_input_talloc_destructor()) */
void osmux_xfrm_input_fini(struct osmux_in_handle *h)
{
	(void)osmux_xfrm_input_talloc_destructor(h);
}

/*! @} */
