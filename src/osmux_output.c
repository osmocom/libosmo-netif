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

/*! \file osmux_output.c
 *  \brief Osmocom multiplex protocol helpers (output)
 */

/* delta time between two RTP messages (in microseconds) */
#define DELTA_RTP_MSG		20000
/* delta time between two RTP messages (in samples, 8kHz) */
#define DELTA_RTP_TIMESTAMP	160

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
	unsigned int msg_len = sizeof(struct rtp_hdr) +
			       sizeof(struct amr_hdr) +
			       payload_len;

	if (h->rtp_msgb_alloc_cb) {
		out_msg = h->rtp_msgb_alloc_cb(h->rtp_msgb_alloc_cb_data, msg_len);
	} else {
		out_msg = msgb_alloc(msg_len, "osmux-rtp");
	}
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
	 * 2- Intermediate osmux frame lost (seq gap), otherwise rtp receiver only sees
	 *    steady increase of delay
	 */
	rtph->marker = first_pkt &&
			(osmuxh->rtp_m || (osmuxh->seq != ((h->osmux_seq_ack + 1) & 0xff)));

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

	for (i = 0; i < osmuxh->ctr + 1; i++) {
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

struct osmux_tx_handle {
	struct osmo_timer_list	timer;
	struct msgb		*msg;
	void			(*tx_cb)(struct msgb *msg, void *data);
	void			*data;
};

static int osmux_xfrm_output_talloc_destructor(struct osmux_out_handle *h)
{
	osmux_xfrm_output_flush(h);
	return 0;
}

/*! \brief Allocate a new osmux out handle
 *  \param[in] ctx talloc context to use when allocating the returned struct
 *  \return Allocated osmux out handle
 *
 * This object contains configuration and state to handle a specific CID in
 * incoming network Osmux messages, repackaging the frames for that CID as RTP
 * packets and pushing them up the protocol stack.
 * Returned pointer can be freed with regular talloc_free, queue will be flushed
 * and all internal data will be freed. */
struct osmux_out_handle *osmux_xfrm_output_alloc(void *ctx)
{
	struct osmux_out_handle *h;

	h = talloc_zero(ctx, struct osmux_out_handle);
	OSMO_ASSERT(h);

	h->rtp_seq = (uint16_t)random();
	h->rtp_timestamp = (uint32_t)random();
	h->rtp_ssrc = (uint32_t)random();
	h->rtp_payload_type = 98;
	INIT_LLIST_HEAD(&h->list);
	osmo_timer_setup(&h->timer, osmux_xfrm_output_trigger, h);

	talloc_set_destructor(h, osmux_xfrm_output_talloc_destructor);
	return h;
}

/* DEPRECATED: Use osmux_xfrm_output_alloc() and osmux_xfrm_output_set_rtp_*() instead */
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

/* DEPRECATED: Use osmux_xfrm_output_alloc() and osmux_xfrm_output_set_rtp_*() instead */
void osmux_xfrm_output_init(struct osmux_out_handle *h, uint32_t rtp_ssrc)
{
	/* backward compatibility with old users, where 98 was harcoded in osmux_rebuild_rtp()  */
	osmux_xfrm_output_init2(h, rtp_ssrc, 98);
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

/*! \brief Set callback to call when an RTP packet to be generated is to be allocated
 *  \param[in] h the osmux out handle handling a specific CID
 *  \param[in] cb User defined msgb alloc function for generated RTP pkts
 *  \param[in] cb_data Opaque data pointer set by user and passed in \ref cb
 *  \return msgb structure to be used to fill in generated RTP pkt content
 */
void osmux_xfrm_output_set_rtp_msgb_alloc_cb(struct osmux_out_handle *h,
					     rtp_msgb_alloc_cb_t cb,
					     void *cb_data)
{
	h->rtp_msgb_alloc_cb = cb;
	h->rtp_msgb_alloc_cb_data = cb_data;
}

/*! \brief Set SSRC of generated RTP packets from Osmux frames
 *  \param[in] h the osmux out handle handling a specific CID
 *  \param[in] rtp_ssrc the RTP SSRC to set
 */
void osmux_xfrm_output_set_rtp_ssrc(struct osmux_out_handle *h, uint32_t rtp_ssrc)
{
	h->rtp_ssrc = rtp_ssrc;
}

/*! \brief Set Payload Type of generated RTP packets from Osmux frames
 *  \param[in] h the osmux out handle handling a specific CID
 *  \param[in] rtp_payload_type the RTP Payload Type to set
 */
void osmux_xfrm_output_set_rtp_pl_type(struct osmux_out_handle *h, uint32_t rtp_payload_type)
{
	h->rtp_payload_type = rtp_payload_type;
}

/*! @} */
