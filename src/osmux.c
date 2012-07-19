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

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include <arpa/inet.h>

#define DEBUG_TIMING		1

#define OSMUX_BATCH_MAX		1480	/* XXX: MTU - iphdr (20 bytes) */

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh = NULL;

	if (msg->len > sizeof(struct osmux_hdr)) {
		osmuxh = (struct osmux_hdr *)msg->data;

		msgb_pull(msg, sizeof(struct osmux_hdr) +
				osmo_amr_bytes(osmuxh->amr_cmr));
	} else if (msg->len > 0) {
		printf("remaining %d bytes, broken osmuxhdr?\n", msg->len);
	}

	return osmuxh;
}

struct msgb *
osmux_xfrm_output(struct osmux_hdr *osmuxh, struct osmux_out_handle *h)
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
	rtph->marker = osmuxh->rtp_marker;
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
	memcpy(out_msg->tail, osmux_get_payload(osmuxh),
		osmo_amr_bytes(osmuxh->amr_cmr));
	msgb_put(out_msg, osmo_amr_bytes(osmuxh->amr_cmr));

	/* bump last RTP sequence number and timestamp that has been used */
	h->rtp_seq++;
	h->rtp_timestamp++;

	return out_msg;
}

static struct osmux_batch {
	struct osmo_timer_list timer;
	struct msgb *msg;
	uint8_t seq;
} batch;

static int osmux_batch_has_room(int msg_len)
{
	return batch.msg == NULL ? 1 : msg_len < msgb_tailroom(batch.msg);
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	printf("invoking delivery function\n");
	h->deliver(batch.msg);
	msgb_free(batch.msg);
	batch.msg = NULL;
	osmo_timer_del(&batch.timer);
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

	printf("batch timeout!\n");
	osmux_xfrm_input_deliver(h);
}

static struct msgb *osmux_batch_get(void)
{
	if (batch.msg == NULL) {
		batch.msg = msgb_alloc(OSMUX_BATCH_MAX, "OSMUX");
		if (batch.msg == NULL) {
			fprintf(stderr, "Not enough memory\n");
			return NULL;
		}

		osmo_timer_schedule(&batch.timer, 0, 160000); /* XXX */
	}

	return batch.msg;
}

static int
osmux_batch_add(struct msgb *msg, struct rtp_hdr *rtph, struct amr_hdr *amrh,
		uint32_t amr_payload_len, uint8_t circuit_id, uint8_t seq)
{
	struct osmux_hdr *osmuxh;

	osmuxh = (struct osmux_hdr *)batch.msg->tail;
	osmuxh->ft = OSMUX_FT_VOICE_AMR;
	osmuxh->circuit_id = circuit_id;
	osmuxh->seq = seq;
	osmuxh->amr_cmr = amrh->cmr;
	osmuxh->amr_f = amrh->f;
	osmuxh->amr_ft = amrh->ft;
	osmuxh->amr_q = amrh->q;
	osmuxh->rtp_marker = rtph->marker;
	msgb_put(batch.msg, sizeof(struct osmux_hdr));

	memcpy(batch.msg->tail, osmo_amr_get_payload(amrh), amr_payload_len);
	msgb_put(batch.msg, amr_payload_len);

	return 0;
}

static int osmux_xfrm_encore_amr(struct rtp_hdr *rtph, struct msgb *msg)
{
	struct amr_hdr *amrh;
	struct msgb *out_msg;
	uint32_t amr_len;
	uint32_t amr_payload_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	amr_payload_len = amr_len - sizeof(struct amr_hdr);

	if (!osmux_batch_has_room(sizeof(struct osmux_hdr) + amr_payload_len))
		return 1;

	out_msg = osmux_batch_get();
	if (out_msg == NULL)
		return -1;

	if (osmux_batch_add(out_msg, rtph, amrh, amr_payload_len, 0,
				batch.seq++) < 0)
		return -1;

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
			ret = osmux_xfrm_encore_amr(rtph, msg);
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
	batch.timer.cb = osmux_batch_timer_expired;
	batch.timer.data = h;
}

struct osmux_tx_handle {
        struct osmo_timer_list  timer;
        struct msgb             *msg;
        void                    (*tx_cb)(struct msgb *msg, void *data);
        void                    *data;
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
	printf("difference %lu.%.6lu\n", diff.tv_sec, diff.tv_usec);
#endif

	h->tx_cb(h->msg, h->data);

	talloc_free(h);
}

void osmux_tx_sched(struct msgb *msg, struct timeval *when,
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
