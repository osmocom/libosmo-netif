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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <getopt.h>

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>
#include <osmocom/netif/amr.h>

static uint8_t osmux_next_seq;

#define TIME_RTP_PKT_MS 20
#define BATCH_FACTOR 6
/* ----------------------------- */

/* Logging related stuff */
#define INT2IDX(x)   (-1*(x)-1)
struct log_info_cat jibuf_test_cat[] = {
	[INT2IDX(DLMUX)] = {
		.name = "DLMUX",
		.description = "Osmocom Osmux",
		.enabled = 1, .loglevel = LOGL_DEBUG,
		},
};
const struct log_info log_info = {
	.filter_fn = NULL,
	.cat = jibuf_test_cat,
	.num_cat = ARRAY_SIZE(jibuf_test_cat),
};
/* ----------------------------- */

static void osmux_init(uint8_t seq)
{
	osmux_next_seq = seq;
}

static struct msgb *osmux_new(uint8_t cid, uint8_t seq, uint8_t batch_factor)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;

	msg = msgb_alloc(1500, "test");
	if (!msg)
		exit(EXIT_FAILURE);
	msgb_put(msg, sizeof(struct osmux_hdr));

	osmuxh = (struct osmux_hdr *)msg->data;
	osmuxh->amr_q = 0;
	osmuxh->amr_f = 0;
	osmuxh->rtp_m = 0;
	osmuxh->ctr = batch_factor - 1;
	osmuxh->ft = 1;
	osmuxh->seq = osmux_next_seq;
	osmuxh->circuit_id = cid;
	osmuxh->amr_ft = AMR_FT_2; /* 5.90 */
	osmuxh->amr_cmr = 0;
	msgb_put(msg, osmo_amr_bytes(osmuxh->amr_ft)*batch_factor);
	return msg;
}

static struct msgb *osmux_next(void)
{
	osmux_next_seq++;
	return osmux_new(0, osmux_next_seq, BATCH_FACTOR);
}

static void sigalarm_handler(int foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}


static void clock_debug(char* str)
{
	struct timespec ts;
	struct timeval tv;
	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	osmo_gettimeofday(&tv, NULL);
	printf("sys={%lu.%06lu}, mono={%lu.%06lu}: %s\n",
		tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec/1000, str);
}

static void clock_override_enable(bool enable)
{
	osmo_gettimeofday_override = enable;
	osmo_clock_override_enable(CLOCK_MONOTONIC, enable);
}

static void clock_override_set(long sec, long usec)
{
	struct timespec *mono;
	osmo_gettimeofday_override_time.tv_sec = sec;
	osmo_gettimeofday_override_time.tv_usec = usec;
	mono = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	mono->tv_sec = sec;
	mono->tv_nsec = usec*1000;

	clock_debug("clock_override_set");
}

static void clock_override_add_debug(long sec, long usec, bool dbg)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec*1000);
	if (dbg)
		clock_debug("clock_override_add");
}
#define clock_override_add(sec, usec) clock_override_add_debug(sec, usec, true)

static void tx_cb(struct msgb *msg, void *data)
{
	struct osmux_out_handle *h_output = (struct osmux_out_handle *) data;
	struct rtp_hdr *rtph;
	char buf[250];
	rtph = osmo_rtp_get_hdr(msg);
	snprintf(buf, sizeof(buf), "dequeue: seq=%"PRIu16" ts=%"PRIu32"%s enqueued=%u",
		ntohs(rtph->sequence), ntohl(rtph->timestamp), rtph->marker ? " M" : "",
		llist_count(&h_output->list));
	clock_debug(buf);
	msgb_free(msg);
}

#define PULL_NEXT(h_output) { \
		struct msgb *_msg; \
		struct osmux_hdr *_osmuxh; \
		int _rc; \
		_msg = osmux_next(); \
		_osmuxh = osmux_xfrm_output_pull(_msg); \
		OSMO_ASSERT(_osmuxh); \
		_rc = osmux_xfrm_output_sched((h_output), _osmuxh); \
		OSMO_ASSERT(_rc == _osmuxh->ctr+1); \
		}

/* Test some regular scenario where frames arrive at exactly the time they should. */
static void test_output_consecutive(void)
{
	struct osmux_out_handle *h_output;

	printf("===test_output_consecutive===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	osmux_init(32);

	h_output = osmux_xfrm_output_alloc(NULL);
	osmux_xfrm_output_set_rtp_ssrc(h_output, 0x7000000);
	osmux_xfrm_output_set_rtp_pl_type(h_output, 98);
	osmux_xfrm_output_set_tx_cb(h_output, tx_cb, h_output);
	h_output->rtp_seq = (uint16_t)50;
	h_output->rtp_timestamp = (uint32_t)500;

	/* First osmux frame at t=0 */
	PULL_NEXT(h_output);
	clock_debug("first dequed before first select");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("second select, second dequed");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("third select, third dequed");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("fourth select, fourth dequed");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("fifth select, fifth dequed");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("sixth select, sixth dequed");
	osmo_select_main(0);
	OSMO_ASSERT(llist_empty(&h_output->list));

	/* Second osmux frame at t=80 */
	clock_debug("send second osmux frame");
	PULL_NEXT(h_output);
	clock_debug("first dequed before first select");
	osmo_select_main(0);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("second select, second dequed");
	osmo_select_main(0);

	clock_override_add(0, 4*TIME_RTP_PKT_MS*1000);
	clock_debug("third select, four packet should be dequeued");
	osmo_select_main(0);
	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	clock_debug("calling flush on empty list, should do nothing");
	osmux_xfrm_output_flush(h_output);
	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	talloc_free(h_output);
}

/* Test that receiving new osmux frame triggers flushing of RTP pakcets
 * generated from previous one, to avoid steady growing delay in scheduling due to
 * jitter of osmux packets received. Specifically test case where the 2 Osmux
 * packets arrive with a small delay of system time in between them, aka the 1st
 * Osmux frame has had some of its AMR payloads already forwarded as RTP to the
 * upper layers. */
static void test_output_interleaved(void)
{
	struct osmux_out_handle *h_output;

	printf("===test_output_interleaved===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	osmux_init(32);

	h_output = osmux_xfrm_output_alloc(NULL);
	osmux_xfrm_output_set_rtp_ssrc(h_output, 0x7000000);
	osmux_xfrm_output_set_rtp_pl_type(h_output, 98);
	osmux_xfrm_output_set_tx_cb(h_output, tx_cb, h_output);
	h_output->rtp_seq = (uint16_t)50;
	h_output->rtp_timestamp = (uint32_t)500;

	/* First osmux frame at t=0, but it actually arrives late due to jitter,
	   so 2nd frame is going to arrive before the 1st one is completelly
	   scheduled */
	PULL_NEXT(h_output);

	clock_override_add(0, 2*TIME_RTP_PKT_MS*1000);
	clock_debug("select, 3 dequed, 3 still queued");
	osmo_select_main(0);

	/* Second osmux frame at t=0 */
	clock_debug("next frame arrives, 3 pending rtp packets are dequeued and first of new osmux frame too");
	PULL_NEXT(h_output);
	osmo_select_main(0);
	OSMO_ASSERT(llist_count(&h_output->list) == 5);

	clock_override_add(0, 5*TIME_RTP_PKT_MS*1000);
	clock_debug("calling select, then all should be out");
	osmo_select_main(0);

	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	talloc_free(h_output);
}

/* Test that receiving new osmux frame triggers flushing of RTP pakcets
 * generated from previous one, to avoid steady growing delay in scheduling due to
 * jitter of osmux packets received. Specifically test case where the 2 Osmux
 * packets arrive (almost) exactly at the same time, so no internal acton is
 * triggered between receival of those. */
static void test_output_2together(void)
{
	struct osmux_out_handle *h_output;

	printf("===test_output_2together===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	osmux_init(32);

	h_output = osmux_xfrm_output_alloc(NULL);
	osmux_xfrm_output_set_rtp_ssrc(h_output, 0x7000000);
	osmux_xfrm_output_set_rtp_pl_type(h_output, 98);
	osmux_xfrm_output_set_tx_cb(h_output, tx_cb, h_output);
	h_output->rtp_seq = (uint16_t)50;
	h_output->rtp_timestamp = (uint32_t)500;

	/* First osmux frame at t=0, but it actually arrives late due to jitter,
	   so we receive both at the same time. */
	PULL_NEXT(h_output);
	clock_debug("calling select in between 2 osmux recv");
	osmo_select_main(0);
	PULL_NEXT(h_output);

	clock_debug("calling select after receiving 2nd osmux. Dequeue 1st osmux frame and 1st rtp from 2nd osmux frame.");
	osmo_select_main(0);
	OSMO_ASSERT(llist_count(&h_output->list) == 5);

	clock_override_add(0, 5*TIME_RTP_PKT_MS*1000);
	clock_debug("select, all 5 remaining should be out");
	osmo_select_main(0);

	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	talloc_free(h_output);
}

/* Generated rtp stream gets first RTP pkt marked with M bit after osmux frame
 * lost is detected (hence a gap in sequence) */
static void test_output_frame_lost(void)
{
	struct osmux_out_handle *h_output;

	printf("===test_output_frame_lost===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	osmux_init(32);

	h_output = osmux_xfrm_output_alloc(NULL);
	osmux_xfrm_output_set_rtp_ssrc(h_output, 0x7000000);
	osmux_xfrm_output_set_rtp_pl_type(h_output, 98);
	osmux_xfrm_output_set_tx_cb(h_output, tx_cb, h_output);
	h_output->rtp_seq = (uint16_t)50;
	h_output->rtp_timestamp = (uint32_t)500;

	clock_debug("first osmux frame");
	PULL_NEXT(h_output);
	clock_override_add(0, 5*TIME_RTP_PKT_MS*1000);
	osmo_select_main(0);

	clock_debug("one osmux frame is now lost (seq++)");
	osmux_next();
	clock_override_add(0, 6*TIME_RTP_PKT_MS*1000);

	clock_debug("3rd osmux frame arrives");
	PULL_NEXT(h_output);
	clock_override_add(0, 5*TIME_RTP_PKT_MS*1000);
	osmo_select_main(0);

	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	talloc_free(h_output);
}

/* Test all packets are transmitted immediately when osmux_xfrm_output_flush()
 * is called. */
static void test_output_flush(void)
{
	struct osmux_out_handle *h_output;

	printf("===test_output_flush===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	osmux_init(32);

	h_output = osmux_xfrm_output_alloc(NULL);
	osmux_xfrm_output_set_rtp_ssrc(h_output, 0x7000000);
	osmux_xfrm_output_set_rtp_pl_type(h_output, 98);
	osmux_xfrm_output_set_tx_cb(h_output, tx_cb, h_output);
	h_output->rtp_seq = (uint16_t)50;
	h_output->rtp_timestamp = (uint32_t)500;

	clock_debug("first osmux frame");
	PULL_NEXT(h_output);
	clock_override_add(0, 2*TIME_RTP_PKT_MS*1000);
	osmo_select_main(0);

	clock_debug("2nd osmux frame arrives");
	PULL_NEXT(h_output);

	clock_debug("flushing, all packet should be transmitted immediately");
	OSMO_ASSERT(llist_count(&h_output->list) == 9);
	OSMO_ASSERT(osmo_timer_pending(&h_output->timer));
	osmux_xfrm_output_flush(h_output);
	OSMO_ASSERT(llist_empty(&h_output->list));
	OSMO_ASSERT(!osmo_timer_pending(&h_output->timer));

	talloc_free(h_output);
}

int main(int argc, char **argv)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	void *tall_ctx = talloc_named_const(NULL, 1, "Root context");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_category_filter(osmo_stderr_target, DLMUX, 1, LOGL_DEBUG);

	alarm(10);

	test_output_consecutive();
	test_output_interleaved();
	test_output_2together();
	test_output_frame_lost();
	test_output_flush();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
