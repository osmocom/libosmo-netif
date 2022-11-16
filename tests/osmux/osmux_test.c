/*
 * (C) 2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2013 by On Waves ehf <http://www.on-waves.com>
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>

#define DOSMUX_TEST 0

struct log_info_cat osmux_test_cat[] = {
	[DOSMUX_TEST] = {
		.name = "DOSMUX_TEST",
		.description = "osmux test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmux_test_log_info = {
	.filter_fn = NULL,
	.cat = osmux_test_cat,
	.num_cat = ARRAY_SIZE(osmux_test_cat),
};

/* RTP packet with AMR payload */
static uint8_t rtp_pkt[] = {
	0x80, 0x62, 0x3f, 0xcc, 0x00, 0x01, 0xa7, 0x6f, /* RTP */
	0x07, 0x09, 0x00, 0x62, 0x20, 0x14, 0xff, 0xd4, /* AMR */
	0xf9, 0xff, 0xfb, 0xe7, 0xeb, 0xf9, 0x9f, 0xf8,
	0xf2, 0x26, 0x33, 0x65, 0x54,
};

#define PKT_TIME_USEC 20*1000

static int rtp_pkts;
static int mark_pkts;

#define clock_debug(fmt, args...) \
	do { \
		struct timespec ts; \
		struct timeval tv; \
		osmo_clock_gettime(CLOCK_MONOTONIC, &ts); \
		osmo_gettimeofday(&tv, NULL); \
		fprintf(stderr, "sys={%lu.%06lu}, mono={%lu.%06lu}: " fmt, \
			tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec/1000, ##args); \
	} while(0)

static void clock_override_enable(bool enable)
{
	osmo_gettimeofday_override = enable;
	osmo_clock_override_enable(CLOCK_MONOTONIC, enable);
}

static void clock_override_add_debug(long sec, long usec, bool dbg)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec*1000);
	if (dbg)
		clock_debug("clock_override_add\n");
}
#define clock_override_add(sec, usec) clock_override_add_debug(sec, usec, true)

static void tx_cb(struct msgb *msg, void *data)
{
	struct rtp_hdr *rtph = (struct rtp_hdr *)msg->data;
	char buf[4096];

	osmo_rtp_snprintf(buf, sizeof(buf), msg);
	clock_debug("extracted packet: %s\n", buf);

	if (memcmp(msg->data + sizeof(struct rtp_hdr),
		   rtp_pkt + sizeof(struct rtp_hdr),
		   sizeof(rtp_pkt) - sizeof(struct rtp_hdr)) != 0) {
		clock_debug("payload mismatch!\n");
		exit(EXIT_FAILURE);
	}

	if (rtph->marker)
		mark_pkts--;
	rtp_pkts--;
	msgb_free(msg);
}

static struct osmux_out_handle *h_output[4];

static void osmux_deliver(struct msgb *batch_msg, void *data)
{
	struct osmux_hdr *osmuxh;
	char buf[2048];

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	clock_debug("OSMUX message (len=%d): %s\n", batch_msg->len, buf);

	/* For each OSMUX message, extract the RTP messages and put them
	 * in a list. Then, reconstruct transmission timing.
	 */
	while((osmuxh = osmux_xfrm_output_pull(batch_msg)) != NULL)
		osmux_xfrm_output_sched(h_output[osmuxh->circuit_id], osmuxh);
	msgb_free(batch_msg);
}

struct osmux_in_handle *h_input;

static void sigalarm_handler(int foo)
{
	clock_debug("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

static void osmux_test_marker(int num_ccid)
{
	struct msgb *msg;
	struct rtp_hdr *rtph = (struct rtp_hdr *)rtp_pkt;
	struct rtp_hdr *cpy_rtph;
	uint16_t seq;
	int i, j;

	for (i = 0; i < 64; i++) {

		seq = ntohs(rtph->sequence);
		seq++;
		rtph->sequence = htons(seq);

		for (j = 0; j < num_ccid; j++) {
			msg = msgb_alloc(1500, "test");
			if (!msg)
				exit(EXIT_FAILURE);

			memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
			cpy_rtph = (struct rtp_hdr *) msgb_put(msg, sizeof(rtp_pkt));

			/* first condition guarantees that 1st packet per stream contains M bit set. */
			if (i == 0 || (i+j) % 7 == 0) {
				cpy_rtph->marker = 1;
				mark_pkts++;
			}

			rtp_pkts++;
			while (osmux_xfrm_input(h_input, msg, j) > 0) {
				osmux_xfrm_input_deliver(h_input);
			}
		}
		clock_override_add(0, PKT_TIME_USEC);
	}

	while (rtp_pkts) {
		clock_override_add(1, 0);
		osmo_select_main(0);
	}

	if (mark_pkts) {
		clock_debug("osmux_test_marker: RTP M bit (marker) mismatch! %d\n", mark_pkts);
		exit(EXIT_FAILURE);
	}
}

static void osmux_test_loop(int ccid)
{
	struct rtp_hdr *rtph = (struct rtp_hdr *)rtp_pkt;
	struct rtp_hdr *cpy_rtph;
	struct msgb *msg;
	int i, j, k = 0;
	char buf[1024];
	uint16_t seq;

	for (i = 1; i < 65; i++) {
		msg = msgb_alloc(1500, "test");
		if (!msg)
			exit(EXIT_FAILURE);

		memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
		cpy_rtph = (struct rtp_hdr *) msgb_put(msg, sizeof(rtp_pkt));

		seq = ntohs(rtph->sequence);
		seq++;
		rtph->sequence = htons(seq);
		if (i < 3) {
			/* Mark 1 rtp packet of each stream */
			cpy_rtph->marker = 1;
			mark_pkts++;
		} else {
		/* osmux is yet unable to detect RTP holes and recreate RTP
		 * packets at the start of the batch. It will hence simply add an M
		 * bit to the osmux header in that situation: */
			if (k == 0 || k == 1)
				mark_pkts++;
		}

		osmo_rtp_snprintf(buf, sizeof(buf), msg);
		clock_debug("adding to ccid=%u %s\n", (i % 2) + ccid, buf);
		rtp_pkts++;

		k++;
		/* Fan out RTP packets between two circuit IDs to test
		 * multi-batch support. Mind that this approach implicitly add
		 * gaps between two messages to test the osmux replaying
		 * feature.
		 */
		osmux_xfrm_input(h_input, msg, (i % 2) + ccid);

		if (i % 4 == 0) {
			/* After four RTP messages, squash them into the OSMUX
			 * batch and call the routine to deliver it.
			 */
			osmux_xfrm_input_deliver(h_input);

			/* The first two RTP message (one per circuit ID batch)
			 * are delivered immediately, wait until the three RTP
			 * messages that are extracted from OSMUX has been
			 * delivered.
			 */
			for (j = 0; j < k-2; j++) {
				osmo_select_main(0);
				clock_override_add(0, PKT_TIME_USEC);
			}

			k = 0;
		}
	}

	if (mark_pkts) {
		clock_debug("osmux_test_loop: RTP M bit (marker) mismatch! %d\n", mark_pkts);
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	int i;

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	/* This test uses fake time to speedup the run, unless we want to manually
	 * test time specific stuff */
	clock_override_enable(true);

	/* This test doesn't use it, but osmux requires it internally. */
	void *tall_ctx = talloc_named_const(NULL, 1, "Root context");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &osmux_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);

	for (i = 0; i < ARRAY_SIZE(h_output); i++) {
		h_output[i] = osmux_xfrm_output_alloc(NULL);
		osmux_xfrm_output_set_rtp_ssrc(h_output[i], 0x7000000 + i);
		osmux_xfrm_output_set_rtp_pl_type(h_output[i], 98);
		osmux_xfrm_output_set_tx_cb(h_output[i], tx_cb, NULL);
		/* These fields are set using random() */
		h_output[i]->rtp_seq = 9158;
		h_output[i]->rtp_timestamp = 1681692777;
	}

	/* If the test takes longer than 10 seconds, abort it */
	alarm(10);

	/* Check if marker bit features work correctly */
	h_input = osmux_xfrm_input_alloc(tall_ctx);
	osmux_xfrm_input_set_initial_seqnum(h_input, 0);
	osmux_xfrm_input_set_batch_factor(h_input, 4);
	osmux_xfrm_input_set_deliver_cb(h_input, osmux_deliver, NULL);

	for (i = 0; i < 4; i++)
		osmux_xfrm_input_open_circuit(h_input, i, 0);
	osmux_test_marker(4);
	for (i = 0; i < 4; i++)
		osmux_xfrm_input_close_circuit(h_input, i);
	TALLOC_FREE(h_input);

	h_input = osmux_xfrm_input_alloc(tall_ctx);
	osmux_xfrm_input_set_initial_seqnum(h_input, 0);
	osmux_xfrm_input_set_batch_factor(h_input, 4);
	osmux_xfrm_input_set_deliver_cb(h_input, osmux_deliver, NULL);

	for (i = 0; i < 2; i++)
		osmux_xfrm_input_open_circuit(h_input, i, 0);

	/* Add two circuits with dummy padding */
	osmux_xfrm_input_open_circuit(h_input, 2, 1);
	osmux_xfrm_input_open_circuit(h_input, 3, 1);

	/* Wait 10 times to make sure dummy padding timer works fine */
	for (i = 0; i < 10; i++)
		osmo_select_main(0);

	/* Start pushing voice data to circuits 0 and 1 */
	osmux_test_loop(0);
	/* ... now start pushing voice data to circuits 2 and 3. This circuits
	 * comes with dummy padding enabled.
	 */
	osmux_test_loop(2);

	for (i = 0; i < 4; i++)
		osmux_xfrm_input_close_circuit(h_input, i);

	/* Reopen with two circuits and retest */
	osmux_xfrm_input_open_circuit(h_input, 0, 0);
	osmux_xfrm_input_open_circuit(h_input, 1, 1);
	osmux_test_loop(0);
	osmux_xfrm_input_close_circuit(h_input, 0);
	osmux_xfrm_input_close_circuit(h_input, 1);

	TALLOC_FREE(h_input);

	for (i = 0; i < ARRAY_SIZE(h_output); i++) {
		clock_debug("Flushing CID %u\n", i);
		osmux_xfrm_output_flush(h_output[i]);
	}

	for (i = 0; i < ARRAY_SIZE(h_output); i++) {
		TALLOC_FREE(h_output[i]);
	}

	clock_debug("OK: Test passed\n");
	return EXIT_SUCCESS;
}
