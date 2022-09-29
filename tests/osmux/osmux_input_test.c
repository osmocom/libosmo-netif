/* (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

static uint16_t rtp_next_seq;
static uint16_t rtp_next_ts;

void *tall_ctx;

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

static void rtp_init(uint16_t seq, uint16_t ts)
{
	rtp_next_seq = seq;
	rtp_next_ts = ts;
}

static struct msgb *rtp_new(uint16_t seq, uint8_t timestamp, uint8_t marker)
{
	struct msgb *msg;
	struct rtp_hdr *rtph;

	msg = msgb_alloc(1500, "rtp");
	if (!msg)
		exit(EXIT_FAILURE);
	msgb_put(msg, sizeof(struct rtp_hdr));

	rtph = (struct rtp_hdr *)msg->data;
	rtph->version = RTP_VERSION;
	rtph->marker = marker;
	rtph->sequence = htons(seq);
	rtph->timestamp = htons(timestamp);
	rtph->ssrc = 0x6789;
	return msg;
}

static struct msgb *rtp_next(void)
{
	rtp_next_seq++;
	rtp_next_ts += TIME_RTP_PKT_MS;
	return rtp_new(rtp_next_seq, rtp_next_ts, 0);
}

static struct amr_hdr *rtp_append_amr(struct msgb *msg, uint8_t ft)
{
	struct amr_hdr *amrh;
	struct rtp_hdr *rtph = (struct rtp_hdr *)msg->data;

	msgb_put(msg, sizeof(struct amr_hdr));
	amrh = (struct amr_hdr *)rtph->data;

	amrh->cmr = 0;
	amrh->q = 1;
	amrh->f = 0;
	amrh->ft = ft;
	msgb_put(msg, osmo_amr_bytes(amrh->ft));
	return amrh;
}

static void sigalarm_handler(int foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

#define clock_debug(fmt, args...) \
	do { \
		struct timespec ts; \
		struct timeval tv; \
		osmo_clock_gettime(CLOCK_MONOTONIC, &ts); \
		osmo_gettimeofday(&tv, NULL); \
		fprintf(stdout, "sys={%lu.%06lu}, mono={%lu.%06lu}: " fmt "\n", \
			tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec/1000, ##args); \
	} while (0)

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

static void test_amr_ft_change_middle_batch_osmux_deliver_cb(struct msgb *batch_msg, void *data)
{
	struct osmux_hdr *osmuxh;
	char buf[2048];
	int n = 0;
	bool *osmux_transmitted = (bool *)data;

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	clock_debug("OSMUX message (len=%d): %s\n", batch_msg->len, buf);

	/* We expect 3 batches: */
	while ((osmuxh = osmux_xfrm_output_pull(batch_msg))) {
		n++;
		OSMO_ASSERT(osmuxh->ft == OSMUX_FT_VOICE_AMR);
		OSMO_ASSERT(osmuxh->rtp_m == 0);
		OSMO_ASSERT(osmuxh->amr_cmr == 0);
		OSMO_ASSERT(osmuxh->amr_q == 1);
		switch (n) {
		case 1:
			OSMO_ASSERT(osmuxh->seq == 0);
			OSMO_ASSERT(osmuxh->ctr == 1);
			OSMO_ASSERT(osmuxh->amr_ft == AMR_FT_2);
			break;
		case 2:
			OSMO_ASSERT(osmuxh->seq == 1);
			OSMO_ASSERT(osmuxh->ctr == 0);
			OSMO_ASSERT(osmuxh->amr_ft == AMR_FT_6);
			break;
		case 3:
			OSMO_ASSERT(osmuxh->seq == 2);
			OSMO_ASSERT(osmuxh->ctr == 0);
			OSMO_ASSERT(osmuxh->amr_ft == AMR_FT_1);
			break;
		}
	}
	OSMO_ASSERT(n == 3);

	msgb_free(batch_msg);

	*osmux_transmitted = true;
}
/* Test if an RTP pkt with changed AMR FT passed to osmux_input is properly
 * processed: The current batch ends and a new batch with a new osmux header is
 * appeneded to the generated packet. */
static void test_amr_ft_change_middle_batch(void)
{
	struct msgb *msg;
	int rc;
	const uint8_t cid = 30;
	bool osmux_transmitted = false;
	struct osmux_in_handle *h_input;

	printf("===%s===\n", __func__);


	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(0, 0);

	h_input = osmux_xfrm_input_alloc(tall_ctx);
	osmux_xfrm_input_set_initial_seqnum(h_input, 0);
	osmux_xfrm_input_set_batch_factor(h_input, 4);
	osmux_xfrm_input_set_deliver_cb(h_input,
					test_amr_ft_change_middle_batch_osmux_deliver_cb,
					&osmux_transmitted);
	osmux_xfrm_input_open_circuit(h_input, cid, false);

	/* First RTP frame at t=0 */
	msg = rtp_next();
	rtp_append_amr(msg, AMR_FT_2);
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* Second RTP frame at t=20 */
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	msg = rtp_next();
	rtp_append_amr(msg, AMR_FT_2);
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* Third RTP frame at t=40, AMR FT changes: */
	clock_debug("Submit RTP with 1st AMR FT change");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	msg = rtp_next();
	rtp_append_amr(msg, AMR_FT_6);
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* Forth RTP frame at t=60, AMR FT changes again: */
	clock_debug("Submit RTP with 2nd AMR FT change");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	msg = rtp_next();
	rtp_append_amr(msg, AMR_FT_1);
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* t=80, osmux batch is scheduled to be transmitted: */
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("Osmux frame should now be transmitted");
	osmo_select_main(0);
	OSMO_ASSERT(osmux_transmitted == true);

	clock_debug("Closing circuit");
	osmux_xfrm_input_close_circuit(h_input, cid);
	talloc_free(h_input);
}

static void test_last_amr_cmr_f_q_used_osmux_deliver_cb(struct msgb *batch_msg, void *data)
{
	struct osmux_hdr *osmuxh;
	char buf[2048];
	bool *osmux_transmitted = (bool *)data;

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	clock_debug("OSMUX message (len=%d): %s\n", batch_msg->len, buf);

	/* We expect 1 batch: */
	osmuxh = osmux_xfrm_output_pull(batch_msg);
	OSMO_ASSERT(osmuxh->ft == OSMUX_FT_VOICE_AMR);
	/* Check CMR and Q values are the ones from the last message: */
	OSMO_ASSERT(osmuxh->amr_f == 0);
	OSMO_ASSERT(osmuxh->amr_q == 0);
	OSMO_ASSERT(osmuxh->amr_cmr == 2);

	osmuxh = osmux_xfrm_output_pull(batch_msg);
	OSMO_ASSERT(osmuxh == NULL);

	msgb_free(batch_msg);

	*osmux_transmitted = true;
}
/* Test that fields CMR, F and Q of the last RTP packet in the batch are the
 * ones set in the osmux batch header. */
static void test_last_amr_cmr_f_q_used(void)
{
	struct msgb *msg;
	int rc;
	const uint8_t cid = 32;
	bool osmux_transmitted = false;
	struct amr_hdr *amrh;
	struct osmux_in_handle *h_input;

	printf("===%s===\n", __func__);



	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(0, 0);

	h_input = osmux_xfrm_input_alloc(tall_ctx);
	osmux_xfrm_input_set_initial_seqnum(h_input, 0);
	osmux_xfrm_input_set_batch_factor(h_input, 3);
	osmux_xfrm_input_set_deliver_cb(h_input,
					test_last_amr_cmr_f_q_used_osmux_deliver_cb,
					&osmux_transmitted);
	osmux_xfrm_input_open_circuit(h_input, cid, false);

	/* First RTP frame at t=0 */
	msg = rtp_next();
	amrh = rtp_append_amr(msg, AMR_FT_2);
	amrh->f = 1;
	amrh->q = 1;
	amrh->cmr = 0;
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* Second RTP frame at t=20, CMR changes 0->1 */
	clock_debug("Submit 2nd RTP packet, CMR changes");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	msg = rtp_next();
	amrh = rtp_append_amr(msg, AMR_FT_2);
	amrh->f = 1;
	amrh->q = 1;
	amrh->cmr = 1;
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* Third RTP frame at t=40, q changes 1->0, CMR changes 1->2: */
	clock_debug("Submit 3rd RTP packet with Q and CMR changes");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	msg = rtp_next();
	amrh = rtp_append_amr(msg, AMR_FT_2);
	amrh->f = 0;
	amrh->q = 0;
	amrh->cmr = 2;
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* t=60, osmux batch is scheduled to be transmitted: */
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("Osmux frame should now be transmitted");
	osmo_select_main(0);
	OSMO_ASSERT(osmux_transmitted == true);

	clock_debug("Closing circuit");
	osmux_xfrm_input_close_circuit(h_input, cid);
	talloc_free(h_input);
}

static void test_initial_osmux_seqnum_osmux_deliver_cb(struct msgb *batch_msg, void *data)
{
	struct osmux_hdr *osmuxh;
	char buf[2048];
	bool *osmux_transmitted = (bool *)data;

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	clock_debug("OSMUX message (len=%d): %s\n", batch_msg->len, buf);

	/* We expect 1 batch: */
	osmuxh = osmux_xfrm_output_pull(batch_msg);
	/* Check seqnum is the one configured beforehand: */
	OSMO_ASSERT(osmuxh->seq == 123);

	osmuxh = osmux_xfrm_output_pull(batch_msg);
	OSMO_ASSERT(osmuxh == NULL);

	msgb_free(batch_msg);

	*osmux_transmitted = true;
}
/* Test that the first transmitted osmux header is set according to what has been configured. */
static void test_initial_osmux_seqnum(void)
{
	struct msgb *msg;
	int rc;
	const uint8_t cid = 33;
	bool osmux_transmitted = false;
	struct amr_hdr *amrh;
	struct osmux_in_handle *h_input;

	printf("===%s===\n", __func__);



	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(0, 0);

	h_input = osmux_xfrm_input_alloc(tall_ctx);
	osmux_xfrm_input_set_initial_seqnum(h_input, 123);
	osmux_xfrm_input_set_batch_factor(h_input, 1);
	osmux_xfrm_input_set_deliver_cb(h_input,
					test_initial_osmux_seqnum_osmux_deliver_cb,
					&osmux_transmitted);
	osmux_xfrm_input_open_circuit(h_input, cid, false);

	/* First RTP frame at t=0 */
	msg = rtp_next();
	amrh = rtp_append_amr(msg, AMR_FT_2);
	amrh->f = 1;
	amrh->q = 1;
	amrh->cmr = 0;
	rc = osmux_xfrm_input(h_input, msg, cid);
	OSMO_ASSERT(rc == 0);

	/* t=20, osmux batch is scheduled to be transmitted:  */
	clock_debug("Submit 2nd RTP packet, CMR changes");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	osmo_select_main(0);
	OSMO_ASSERT(osmux_transmitted == true);

	clock_debug("Closing circuit");
	osmux_xfrm_input_close_circuit(h_input, cid);
	talloc_free(h_input);
}

int main(int argc, char **argv)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	tall_ctx = talloc_named_const(NULL, 1, "Root context");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_category_filter(osmo_stderr_target, DLMUX, 1, LOGL_DEBUG);

	alarm(10);

	test_amr_ft_change_middle_batch();
	test_last_amr_cmr_f_q_used();
	test_initial_osmux_seqnum();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
