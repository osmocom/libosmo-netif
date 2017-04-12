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
#include <osmocom/netif/jibuf.h>
#include <osmocom/netif/rtp.h>

static struct osmo_jibuf *jb;

static uint16_t rtp_next_seq;
static uint32_t rtp_next_ts;

#define SAMPLES_PER_PKT	160
#define TIME_RTP_PKT_MS 20
/* RTP packet with AMR payload */
static uint8_t rtp_pkt[] = {
	0x80, 0x62, 0x3f, 0xcc, 0x00, 0x01, 0xa7, 0x6f, /* RTP */
	0x07, 0x09, 0x00, 0x62, 0x20, 0x14, 0xff, 0xd4, /* AMR */
	0xf9, 0xff, 0xfb, 0xe7, 0xeb, 0xf9, 0x9f, 0xf8,
	0xf2, 0x26, 0x33, 0x65, 0x54,
};

/* ----------------------------- */

/* Logging related stuff */
#define INT2IDX(x)   (-1*(x)-1)
struct log_info_cat jibuf_test_cat[] = {
	[INT2IDX(DLJIBUF)] = {
		.name = "DLJIBUF",
		.description = "Osmocom Jitter Buffer",
		.enabled = 1, .loglevel = LOGL_DEBUG,
		},
};
const struct log_info jibuf_test_log_info = {
	.filter_fn = NULL,
	.cat = jibuf_test_cat,
	.num_cat = ARRAY_SIZE(jibuf_test_cat),
};
/* ----------------------------- */

static void rtp_init(uint16_t seq, uint32_t timestamp)
{
	rtp_next_seq = seq;
	rtp_next_ts = timestamp;
}

static struct msgb *rtp_new(uint16_t seq, uint32_t timestamp)
{
	struct msgb *msg;
	struct rtp_hdr *rtph;

	msg = msgb_alloc(1500, "test");
	if (!msg)
		exit(EXIT_FAILURE);
	memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
	msgb_put(msg, sizeof(rtp_pkt));

	rtph = osmo_rtp_get_hdr(msg);
	rtph->sequence = htons(rtp_next_seq);
	rtph->timestamp = htonl(rtp_next_ts);
	return msg;
}

static struct msgb *rtp_next(void)
{
	rtp_next_seq++;
	rtp_next_ts += SAMPLES_PER_PKT;
	return rtp_new(rtp_next_seq, rtp_next_ts);
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

static void clock_override_add(long sec, long usec)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec*1000);
	clock_debug("clock_override_add");
}


static void dequeue_cb(struct msgb *msg, void *data)
{
	struct rtp_hdr *rtph;
	bool check_latest;
	char buf[250];
	rtph = osmo_rtp_get_hdr(msg);
	check_latest = rtph->sequence == htons(rtp_next_seq) && rtph->timestamp == htonl(rtp_next_ts);
	snprintf(buf, sizeof(buf), "dequeue: seq=%"PRIu16" ts=%"PRIu32" %s",
		ntohs(rtph->sequence), ntohl(rtph->timestamp), check_latest ? "LATEST" : "INTERMEDIATE");
	clock_debug(buf);
	msgb_free(msg);
}

#define ENQUEUE_NEXT(jb) { \
		struct msgb *_msg; \
		int _rc; \
		_msg = rtp_next(); \
		_rc = osmo_jibuf_enqueue(jb, _msg); \
		OSMO_ASSERT(!_rc); \
		}

static void test_normal(void)
{
	int min_delay = 60;

	printf("===test_normal===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	/* First rtp at t=0, should be scheduled in min_delay time */
	ENQUEUE_NEXT(jb);
	clock_override_add(0, min_delay*1000);
	clock_debug("first select, first dequed");
	osmo_select_main(0);

	 /* We are at t=60, if we add a new packet and wait for 20msecs (next packet), we should show it dequeued*/
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("second select, one packet should be dequeued");
	osmo_select_main(0);

	/* We are at t=80, and only 2 packets were introduced. Let's add 2 more, should be dequeued by 80+40: */
	ENQUEUE_NEXT(jb);
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*2*1000);
	clock_debug("third select, two more dequed");
	osmo_select_main(0);

	/* t=120, 4 enqueued, 4 dequeued.*/
	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_delete_nonempty(void)
{
	int min_delay = 100;

	printf("===test_delete_nonempty===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	ENQUEUE_NEXT(jb);

	/* No need to update the time, all msgs should be dequeued at this time */
	OSMO_ASSERT(!osmo_jibuf_empty(jb));
	osmo_jibuf_delete(jb);
}

static void test_packet_lost(void)
{
	int min_delay = 60;

	printf("===test_packet_lost===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	/* First rtp at t=0, should be scheduled in min_delay time */
	clock_debug("enqueue 1st packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);

	clock_debug("packet lost: 2nd");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("packet lost: 3rd");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("packet lost: 4th");
	clock_override_add(0, TIME_RTP_PKT_MS*1000);

	/* We are at t=80 */
	clock_debug("enqueue 5th packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, min_delay*1000);

	/* We are at t=140, all out in order */
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}


static void test_packet_drop(void)
{
	int min_delay = 60;
	struct msgb *msg;

	printf("===test_packet_drop===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	/* First rtp at t=0, should be scheduled in min_delay time */
	clock_debug("enqueue 1st packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 2nd packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 3rd packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 4th packet");
	ENQUEUE_NEXT(jb);

	/* We are at t=60, first comes out */
	osmo_select_main(0);

	/* We move to t=160, next packet in stream is too late:*/
	clock_override_add(0, 100*1000);
	clock_debug("next packet should be dropped, too late");
	msg = rtp_next();
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg) < 0);
	msgb_free(msg);

	/* However, if we try to add a later one, it should work: */
	clock_debug("next packet should be enqueued");
	ENQUEUE_NEXT(jb);

	/* We are at t=160, all of them should be dequeued */
	osmo_select_main(0);

	/* t=160, 4 enqueued, 4 dequeued.*/
	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_packet_out_of_order(void)
{
	int min_delay = 60;
	struct msgb *msg2, *msg3;

	printf("===test_packet_out_of_order===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	/* First rtp at t=0, should be scheduled in min_delay time */
	clock_debug("enqueue 1st packet");
	ENQUEUE_NEXT(jb);

	/* 3rd packet arrives instead of 2nd one */
	msg2 = rtp_next();
	msg3 = rtp_next();
	clock_override_add(0, TIME_RTP_PKT_MS*2*1000);
	clock_debug("enqueue 3rd packet");
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg3) == 0);
	clock_debug("enqueue 2nd packet");
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg2) == 0);

	/* We are at t=100, all out in order */
	clock_override_add(0, min_delay*1000);
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_start_2nd_packet(void)
{
	int min_delay = 60;
	struct msgb *msg1;

	printf("===test_start_2nd_packet===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	/* First rtp at t=0, should be scheduled in min_delay time */
	clock_debug("1st packet is not yet enqueued");
	msg1 = rtp_next();
	clock_override_add(0, TIME_RTP_PKT_MS*2*1000);

	/* 2nd packet arrives instead of 2nd one */
	clock_debug("2nd packet is enqueuded as first");
	ENQUEUE_NEXT(jb);

	clock_debug("1st packet is enqueuded as second, should be enqueued with preference");
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg1) == 0);

	/* 1st packet is dequeued */
	clock_override_add(0, (min_delay-TIME_RTP_PKT_MS)*1000);
	osmo_select_main(0);

	/* 2nst packet is dequeued */
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_buffer_threshold_change(void)
{
	int min_delay = 60;
	struct msgb *msg;
	uint32_t threshold_delay;
	int i;

	printf("===test_buffer_threshold_change===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 400);
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	OSMO_ASSERT(min_delay == jb->threshold_delay);
	threshold_delay = jb->threshold_delay;

	/* First rtp at t=0, should be scheduled in min_delay time */
	clock_debug("enqueue 1st packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 2nd packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 3rd packet");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 4th packet");
	ENQUEUE_NEXT(jb);

	/* We are at t=60, first comes out */
	osmo_select_main(0);

	/* We move to t=160, next packet in stream is too late:*/
	clock_override_add(0, 100*1000);
	clock_debug("next packet should be dropped, too late");
	msg = rtp_next();
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg) < 0);
	msgb_free(msg);

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("next packet is dropped, but buffer is increased");
	msg = rtp_next();
	OSMO_ASSERT(osmo_jibuf_enqueue(jb, msg) < 0);
	msgb_free(msg);
	OSMO_ASSERT(jb->threshold_delay > threshold_delay);
	threshold_delay = jb->threshold_delay;

	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("next packet is enqueued since the buffer increased");
	ENQUEUE_NEXT(jb);

	/* As the last buffer was really late but still accepted, it is not delayed: */
	osmo_select_main(0);

	clock_debug("Enqueue late packets");
	for (i = 0; i<4; i++) {
		ENQUEUE_NEXT(jb);
	}

	clock_debug("Run perfectly for a while, buffer should decrease");
	for (i = 0; i<100; i++) {
		clock_override_add(0, TIME_RTP_PKT_MS*1000);
		ENQUEUE_NEXT(jb);
		osmo_select_main(0);
	}
	clock_debug("Done, checking threshold and cleaning");
	OSMO_ASSERT(jb->threshold_delay < threshold_delay);
	clock_override_add(0, jb->threshold_delay*1000);
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_seq_wraparound(void)
{
	int min_delay = 80;

	printf("===test_seq_wraparound===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(65533, 400); /* seq = 2^16 -3 */
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	clock_debug("enqueue 1st packet (seq=65534)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 2nd packet (seq=65535)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 3rd packet (seq=0, wraparound)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 4th packet (seq=1)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 5th packet (seq=2)");
	ENQUEUE_NEXT(jb);

	clock_debug("dequeue 1st packet (seq=65534)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 2nd packet (seq=65535)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 3rd packet (seq=0, wraparound)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 4th packet (seq=1)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 5th packet (seq=2)");
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

static void test_timestamp_wraparound(void)
{
	int min_delay = 80;
	unsigned int offset = 14;

	printf("===test_timestamp_wraparound===\n");

	clock_override_enable(true);
	clock_override_set(0, 0);
	rtp_init(32, 4294966816 + offset); /* timestamp = 2^32 - 3*SAMPLES_PER_PKT + offset */
	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, min_delay);
	osmo_jibuf_set_max_delay(jb, 200);

	clock_debug("enqueue 1st packet (ts=4294966990)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 2nd packet (ts=4294967150)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 3rd packet (ts=14, wraparound)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 4th packet (ts=174)");
	ENQUEUE_NEXT(jb);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("enqueue 5th packet (ts=334)");
	ENQUEUE_NEXT(jb);

	clock_debug("dequeue 1st packet (ts=4294966990)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 2nd packet (ts=4294967150)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 3rd packet (ts=14, wraparound)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 4th packet (ts=174)");
	osmo_select_main(0);
	clock_override_add(0, TIME_RTP_PKT_MS*1000);
	clock_debug("dequeue 5th packet (ts=334)");
	osmo_select_main(0);

	OSMO_ASSERT(osmo_jibuf_empty(jb));

	osmo_jibuf_delete(jb);
}

int main(int argc, char **argv)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	osmo_init_logging(&jibuf_test_log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_category_filter(osmo_stderr_target, DLJIBUF, 1, LOGL_DEBUG);

	alarm(10);

	test_normal();
	test_delete_nonempty();
	test_packet_lost();
	test_packet_drop();
	test_packet_out_of_order();
	test_start_2nd_packet();
	test_buffer_threshold_change();
	test_seq_wraparound();
	test_timestamp_wraparound();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}