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

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/jibuf.h>
#include <osmocom/netif/rtp.h>

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

/* RTP packet with AMR payload */
static uint8_t rtp_pkt[] = {
	0x80, 0x62, 0x3f, 0xcc, 0x00, 0x01, 0xa7, 0x6f, /* RTP */
	0x07, 0x09, 0x00, 0x62, 0x20, 0x14, 0xff, 0xd4, /* AMR */
	0xf9, 0xff, 0xfb, 0xe7, 0xeb, 0xf9, 0x9f, 0xf8,
	0xf2, 0x26, 0x33, 0x65, 0x54,
};

static void sigalarm_handler(int foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

#define SAMPLES_PER_PKT	160
#define RTP_FREQ_MS 20
#define RTP_PKTS_PER_SEC (1000/RTP_FREQ_MS)
#define NET_DELAY_MS 	300
#define GENERATED_JITTER_MS 160
#define NUM_PACKETS_TO_SEND 1000

#define TRACE_PACKE_DEBUG 0
#define TRACE_PACKET_GNUPLOT 1
#define TRACE_PACKET_TEST_JITTER 0

struct checkpoint {
	struct timeval ts;
	int transit;
	double jitter;
};

struct rtp_pkt_info {
	struct osmo_timer_list timer;
	struct timeval tx_prev_time;
	struct timeval tx_time;
	uint32_t tx_delay;
	struct checkpoint prequeue;
	struct checkpoint postqueue;
};

struct rtp_pkt_info_cb {
	struct rtp_pkt_info *data;
};

struct osmo_jibuf *jb;
uint16_t rtp_first_seq;
uint16_t rtp_next_seq;
uint32_t rtp_next_ts;
uint32_t packets_sent;
uint32_t packets_received;
uint32_t packets_dropped;
uint32_t packets_too_much_jitter;

struct rtp_pkt_info *msgb_get_pinfo(struct msgb* msg)
{
	struct rtp_pkt_info_cb *cb = (struct rtp_pkt_info_cb *)&((msg)->cb[0]);
	return cb->data;
}

static uint32_t timeval2ms(const struct timeval *ts)
{
	return ts->tv_sec * 1000 + ts->tv_usec / 1000;
}

int calc_relative_transmit_time(struct timeval *tx_0, struct timeval *tx_f,
				struct timeval *rx_0, struct timeval *rx_f)
{
	struct timeval txdiff, rxdiff, diff;
	timersub(rx_f, rx_0, &rxdiff);
	timersub(tx_f, tx_0, &txdiff);
	timersub(&rxdiff, &txdiff, &diff);
	return timeval2ms(&diff);
}

void trace_pkt(struct msgb *msg, char* info) {
	struct timeval now, total_delay;
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	gettimeofday(&now, NULL);
	timersub(&now, &pinfo->tx_time, &total_delay);

#if TRACE_PACKET_DEBUG
	uint32_t total_delay_ms = timeval2ms(&total_delay);
	LOGP(DLJIBUF, LOGL_DEBUG, "%s: seq=%"PRIu16" ts=%"PRIu32" (%ld.%06ld) tx_delay=%"PRIu32 \
		" end_delay=%"PRIu32" pre_trans=%d pre_jitter=%f post_trans=%d post_jitter=%f\n",
		info, ntohs(rtph->sequence), ntohl(rtph->timestamp),
		pinfo->tx_time.tv_sec, pinfo->tx_time.tv_usec,
		pinfo->tx_delay, total_delay_ms,
		pinfo->prequeue.transit, pinfo->prequeue.jitter,
		pinfo->postqueue.transit, pinfo->postqueue.jitter);
#endif

#if TRACE_PACKET_GNUPLOT
	/* Used as input for gplot: "gnuplot -p jitter.plt -"" */
	uint32_t tx_time_ms = timeval2ms(&pinfo->tx_time);
	uint32_t prequeue_time_ms = timeval2ms(&pinfo->prequeue.ts);
	uint32_t postqueue_time_ms = timeval2ms(&pinfo->postqueue.ts);
	fprintf(stderr, "%"PRIu16"\t%"PRIu32"\t%"PRIu32"\t%"PRIu32"\t%d\t%d\t%f\t%f\t%"PRIu32"\t%"PRIu32"\n",
		ntohs(rtph->sequence), tx_time_ms,
		prequeue_time_ms, postqueue_time_ms,
		pinfo->prequeue.transit, pinfo->postqueue.transit,
		pinfo->prequeue.jitter, pinfo->postqueue.jitter,
		packets_dropped, jb->threshold_delay);
#endif
}

void pkt_add_result(struct msgb *msg, bool dropped)
{
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	if (dropped) {
		packets_dropped++;
		trace_pkt(msg,"dropped");
	} else {
		packets_received++;
		trace_pkt(msg,"received");

		if (pinfo->prequeue.jitter < pinfo->postqueue.jitter) {
			packets_too_much_jitter++;
#if TRACE_PACKET_TEST_JITTER
			LOGP(DLJIBUF, LOGL_ERROR, "JITTER HIGHER THAN REF: %s seq=%"PRIu16" ts=%"PRIu32 \
				" (%ld.%06ld) tx_delay=%"PRIu32" end_delay=%"PRIu32 \
				" pre_trans=%d pre_jitter=%f post_trans=%d post_jitter=%f dropped=%"PRIu32 \
				" buffer=%"PRIu32"\n",
				info, ntohs(rtph->sequence), ntohl(rtph->timestamp),
				pinfo->tx_time.tv_sec, pinfo->tx_time.tv_usec,
				pinfo->tx_delay, total_delay_ms,
				pinfo->prequeue.transit, pinfo->prequeue.jitter,
				pinfo->postqueue.transit, pinfo->postqueue.jitter,
				packets_dropped, jb->threshold_delay);
#endif
		}
	}
}

void dequeue_cb(struct msgb *msg, void *data)
{
	static struct checkpoint postqueue_prev;
	static bool postqueue_started = false;

	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	gettimeofday(&pinfo->postqueue.ts, NULL);

	if (postqueue_started) {
		pinfo->postqueue.transit = calc_relative_transmit_time(
					&pinfo->tx_prev_time, &pinfo->tx_time,
					&postqueue_prev.ts, &pinfo->postqueue.ts);

		uint32_t abs_transit = pinfo->postqueue.transit *
					( pinfo->postqueue.transit >= 0 ? 1 : -1 );

		pinfo->postqueue.jitter = postqueue_prev.jitter +
				((double)abs_transit - postqueue_prev.jitter)/16.0;
	} else {
		postqueue_started = true;
		pinfo->postqueue.transit = 0;
		pinfo->postqueue.jitter = 0;
	}

	postqueue_prev = pinfo->postqueue;

	pkt_add_result(msg, false);

	osmo_timer_del(&pinfo->timer);
	msgb_free(msg);
}

void pkt_arrived_cb(void *data)
{
	static struct checkpoint prequeue_prev;
	static bool prequeue_started = false;

	struct msgb *msg = (struct msgb*) data;
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	gettimeofday(&pinfo->prequeue.ts, NULL);

	if (prequeue_started) {
		pinfo->prequeue.transit = calc_relative_transmit_time(
					&pinfo->tx_prev_time, &pinfo->tx_time,
					&prequeue_prev.ts, &pinfo->prequeue.ts);

		uint32_t abs_transit = pinfo->prequeue.transit *
					( pinfo->prequeue.transit >= 0 ? 1 : -1 );

		pinfo->prequeue.jitter = prequeue_prev.jitter +
				((double)abs_transit - prequeue_prev.jitter)/16.0;
	} else {
		prequeue_started = true;
		pinfo->prequeue.transit = 0;
		pinfo->prequeue.jitter = 0;
	}

	prequeue_prev = pinfo->prequeue;

	int n = osmo_jibuf_enqueue(jb, msg);

	if (n<0) {
		pkt_add_result(msg, true);
		osmo_timer_del(&pinfo->timer);
		msgb_free(msg);
	}
}

void rand_send_rtp_packet()
{
	static struct timeval tx_prev_time;

	struct rtp_pkt_info *pinfo;
	struct rtp_hdr *rtph;
	struct msgb *msg;

	/* Set fake prev_time for 1st packet. Otherwise transit calculations for first
	 * packet can be really weird if they not arrive in order */
	if (rtp_next_seq == rtp_first_seq) {
		struct timeval now, time_rate = { .tv_sec = 0, .tv_usec = RTP_FREQ_MS * 1000};
		gettimeofday(&now, NULL);
		timersub(&now, &time_rate, &tx_prev_time);
	}


	msg = msgb_alloc(1500, "test");
	if (!msg)
		exit(EXIT_FAILURE);

	memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
	msgb_put(msg, sizeof(rtp_pkt));

	rtph = osmo_rtp_get_hdr(msg);

	rtph->sequence = htons(rtp_next_seq);
	rtp_next_seq++;

	rtph->timestamp = htonl(rtp_next_ts);
	rtp_next_ts += SAMPLES_PER_PKT;

	pinfo = talloc_zero(msg, struct rtp_pkt_info);
	struct rtp_pkt_info_cb *cb = (struct rtp_pkt_info_cb *)&((msg)->cb[0]);
	cb->data = pinfo;

	gettimeofday(&pinfo->tx_time, NULL);
	pinfo->tx_prev_time = tx_prev_time;
	memset(&pinfo->timer, 0, sizeof(struct osmo_timer_list));
	pinfo->timer.cb = pkt_arrived_cb;
	pinfo->timer.data = msg;
	pinfo->tx_delay = NET_DELAY_MS + (random() % (GENERATED_JITTER_MS));

	tx_prev_time = pinfo->tx_time;

	/* TODO: add a random() to lose/drop packets */

	osmo_timer_schedule(&pinfo->timer, 0, pinfo->tx_delay * 1000);
}

void generate_pkt_cb(void *data)
{
	static struct osmo_timer_list enqueue_timer = {.cb = generate_pkt_cb, .data = NULL};
	static struct timeval last_generated;

	struct timeval time_rate = { .tv_sec = 0, .tv_usec = RTP_FREQ_MS * 1000};
	struct timeval sched_ts;

	if (!packets_sent)
		gettimeofday(&last_generated, NULL);

	rand_send_rtp_packet();
	packets_sent++;

	timeradd(&last_generated, &time_rate, &sched_ts);
	last_generated = sched_ts;
	if (packets_sent < NUM_PACKETS_TO_SEND) {
		enqueue_timer.timeout = sched_ts;
		osmo_timer_add(&enqueue_timer);
	}
}

void check_results()
{
	uint32_t drop_threshold = NUM_PACKETS_TO_SEND * 5 / 100;
	if (packets_dropped > drop_threshold) {
		fprintf(stdout, "Too many dropped packets (%"PRIu32" > %"PRIu32")\n",
				packets_dropped, drop_threshold);
		exit(1);
	}

	uint32_t jitter_high_threshold = NUM_PACKETS_TO_SEND * 8 / 100;
	if (packets_too_much_jitter > jitter_high_threshold) {
		fprintf(stdout, "Too many packets with higher jitter (%"PRIu32" > %"PRIu32")\n",
				packets_too_much_jitter, jitter_high_threshold);
		exit(1);
	}
}

int main(void)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	/* This test doesn't use it, but jibuf requires it internally. */
	osmo_init_logging(&jibuf_test_log_info);
	log_set_category_filter(osmo_stderr_target, DLMIB, 1, LOGL_ERROR);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	srandom(time(NULL));
	rtp_first_seq = (uint16_t) random();
	rtp_next_seq = rtp_first_seq;
	rtp_next_ts = (uint32_t) random();
	jb = osmo_jibuf_alloc(NULL);

	osmo_jibuf_set_min_delay(jb, GENERATED_JITTER_MS - RTP_FREQ_MS);
	osmo_jibuf_set_max_delay(jb, GENERATED_JITTER_MS + RTP_FREQ_MS*2);

	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);

	generate_pkt_cb(NULL);

	/* If the test takes longer than twice the time needed to generate the packets
	 plus 10 seconds, abort it */
	alarm(NUM_PACKETS_TO_SEND*20/1000 +10);

	while((packets_received + packets_dropped) < NUM_PACKETS_TO_SEND)
		osmo_select_main(0);

	osmo_jibuf_delete(jb);

	check_results();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
