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
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/jibuf.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include "osmo-pcap-test/osmo_pcap.h"


struct checkpoint {
	struct timeval ts;
	int transit;
	double jitter;
	uint32_t timestamp;
	uint16_t seq;
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

/* Option parameters to the program */
static bool opt_test_rand;
static bool opt_debug_human;
static bool opt_debug_table;
static bool opt_osmux;
static char* opt_pcap_file;
uint32_t opt_buffer_min = 60;
uint32_t opt_buffer_max = 500;
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

/* Used for test random: */
#define SAMPLES_PER_PKT	160
#define RTP_FREQ_MS 20
#define RTP_PKTS_PER_SEC (1000/RTP_FREQ_MS)
#define NET_DELAY_MS 	300
#define GENERATED_JITTER_MS 160
#define NUM_PACKETS_TO_SEND 1000

/* RTP packet with AMR payload */
static uint8_t rtp_pkt[] = {
	0x80, 0x62, 0x3f, 0xcc, 0x00, 0x01, 0xa7, 0x6f, /* RTP */
	0x07, 0x09, 0x00, 0x62, 0x20, 0x14, 0xff, 0xd4, /* AMR */
	0xf9, 0xff, 0xfb, 0xe7, 0xeb, 0xf9, 0x9f, 0xf8,
	0xf2, 0x26, 0x33, 0x65, 0x54,
};

static struct osmo_jibuf *jb;
static uint16_t rtp_first_seq;
static uint16_t rtp_next_seq;
static uint32_t rtp_next_ts;
static struct timeval tx_prev_time;
static uint32_t packets_sent;
static uint32_t packets_received;
static uint32_t packets_dropped;
static uint32_t packets_too_much_jitter;
/* ----------------------------- */

/* Used for test pcap: */
static struct osmo_pcap osmo_pcap;
static bool pcap_finished;
static struct osmux_out_handle pcap_osmux_h;
static struct llist_head osmux_list;
/* ----------------------------- */

static void sigalarm_handler(int foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

struct rtp_pkt_info *msgb_get_pinfo(struct msgb* msg)
{
	struct rtp_pkt_info_cb *cb = (struct rtp_pkt_info_cb *)&((msg)->cb[0]);
	return cb->data;
}

static uint32_t timeval2ms(const struct timeval *ts)
{
	return ts->tv_sec * 1000 + ts->tv_usec / 1000;
}

bool pkt_is_syncpoint(struct msgb* msg, uint16_t prev_seq, uint32_t prev_timestamp)
{
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);

	uint16_t current_seq = ntohs(rtph->sequence);
	uint32_t current_tx_ts = ntohl(rtph->timestamp);
	bool insync = (current_tx_ts - prev_timestamp) == (current_seq - prev_seq)*SAMPLES_PER_PKT;
	return !insync || rtph->marker;
}

int32_t calc_rel_transmit_time(uint32_t tx_0, uint32_t tx_f, uint32_t rx_0, uint32_t rx_f, bool tx_is_samples, bool pre)
{
	int32_t rxdiff, txdiff, res;
	rxdiff = (rx_f - rx_0);
	txdiff = (tx_f - tx_0);
	if(tx_is_samples)
		txdiff = txdiff * RTP_FREQ_MS/SAMPLES_PER_PKT;
	res = rxdiff - txdiff;
	//fprintf(stderr, "%s: (%u - %u) - (%u - %u) = %d - %d (%d) = %d\n", (pre ? "pre" : "post"), rx_f, rx_0, tx_f, tx_0, rxdiff, txdiff, (tx_f - tx_0), res);
	return res;
}

void trace_pkt(struct msgb *msg, char* info) {
	struct timeval now, total_delay;
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	gettimeofday(&now, NULL);
	timersub(&now, &pinfo->tx_time, &total_delay);

	if (opt_debug_human) {
	uint32_t total_delay_ms = timeval2ms(&total_delay);
	LOGP(DLJIBUF, LOGL_DEBUG, "%s: seq=%"PRIu16" ts=%"PRIu32" (%ld.%06ld) tx_delay=%"PRIu32 \
		" end_delay=%"PRIu32" pre_trans=%d pre_jitter=%f post_trans=%d post_jitter=%f\n",
		info, ntohs(rtph->sequence), ntohl(rtph->timestamp),
		pinfo->tx_time.tv_sec, pinfo->tx_time.tv_usec,
		pinfo->tx_delay, total_delay_ms,
		pinfo->prequeue.transit, pinfo->prequeue.jitter,
		pinfo->postqueue.transit, pinfo->postqueue.jitter);

	if (pinfo->prequeue.jitter < pinfo->postqueue.jitter)
	LOGP(DLJIBUF, LOGL_ERROR, "JITTER HIGHER THAN REF: seq=%"PRIu16" ts=%"PRIu32 \
		" (%ld.%06ld) tx_delay=%"PRIu32" end_delay=%"PRIu32 \
		" pre_trans=%d pre_jitter=%f post_trans=%d post_jitter=%f dropped=%"PRIu32 \
		" buffer=%"PRIu32"\n",
		ntohs(rtph->sequence), ntohl(rtph->timestamp),
		pinfo->tx_time.tv_sec, pinfo->tx_time.tv_usec,
		pinfo->tx_delay, total_delay_ms,
		pinfo->prequeue.transit, pinfo->prequeue.jitter,
		pinfo->postqueue.transit, pinfo->postqueue.jitter,
		packets_dropped, jb->threshold_delay);
	}

	if (opt_debug_table) {
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
	}
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

		if (pinfo->prequeue.jitter < pinfo->postqueue.jitter)
			packets_too_much_jitter++;
	}
}

void dequeue_cb(struct msgb *msg, void *data)
{
	static struct checkpoint postqueue_prev;
	static bool postqueue_started = false;

	bool tx_is_samples;
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);

	uint32_t tx1, tx0, rx0, rx1;

	gettimeofday(&pinfo->postqueue.ts, NULL);
	pinfo->postqueue.timestamp = htonl(rtph->timestamp);

	/* If pkt->marker -> init of talkspurt, there may be missing packets before,
	 * better to start calculating the jitter from here */
	if (postqueue_started && !pkt_is_syncpoint(msg, postqueue_prev.seq, postqueue_prev.timestamp)) {
		/* In random test mode we now the sender time, so we get real
		 * jitter results using it */
		if(opt_test_rand) {
			tx0 = timeval2ms(&pinfo->tx_prev_time);
			tx1 = timeval2ms(&pinfo->tx_time);
			tx_is_samples = false;
		} else {
			tx0 = postqueue_prev.timestamp;
			tx1 = pinfo->postqueue.timestamp;
			tx_is_samples = true;
		}
		rx0 = timeval2ms(&postqueue_prev.ts);
		rx1 = timeval2ms(&pinfo->postqueue.ts);
		pinfo->postqueue.transit = calc_rel_transmit_time(tx0, tx1, rx0, rx1, tx_is_samples, 0);

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
	postqueue_prev.seq = htons(rtph->sequence);

	pkt_add_result(msg, false);

	osmo_timer_del(&pinfo->timer);
	msgb_free(msg);
}

void pkt_arrived_cb(void *data)
{
	static struct checkpoint prequeue_prev;
	static bool prequeue_started = false;

	bool tx_is_samples;
	struct msgb *msg = (struct msgb*) data;
	struct rtp_hdr *rtph = osmo_rtp_get_hdr(msg);
	struct rtp_pkt_info *pinfo = msgb_get_pinfo(msg);


	uint32_t tx1, tx0, rx0, rx1;

	gettimeofday(&pinfo->prequeue.ts, NULL);
	pinfo->prequeue.timestamp = htonl(rtph->timestamp);

	/* If pkt->marker -> init of talkspurt, there may be missing packets before,
	 * better to start calculating the jitter from here */
	if (prequeue_started && !pkt_is_syncpoint(msg, prequeue_prev.seq, prequeue_prev.timestamp)) {
		/* In random test mode we now the sender time, so we get real
		 * jitter results using it */
		if(opt_test_rand) {
			tx0 = timeval2ms(&pinfo->tx_prev_time);
			tx1 = timeval2ms(&pinfo->tx_time);
			tx_is_samples = false;
		} else {
			tx0 = prequeue_prev.timestamp;
			tx1 = pinfo->prequeue.timestamp;
			tx_is_samples = true;
		}
		rx0 = timeval2ms(&prequeue_prev.ts);
		rx1 = timeval2ms(&pinfo->prequeue.ts);
		pinfo->prequeue.transit = calc_rel_transmit_time(tx0, tx1, rx0, rx1, tx_is_samples, 1);

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
	prequeue_prev.seq = htons(rtph->sequence);

	int n = osmo_jibuf_enqueue(jb, msg);

	if (n<0) {
		pkt_add_result(msg, true);
		osmo_timer_del(&pinfo->timer);
		msgb_free(msg);
	}
}

struct rtp_pkt_info * msgb_allocate_pinfo(struct msgb *msg)
{
	struct rtp_pkt_info_cb *cb = (struct rtp_pkt_info_cb *)&((msg)->cb[0]);
	cb->data = (struct rtp_pkt_info *) talloc_zero(msg, struct rtp_pkt_info);
	return cb->data;
}

void rand_send_rtp_packet()
{

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

	pinfo = msgb_allocate_pinfo(msg);

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

void rand_generate_pkt_cb(void *data)
{
	static struct osmo_timer_list enqueue_timer = {.cb = rand_generate_pkt_cb, .data = NULL};
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


static int pcap_generate_pkt_cb(struct msgb *msg)
{
	struct rtp_pkt_info *pinfo;
	/* Set fake prev_time for 1st packet. Otherwise transit calculations for first
	 * packet can be really weird if they not arrive in order */
	if (!packets_sent) {
		struct timeval now, time_rate = { .tv_sec = 0, .tv_usec = RTP_FREQ_MS * 1000};
		gettimeofday(&now, NULL);
		timersub(&now, &time_rate, &tx_prev_time);
	}

	pinfo = msgb_allocate_pinfo(msg);
	gettimeofday(&pinfo->tx_time, NULL);
	pinfo->tx_prev_time = tx_prev_time;

	tx_prev_time = pinfo->tx_time;
	packets_sent++;
	pkt_arrived_cb(msg);
	return 0;
}

void glue_cb(struct msgb *msg, void *data)
{
	pcap_generate_pkt_cb(msg);
}

int pcap_read_osmux(struct msgb *msg)
{
	struct osmux_hdr *osmuxh;

	/* This code below belongs to the osmux receiver */
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		osmux_xfrm_output(osmuxh, &pcap_osmux_h, &osmux_list);
		osmux_tx_sched(&osmux_list, glue_cb, NULL);
	}
	msgb_free(msg);
	return 0;
}

void pcap_pkt_timer_cb(void *data)
{
	int (*mycb)(struct msgb *msgb);
	if(opt_osmux)
		mycb = pcap_read_osmux;
	else
		mycb = pcap_generate_pkt_cb;

	if (osmo_pcap_test_run(&osmo_pcap, IPPROTO_UDP, mycb) < 0) {
		osmo_pcap_stats_printf();
		osmo_pcap_test_close(osmo_pcap.h);
		pcap_finished=true;
	}
}

void rand_test_check()
{
	uint32_t drop_threshold = NUM_PACKETS_TO_SEND * 5 / 100;
	if (packets_dropped > drop_threshold) {
		fprintf(stdout, "Too many dropped packets (%"PRIu32" > %"PRIu32")\n",
				packets_dropped, drop_threshold);
		exit(EXIT_FAILURE);
	}

	uint32_t jitter_high_threshold = NUM_PACKETS_TO_SEND * 8 / 100;
	if (packets_too_much_jitter > jitter_high_threshold) {
		fprintf(stdout, "Too many packets with higher jitter (%"PRIu32" > %"PRIu32")\n",
				packets_too_much_jitter, jitter_high_threshold);
		exit(EXIT_FAILURE);
	}
}

void rand_test()
{
	srandom(time(NULL));
	rtp_first_seq = (uint16_t) random();
	rtp_next_seq = rtp_first_seq;
	rtp_next_ts = (uint32_t) random();
	jb = osmo_jibuf_alloc(NULL);

	osmo_jibuf_set_min_delay(jb, GENERATED_JITTER_MS - RTP_FREQ_MS);
	osmo_jibuf_set_max_delay(jb, GENERATED_JITTER_MS + RTP_FREQ_MS*2);

	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);

	/* first run */
	rand_generate_pkt_cb(NULL);

	/* If the test takes longer than twice the time needed to generate the packets
	 plus 10 seconds, abort it */
	alarm(NUM_PACKETS_TO_SEND*20/1000 +10);

	while((packets_received + packets_dropped) < NUM_PACKETS_TO_SEND)
		osmo_select_main(0);

	osmo_jibuf_delete(jb);

	rand_test_check();
}

void pcap_test_check() {

}

void pcap_test() {
	osmo_pcap_init();

	osmo_pcap.h = osmo_pcap_test_open(opt_pcap_file);
	if (osmo_pcap.h == NULL)
		exit(EXIT_FAILURE);

	osmo_pcap.timer.cb = pcap_pkt_timer_cb;

	if(opt_osmux) {
		INIT_LLIST_HEAD(&osmux_list);
		osmux_xfrm_output_init(&pcap_osmux_h, 0);
	}

	jb = osmo_jibuf_alloc(NULL);
	osmo_jibuf_set_dequeue_cb(jb, dequeue_cb, NULL);
	osmo_jibuf_set_min_delay(jb, opt_buffer_min);
	osmo_jibuf_set_max_delay(jb, opt_buffer_max);

	/* first run */
	pcap_pkt_timer_cb(NULL);

	while(!pcap_finished || !osmo_jibuf_empty(jb))
		osmo_select_main(0);

	osmo_jibuf_delete(jb);

	pcap_test_check();
}

static void print_help(void)
{
	printf("jibuf_test [-r] [-p pcap] [-o] [-d] [-g] [-m ms] [-M ms]\n");
	printf(" -h Print this help message\n");
	printf(" -r Run test with randomly generated jitter\n");
	printf(" -p Run test with specified pcap file\n");
	printf(" -o The pcap contains OSMUX packets isntead of RTP\n");
	printf(" -d Enable packet trace debug suitable for humans\n");
	printf(" -t Enable packet trace debug suitable for gnuplot\n");
	printf(" -m Minimum buffer size for the jitter-buffer, in ms (only used in -p mode)\n");
	printf(" -M Maximum buffer size for the jitter-buffer, in ms (only used in -p mode)\n");
}

static int parse_options(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "hdtrop:m:M:")) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			return -1;
		case 'd':
			opt_debug_human = true;
			break;
		case 't':
			opt_debug_table = true;
			break;
		case 'r':
			opt_test_rand = true;
			break;
		case 'o':
			opt_osmux = true;
			break;
		case 'p':
			opt_pcap_file = strdup(optarg);
			break;
		case 'm':
			opt_buffer_min = (uint32_t) atoi(optarg);
			break;
		case 'M':
			opt_buffer_max = (uint32_t) atoi(optarg);
			break;
		default:
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	if(parse_options(argc, argv) < 0)
		exit(EXIT_FAILURE);

	osmo_init_logging(&jibuf_test_log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	if(opt_debug_human && !opt_debug_table)
		log_set_category_filter(osmo_stderr_target, DLMIB, 1, LOGL_DEBUG);

	if(opt_pcap_file && opt_test_rand) {
		print_help();
		exit(EXIT_FAILURE);
	}


	if(opt_pcap_file)
		pcap_test();

	if(opt_test_rand)
		rand_test();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
