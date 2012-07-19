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
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "proto.h"

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>

#include <osmocom/netif/osmux.h>

struct osmo_pcap_test_stats {
	uint32_t pkts;
	uint32_t skip;
	uint32_t processed;
	uint32_t unsupported_l3;
	uint32_t unsupported_l4;
} osmo_pcap_test_stats;

static int
osmo_pcap_process_packet(const uint8_t *pkt, uint32_t pktlen,
			 struct osmo_pcap_proto_l2l3 *l3h,
			 struct osmo_pcap_proto_l4 *l4h,
			 int (*cb)(struct msgb *msgb))
{
	unsigned int l3hdr_len, skip_hdr_len;
	struct msgb *msgb;
	int ret;

	/* skip layer 2, 3 and 4 headers */
	l3hdr_len = l3h->l3pkt_hdr_len(pkt + ETH_HLEN);
	skip_hdr_len = l3h->l2hdr_len + l3hdr_len +
			l4h->l4pkt_hdr_len(pkt + ETH_HLEN + l3hdr_len);

	/* This packet contains no data, skip it. */
	if (l4h->l4pkt_no_data(pkt + l3hdr_len + ETH_HLEN)) {
		osmo_pcap_test_stats.skip++;
		return 0;
	}

	/* get application layer data. */
	pkt += skip_hdr_len;
	pktlen -= skip_hdr_len;

	/* Create the fake network buffer. */
	msgb = msgb_alloc(pktlen, "OSMO/PCAP test");
	if (msgb == NULL) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}
	memcpy(msgb->data, pkt, pktlen);
	msgb_put(msgb, pktlen);

	ret = cb(msgb);

	msgb_free(msgb);

	osmo_pcap_test_stats.processed++;

	return ret;
}

static pcap_t *osmo_pcap_test_open(const char *pcapfile)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_offline(pcapfile, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open pcap file %s: %s\n",
				pcapfile, errbuf);
		return NULL;
	}

	return handle;
}

static void osmo_pcap_test_close(pcap_t *handle)
{
	pcap_close(handle);
}

static struct osmo_pcap {
	pcap_t			*h;
	struct osmo_timer_list	timer;
	struct timeval		last;
} osmo_pcap;

static int
osmo_pcap_test_run(pcap_t *handle, uint8_t pnum, int (*cb)(struct msgb *msgb))
{
	struct osmo_pcap_proto_l2l3 *l3h;
	struct osmo_pcap_proto_l4 *l4h;
	struct pcap_pkthdr pcaph;
	const u_char *pkt;
	struct timeval res;
	uint8_t l4protonum;

retry:
	pkt = pcap_next(handle, &pcaph);
	if (pkt == NULL)
		return -1;

	osmo_pcap_test_stats.pkts++;

	l3h = osmo_pcap_proto_l2l3_find(pkt);
	if (l3h == NULL) {
		osmo_pcap_test_stats.unsupported_l3++;
		goto retry;
	}
	l4protonum = l3h->l4pkt_proto(pkt + ETH_HLEN);

	/* filter l4 protocols we are not interested in */
	if (l4protonum != pnum) {
		osmo_pcap_test_stats.skip++;
		goto retry;
	}

	l4h = osmo_pcap_proto_l4_find(pkt, l4protonum);
	if (l4h == NULL) {
		osmo_pcap_test_stats.unsupported_l4++;
		goto retry;
	}

	/* first packet that is going to be processed */
	if (osmo_pcap_test_stats.processed == 0)
		memcpy(&osmo_pcap.last, &pcaph.ts, sizeof(struct timeval));

	/* retry with next packet if this has been skipped. */
	if (osmo_pcap_process_packet(pkt, pcaph.caplen, l3h, l4h, cb) < 0)
		goto retry;

	/* calculate waiting time */
	timersub(&pcaph.ts, &osmo_pcap.last, &res);
	printf("waiting %lu.%.6lu seconds\n", res.tv_sec, res.tv_usec);
	osmo_timer_schedule(&osmo_pcap.timer, res.tv_sec, res.tv_usec);

	memcpy(&osmo_pcap.last, &pcaph.ts, sizeof(struct timeval));

	return 0;
}

static struct osmux_out_handle h = {
        .rtp_seq        = 1000,
        .rtp_timestamp  = 10,
};

static void tx_cb(struct msgb *msg, void *data)
{
	printf("now sending message scheduled [emulated], msg=%p\n", msg);
	/*
	 * Here we should call the real function that sends the message
	 * instead of releasing it.
	 */
	msgb_free(msg);
}

static void deliver(struct msgb *batch_msg)
{
        struct osmux_hdr *osmuxh;
        struct msgb *msg;
        int i = 0;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
	struct timeval delta = { .tv_sec = 0, .tv_usec = 160000 };

	timerclear(&tv);

        printf("sending batch (len=%d) [emulated]\n", batch_msg->len);
        while((osmuxh = osmux_xfrm_output_pull(batch_msg)) != NULL) {
                msg = osmux_xfrm_output(osmuxh, &h);
		printf("schedule transmision for %lu.%6lu seconds, "
		       "msg=%p (%d in batch)\n",
			tv.tv_sec, tv.tv_usec, msg, ++i);
		osmux_tx_sched(msg, &tv, tx_cb, NULL);
		timeradd(&tv, &delta, &tv);
        }
}

struct osmux_in_handle h_input = {
	.osmux_seq	= 0, /* sequence number to start OSmux message from */
	.deliver	= deliver,
};

static int run(struct msgb *msg)
{
	int ret;
retry:
	ret = osmux_xfrm_input(msg);
	switch(ret) {
		case -1:
			printf("something is wrong\n");
			break;
		case 0:
			break;
		case 1:
			osmux_xfrm_input_deliver(&h_input);
			goto retry;
	}
	return 0;
}

static void osmo_pcap_pkt_timer_cb(void *data)
{
	if (osmo_pcap_test_run(osmo_pcap.h, IPPROTO_UDP, run) < 0) {
		printf("pkts=%d processed=%d skip=%d "
			"unsupported_l3=%d unsupported_l4=%d\n",
			osmo_pcap_test_stats.pkts,
			osmo_pcap_test_stats.processed,
			osmo_pcap_test_stats.skip,
			osmo_pcap_test_stats.unsupported_l3,
			osmo_pcap_test_stats.unsupported_l4);
		printf("\e[1;34mDone.\e[0m\n");
		osmo_pcap_test_close(osmo_pcap.h);
		exit(EXIT_SUCCESS);
	}
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Wrong usage:\n");
		fprintf(stderr, "%s <pcap_file>\n", argv[0]);
		fprintf(stderr, "example: %s file.pcap\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Initialization of supported layer 3 and 4 protocols here. */
	l2l3_ipv4_init();
	l4_tcp_init();
	l4_udp_init();

	printf("\e[1;34mStarting test...\e[0m\n");

	osmo_pcap.h = osmo_pcap_test_open(argv[1]);
	if (osmo_pcap.h == NULL)
		exit(EXIT_FAILURE);

	osmo_pcap.timer.cb = osmo_pcap_pkt_timer_cb;

	/* first run */
	osmo_pcap_pkt_timer_cb(NULL);

	osmux_xfrm_input_init(&h_input);

	while(1) {
		osmo_select_main(0);
	}

	return ret;
}
