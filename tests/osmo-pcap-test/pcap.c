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
#include <sys/time.h>

#include <linux/if_ether.h>

#include "proto.h"
#include "osmo_pcap.h"

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/select.h>

#include <osmocom/netif/osmux.h>

struct osmo_pcap_test_stats {
	uint32_t pkts;
	uint32_t skip;
	uint32_t processed;
	uint32_t unsupported_l2;
	uint32_t unsupported_l3;
	uint32_t unsupported_l4;
} osmo_pcap_test_stats;

static int
osmo_pcap_process_packet(struct msgb **msgptr,
			 const uint8_t *pkt, uint32_t pktlen,
			 struct osmo_pcap_proto_l2 *l2h,
			 struct osmo_pcap_proto_l3 *l3h,
			 struct osmo_pcap_proto_l4 *l4h,
			 int (*cb)(struct msgb *msgb))
{
	unsigned int l2hdr_len, l3hdr_len, skip_hdr_len;
	struct msgb *msgb;

	/* skip layer 2, 3 and 4 headers */
	l2hdr_len = l2h->l2pkt_hdr_len(pkt);
	l3hdr_len = l3h->l3pkt_hdr_len(pkt + l2hdr_len);
	skip_hdr_len = l2hdr_len + l3hdr_len +
			l4h->l4pkt_hdr_len(pkt + l2hdr_len + l3hdr_len);

	/* This packet contains no data, skip it. */
	if (l4h->l4pkt_no_data(pkt + l2hdr_len + l3hdr_len)) {
		osmo_pcap_test_stats.skip++;
		return -1;
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

	*msgptr = msgb;

	return 0;
}

pcap_t *osmo_pcap_test_open(const char *pcapfile)
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

void osmo_pcap_test_close(pcap_t *handle)
{
	pcap_close(handle);
}

int
osmo_pcap_test_run(struct osmo_pcap *p, uint8_t pnum, int (*cb)(struct msgb *msgb))
{
	struct osmo_pcap_proto_l2 *l2h;
	struct osmo_pcap_proto_l3 *l3h;
	struct osmo_pcap_proto_l4 *l4h;
	struct pcap_pkthdr pcaph;
	const u_char *l2pkt, *l3pkt;
	struct timespec now_ts, elapsed_sys_ts;
	struct timeval res, elapsed_pcap, elapsed_sys;
	uint8_t l4protonum;

	if (p->deliver_msg) {
		if (cb(p->deliver_msg) == 0)
			osmo_pcap_test_stats.processed++;
		p->deliver_msg = 0;
	}

retry:
	l2pkt = pcap_next(p->h, &pcaph);
	if (l2pkt == NULL)
		return -1;

	osmo_pcap_test_stats.pkts++;

	int linktype = pcap_datalink(p->h);
	l2h = osmo_pcap_proto_l2_find(linktype);
	if (l2h == NULL) {
		osmo_pcap_test_stats.unsupported_l2++;
		goto retry;
	}

	l3h = osmo_pcap_proto_l3_find(l2h->l3pkt_proto(l2pkt));
	if (l3h == NULL) {
		osmo_pcap_test_stats.unsupported_l3++;
		goto retry;
	}

	l3pkt = l2pkt + l2h->l2pkt_hdr_len(l2pkt);
	l4protonum = l3h->l4pkt_proto(l3pkt);
	/* filter l4 protocols we are not interested in */
	if (l4protonum != pnum) {
		osmo_pcap_test_stats.skip++;
		goto retry;
	}

	l4h = osmo_pcap_proto_l4_find(l4protonum);
	if (l4h == NULL) {
		osmo_pcap_test_stats.unsupported_l4++;
		goto retry;
	}

	/* first packet that is going to be processed */
	if (osmo_pcap_test_stats.processed == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &p->start_sys) < 0)
			return -1;
		memcpy(&p->start_pcap, &pcaph.ts, sizeof(struct timeval));
	}

	/* retry with next packet if this has been skipped. */
	if (osmo_pcap_process_packet(&p->deliver_msg, l2pkt, pcaph.caplen, l2h, l3h, l4h, cb) < 0)
		goto retry;

	/* calculate waiting time */
	timersub(&pcaph.ts, &p->start_pcap, &elapsed_pcap);
	if (clock_gettime(CLOCK_MONOTONIC, &now_ts) < 0)
		return -1;
	timespecsub(&now_ts, &p->start_sys, &elapsed_sys_ts);
	elapsed_sys.tv_sec = elapsed_sys_ts.tv_sec;
	elapsed_sys.tv_usec = elapsed_sys_ts.tv_nsec / 1000;

	if (timercmp(&elapsed_sys, &elapsed_pcap, >)) {
		printf("We are late!\n");
		res.tv_sec = 0;
		res.tv_usec = 0;
	} else {
		timersub(&elapsed_pcap, &elapsed_sys, &res);
	}
	printf("next packet comes in %lu.%.6lu seconds\n",
	       (unsigned int long) res.tv_sec, (unsigned int long) res.tv_usec);
	osmo_timer_schedule(&p->timer, res.tv_sec, res.tv_usec);

	return 0;
}

void osmo_pcap_stats_printf(void)
{
	printf("pkts=%d processed=%d skip=%d unsupported_l2=%d "
		"unsupported_l3=%d unsupported_l4=%d\n",
		osmo_pcap_test_stats.pkts,
		osmo_pcap_test_stats.processed,
		osmo_pcap_test_stats.skip,
		osmo_pcap_test_stats.unsupported_l2,
		osmo_pcap_test_stats.unsupported_l3,
		osmo_pcap_test_stats.unsupported_l4);
}

void osmo_pcap_init(void)
{
	/* Initialization of supported layer 2, 3 and 4 protocols here. */
	l2_eth_init();
	l2_sll_init();
	l3_ipv4_init();
	l4_tcp_init();
	l4_udp_init();
}
