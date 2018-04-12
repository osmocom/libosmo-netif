/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later vers
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <pcap/bpf.h>

#include "proto.h"

#define PRINT_CMP(...)

static int unsigned l2_eth_pkt_l3proto_num(const uint8_t *pkt)
{
	const struct ethhdr *eh = (const struct ethhdr *)pkt;
	switch(ntohs(eh->h_proto)) {
	case ETH_P_IP:
		return htons(AF_INET);
	default:
		return eh->h_proto;
	}
}

static unsigned int l2_eth_pkt_l2hdr_len(const uint8_t *pkt)
{

	return ETH_HLEN;
}

static struct osmo_pcap_proto_l2 eth = {
	//.l2protonum	= ETH_P_IP,
	.l2protonum	= DLT_EN10MB,
	.l2pkt_hdr_len	= l2_eth_pkt_l2hdr_len,
	.l3pkt_proto	= l2_eth_pkt_l3proto_num,
};

void l2_eth_init(void)
{
	osmo_pcap_proto_l2_register(&eth);
}
