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
#include <linux/if_ether.h>
#include <pcap/sll.h>
#include <pcap/dlt.h>

#include "proto.h"

#define PRINT_CMP(...)

static unsigned int l2_sll_pkt_l3proto_num(const uint8_t *pkt)
{
	const struct sll_header *lh = (const struct sll_header *)pkt;
	switch(ntohs(lh->sll_protocol)) {
	case ETH_P_IP:
		return htons(AF_INET);
	default:
		return lh->sll_protocol;
	}
}

static unsigned int l2_sll_pkt_l2hdr_len(const uint8_t *pkt)
{

	return SLL_HDR_LEN;
}

static struct osmo_pcap_proto_l2 sll = {
	.l2protonum	= DLT_LINUX_SLL,
	.l2pkt_hdr_len	= l2_sll_pkt_l2hdr_len,
	.l3pkt_proto	= l2_sll_pkt_l3proto_num,
};

void l2_sll_init(void)
{
	osmo_pcap_proto_l2_register(&sll);
}
