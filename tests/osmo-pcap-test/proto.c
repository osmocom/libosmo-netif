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
#include <netinet/in.h>
#include <linux/if_ether.h>

#include <osmocom/core/linuxlist.h>
#include "proto.h"

static LLIST_HEAD(l2_proto_list);
static LLIST_HEAD(l3_proto_list);
static LLIST_HEAD(l4_proto_list);
#include <stdio.h>

struct osmo_pcap_proto_l2 *osmo_pcap_proto_l2_find(unsigned int pcap_linktype)
{
	struct osmo_pcap_proto_l2 *cur;

	llist_for_each_entry(cur, &l2_proto_list, head) {
		if (cur->l2protonum == pcap_linktype)
			return cur;
	}
	return NULL;
}

void osmo_pcap_proto_l2_register(struct osmo_pcap_proto_l2 *h)
{
	llist_add(&h->head, &l2_proto_list);
}


struct osmo_pcap_proto_l3 *osmo_pcap_proto_l3_find(unsigned int l3protocol)
{
	struct osmo_pcap_proto_l3 *cur;

	llist_for_each_entry(cur, &l3_proto_list, head) {
		if (ntohs(cur->l3protonum) == l3protocol)
			return cur;
	}
	return NULL;
}

void osmo_pcap_proto_l3_register(struct osmo_pcap_proto_l3 *h)
{
	llist_add(&h->head, &l3_proto_list);
}

struct osmo_pcap_proto_l4 *
osmo_pcap_proto_l4_find(unsigned int l4protocol)
{
	struct osmo_pcap_proto_l4 *cur;

	llist_for_each_entry(cur, &l4_proto_list, head) {
		if (cur->l4protonum == l4protocol)
			return cur;
	}
	return NULL;
}

void osmo_pcap_proto_l4_register(struct osmo_pcap_proto_l4 *h)
{
	llist_add(&h->head, &l4_proto_list);
}
