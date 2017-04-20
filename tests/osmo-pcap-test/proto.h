#ifndef _OSMO_PCAP_PROTO_H_
#define _OSMO_PCAP_PROTO_H_

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

struct osmo_pcap_proto_l4 {
	struct llist_head	head;

	unsigned int		l4protonum;

	unsigned int	(*l4pkt_hdr_len)(const uint8_t *pkt);
	unsigned int	(*l4pkt_no_data)(const uint8_t *pkt);
};

struct osmo_pcap_proto_l3 {
	struct llist_head	head;

	unsigned int		l3protonum;

	unsigned int	(*l3pkt_hdr_len)(const uint8_t *pkt);
	unsigned int	(*l4pkt_proto)(const uint8_t *pkt);
};

struct osmo_pcap_proto_l2 {
	struct llist_head	head;

	unsigned int		l2protonum;

	unsigned int	(*l2pkt_hdr_len)(const uint8_t *pkt);
	unsigned int	(*l3pkt_proto)(const uint8_t *pkt);
};


struct osmo_pcap_proto_l2 *osmo_pcap_proto_l2_find(unsigned int pcap_linktype);
void osmo_pcap_proto_l2_register(struct osmo_pcap_proto_l2 *h);

struct osmo_pcap_proto_l3 *osmo_pcap_proto_l3_find(unsigned int l3protonum);
void osmo_pcap_proto_l3_register(struct osmo_pcap_proto_l3 *h);

struct osmo_pcap_proto_l4 *osmo_pcap_proto_l4_find(unsigned int l4protonum);
void osmo_pcap_proto_l4_register(struct osmo_pcap_proto_l4 *h);

/* Initialization of supported protocols here. */
void l2_sll_init(void);
void l2_eth_init(void);
void l3_ipv4_init(void);
void l4_tcp_init(void);
void l4_udp_init(void);

#endif
