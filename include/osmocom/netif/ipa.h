#ifndef _OSMO_NETIF_IPA_H_
#define _OSMO_NETIF_IPA_H_

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/netif/stream.h>

/* This is like 'struct ipaccess_head' in libosmocore, but 'ipa_head' is
 * actually the more apropriate name, so rather than making more code
 * use the wrong name, let's keep the duplicate header definitions below */
struct ipa_head {
	uint16_t len;	/* network byte order */
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

struct ipa_head_ext {
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

struct osmo_msgb_ipa_cb {
	uint8_t proto;
	uint8_t proto_ext;
} __attribute__ ((packed));

#define OSMO_MSGB_IPA_CB(__msg)	((struct osmo_msgb_ipa_cb *)&((__msg)->cb[0]))
#define msgb_ipa_proto(__x)	OSMO_MSGB_IPA_CB(__x)->proto
#define msgb_ipa_proto_ext(__x)	OSMO_MSGB_IPA_CB(__x)->proto_ext

struct msgb *osmo_ipa_msg_alloc(int headroom);
struct msgb *osmo_ipa_ext_msg_alloc(int headroom);

void osmo_ipa_msg_push_header(struct msgb *msg, uint8_t proto);

int osmo_ipa_process_msg(struct msgb *msg);

struct osmo_fd;
struct tlv_parsed;

int osmo_ipa_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd, int server);
int osmo_ipa_parse_unitid(const char *str, struct ipaccess_unit *unit_data);

int ipaccess_send_pong(int fd);
int ipaccess_send_id_ack(int fd);
int ipaccess_send_id_req(int fd);

struct osmo_ipa_unit;

struct msgb *ipa_cli_id_resp(struct osmo_ipa_unit *dev, uint8_t *data, int len);
struct msgb *ipa_cli_id_ack(void);

int osmo_ipa_parse_msg_id_resp(struct msgb *msg, struct ipaccess_unit *unit_data);

int osmo_ipa_segmentation_cb(struct msgb *msg);

#define IPAC_PROTO_UNSPECIFIED -1

void osmo_ipa_stream_srv_send(struct osmo_stream_srv *conn, int ipaccess_proto,
			 enum ipaccess_proto_ext pe, struct msgb *msg);
void osmo_ipa_stream_cli_send(struct osmo_stream_cli *cli, int ipaccess_proto,
			 enum ipaccess_proto_ext pe, struct msgb *msg);
#endif
