#ifndef _OSMO_NETIF_IPA_H_
#define _OSMO_NETIF_IPA_H_

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>

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

struct osmo_ipa_msgb_cb {
	uint8_t proto;
	uint8_t proto_ext;
} __attribute__ ((packed));


/* We don't just cast to 'struct osmo_ipa_msgb_cb *', because that would
 * break the strict aliasing rule. Casting to a reference to a union with
 * a compatible struct member seems to be allowed, though, see:
 *	N1570 Committee Draft — April 12, 2011 ISO/IEC 9899:201x,
 *	Section 6.5, §7 */
#define OSMO_IPA_MSGB_CB(__msg)	(&((( \
					union { \
						unsigned long cb; \
						struct osmo_ipa_msgb_cb _cb; \
					} \
				*)&((__msg)->cb[0]))->_cb))

#define osmo_ipa_msgb_cb_proto(__x)	OSMO_IPA_MSGB_CB(__x)->proto
#define osmo_ipa_msgb_cb_proto_ext(__x)	OSMO_IPA_MSGB_CB(__x)->proto_ext

struct msgb *osmo_ipa_msg_alloc(int headroom);
struct msgb *osmo_ipa_ext_msg_alloc(size_t headroom);

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

void osmo_ipa_msg_push_headers(struct msgb *msg, enum ipaccess_proto p, enum ipaccess_proto_ext pe);

/***********************************************************************
 * IPA Keep-Alive FSM
 ***********************************************************************/
struct osmo_ipa_ka_fsm_inst;
typedef int (*osmo_ipa_ka_fsm_timeout_cb_t)(struct osmo_ipa_ka_fsm_inst *ka_fi, void *data);

typedef int (*osmo_ipa_ka_fsm_send_cb_t)(struct osmo_ipa_ka_fsm_inst *ka_fi, struct msgb *msg, void *data);

struct osmo_ipa_ka_fsm_inst *osmo_ipa_ka_fsm_alloc(void *ctx, const char *id);
void osmo_ipa_ka_fsm_free(struct osmo_ipa_ka_fsm_inst *ka_fi);

int osmo_ipa_ka_fsm_set_id(struct osmo_ipa_ka_fsm_inst *ka_fi, const char *id);
int osmo_ipa_ka_fsm_set_ping_interval(struct osmo_ipa_ka_fsm_inst *ka_fi, unsigned int interval);
int osmo_ipa_ka_fsm_set_pong_timeout(struct osmo_ipa_ka_fsm_inst *ka_fi, unsigned int timeout);
void osmo_ipa_ka_fsm_set_data(struct osmo_ipa_ka_fsm_inst *ka_fi, void *cb_data);
void *osmo_ipa_ka_fsm_get_data(const struct osmo_ipa_ka_fsm_inst *ka_fi);

void osmo_ipa_ka_fsm_set_send_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, osmo_ipa_ka_fsm_send_cb_t send_cb);
void osmo_ipa_ka_fsm_set_timeout_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, osmo_ipa_ka_fsm_timeout_cb_t timeout_cb);

void osmo_ipa_ka_fsm_start(struct osmo_ipa_ka_fsm_inst *ka_fi);
void osmo_ipa_ka_fsm_pong_received(struct osmo_ipa_ka_fsm_inst *ka_fi);
void osmo_ipa_ka_fsm_stop(struct osmo_ipa_ka_fsm_inst *ka_fi);

#endif
