#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/netif/channel.h>
#include <osmocom/netif/ipa.h>

#define IPA_ALLOC_SIZE 1200

/*
 * Common propietary IPA messages:
 *	- PONG: in reply to PING.
 *	- ID_REQUEST: first messages once OML has been established.
 *	- ID_ACK: in reply to ID_ACK.
 */
const uint8_t ipa_pong_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG
};

const uint8_t ipa_id_ack_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK
};

const uint8_t ipa_id_req_msg[] = {
	0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
	0x01, IPAC_IDTAG_UNIT,
	0x01, IPAC_IDTAG_MACADDR,
	0x01, IPAC_IDTAG_LOCATION1,
	0x01, IPAC_IDTAG_LOCATION2,
	0x01, IPAC_IDTAG_EQUIPVERS,
	0x01, IPAC_IDTAG_SWVERSION,
	0x01, IPAC_IDTAG_UNITNAME,
	0x01, IPAC_IDTAG_SERNR,
};

static const char *idtag_names[] = {
	[IPAC_IDTAG_SERNR]	= "Serial_Number",
	[IPAC_IDTAG_UNITNAME]	= "Unit_Name",
	[IPAC_IDTAG_LOCATION1]	= "Location_1",
	[IPAC_IDTAG_LOCATION2]	= "Location_2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equipment_Version",
	[IPAC_IDTAG_SWVERSION]	= "Software_Version",
	[IPAC_IDTAG_IPADDR]	= "IP_Address",
	[IPAC_IDTAG_MACADDR]	= "MAC_Address",
	[IPAC_IDTAG_UNIT]	= "Unit_ID",
};

const char *ipaccess_idtag_name(uint8_t tag)
{
	if (tag >= ARRAY_SIZE(idtag_names))
		return "unknown";

	return idtag_names[tag];
}


struct msgb *osmo_ipa_msg_alloc(int headroom)
{
	struct msgb *msg;

	headroom += sizeof(struct ipa_head);

	msg = msgb_alloc_headroom(IPA_ALLOC_SIZE + headroom, headroom, "IPA");
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	return msg;
}

void osmo_ipa_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipa_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipa_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

int osmo_ipa_msg_recv(int fd, struct msgb *msg)
{
	struct ipa_head *hh;
	int len, ret;

	/* first read our 3-byte header */
	hh = (struct ipa_head *) msg->data;
	ret = recv(fd, msg->data, sizeof(*hh), 0);
	if (ret <= 0) {
		return ret;
	} else if (ret != sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "too small message received\n");
		return -EIO;
	}
	msgb_put(msg, ret);

	/* then read the length as specified in header */
	msg->l2h = msg->data + sizeof(*hh);
	len = ntohs(hh->len);

	if (len < 0 || IPA_ALLOC_SIZE < len + sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "bad message length of %d bytes, "
					"received %d bytes\n", len, ret);
		return -EIO;
	}

	ret = recv(fd, msg->l2h, len, 0);
	if (ret <= 0) {
		return ret;
	} else if (ret < len) {
		LOGP(DLINP, LOGL_ERROR, "trunked message received\n");
		return -EIO;
	}
	msgb_put(msg, ret);
	return ret;
}

int osmo_ipa_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;

	memset(dec, 0, sizeof(*dec));

	while (len >= 2) {
		len -= 2;
		t_len = *cur++;
		t_tag = *cur++;

		if (t_len > len + 1) {
			LOGP(DLMI, LOGL_ERROR, "The tag does not fit: %d\n", t_len);
			return -EINVAL;
		}

		DEBUGPC(DLMI, "%s='%s' ", ipaccess_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len;
		dec->lv[t_tag].val = cur;

		cur += t_len;
		len -= t_len;
	}
	return 0;
}

int osmo_ipa_parse_unitid(const char *str, struct ipaccess_unit *unit_data)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->bts_id = ul & 0xffff;
	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->trx_id = ul & 0xffff;

	return 0;
}

static int ipaccess_send(int fd, const void *msg, size_t msglen)
{
	int ret;

	ret = write(fd, msg, msglen);
	if (ret < 0)
		return ret;
	if (ret < msglen) {
		LOGP(DLINP, LOGL_ERROR, "ipaccess_send: short write\n");
		return -EIO;
	}
	return ret;
}

int ipaccess_send_pong(int fd)
{
	return ipaccess_send(fd, ipa_pong_msg, sizeof(ipa_pong_msg));
}

int ipaccess_send_id_ack(int fd)
{
	return ipaccess_send(fd, ipa_id_ack_msg, sizeof(ipa_id_ack_msg));
}

int ipaccess_send_id_req(int fd)
{
	return ipaccess_send(fd, ipa_id_req_msg, sizeof(ipa_id_req_msg));
}

/* base handling of the ip.access protocol */
int osmo_ipa_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd)
{
	int ipa_ccm = 0;
	uint8_t msg_type = *(msg->l2h);
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ipa_ccm = 1;
		ret = ipaccess_send_pong(bfd->fd);
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DLMI, "PONG!\n");
		ipa_ccm = 1;
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DLMI, "ID_ACK? -> ACK!\n");
		ipa_ccm = 1;
		ret = ipaccess_send_id_ack(bfd->fd);
		break;
	}
	return ipa_ccm;
}

int ipaccess_parse_unitid(const char *str, struct ipaccess_unit *unit_data)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->bts_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->trx_id = ul & 0xffff;

	return 0;
}
