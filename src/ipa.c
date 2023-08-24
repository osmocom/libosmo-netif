/* (C) 2011-2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
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

#include <osmocom/netif/ipa.h>
#include <osmocom/netif/ipa_unit.h>

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

struct msgb *osmo_ipa_ext_msg_alloc(size_t headroom)
{
	return osmo_ipa_msg_alloc(sizeof(struct ipa_head_ext) + headroom);
}

void osmo_ipa_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipa_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipa_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

int osmo_ipa_process_msg(struct msgb *msg)
{
	struct ipa_head *hh;
	int len;

	if (msg->len < sizeof(struct ipa_head)) {
		LOGP(DLINP, LOGL_ERROR, "too small IPA message\n");
		return -EIO;
	}
	hh = (struct ipa_head *) msg->data;

	len = sizeof(struct ipa_head) + ntohs(hh->len);
	if (len > msg->len) {
		LOGP(DLINP, LOGL_ERROR, "bad IPA message header "
					"hdrlen=%u < datalen=%u\n",
					len, msg->len);
		return -EIO;
	}
	msg->l2h = msg->data + sizeof(*hh);

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
int osmo_ipa_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd, int server)
{
	int ipa_ccm = 0;
	uint8_t msg_type = *(msg->l2h);

	switch (msg_type) {
	case IPAC_MSGT_PING:
		LOGP(DLINP, LOGL_DEBUG, "PING!\n");
		ipa_ccm = 1;
		ipaccess_send_pong(bfd->fd);
		break;
	case IPAC_MSGT_PONG:
		LOGP(DLINP, LOGL_DEBUG, "PONG!\n");
		ipa_ccm = 1;
		break;
	case IPAC_MSGT_ID_ACK:
		if (server) {
			LOGP(DLINP, LOGL_DEBUG, "ID_ACK? -> ACK!\n");
			ipa_ccm = 1;
			ipaccess_send_id_ack(bfd->fd);
		} else {
			LOGP(DLINP, LOGL_DEBUG, "ID_ACK! OK!\n");
			ipa_ccm = 1;
		}
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

struct msgb *ipa_cli_id_resp(struct osmo_ipa_unit *dev, uint8_t *data, int len)
{
	struct msgb *nmsg;
	char str[64];
	uint8_t *tag;

	nmsg = osmo_ipa_msg_alloc(0);
	if (nmsg == NULL)
		return NULL;

	*msgb_put(nmsg, 1) = IPAC_MSGT_ID_RESP;
	while (len) {
		if (len < 2) {
			LOGP(DLINP, LOGL_NOTICE,
				"Short read of ipaccess tag\n");
			msgb_free(nmsg);
			return NULL;
		}
		switch (data[1]) {
		case IPAC_IDTAG_UNIT:
			osmo_ipa_unit_snprintf(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_MACADDR:
			osmo_ipa_unit_snprintf_mac_addr(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_LOCATION1:
			osmo_ipa_unit_snprintf_loc1(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_LOCATION2:
			osmo_ipa_unit_snprintf_loc2(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_EQUIPVERS:
			osmo_ipa_unit_snprintf_hwvers(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_SWVERSION:
			osmo_ipa_unit_snprintf_swvers(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_UNITNAME:
			osmo_ipa_unit_snprintf_name(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_SERNR:
			osmo_ipa_unit_snprintf_serno(str, sizeof(str), dev);
			break;
		default:
			LOGP(DLINP, LOGL_NOTICE,
				"Unknown ipaccess tag 0x%02x\n", *data);
			msgb_free(nmsg);
			return NULL;
		}
		LOGP(DLINP, LOGL_INFO, " tag %d: %s\n", data[1], str);
		tag = msgb_put(nmsg, 3 + strlen(str) + 1);
		tag[0] = 0x00;
		tag[1] = 1 + strlen(str) + 1;
		tag[2] = data[1];
		memcpy(tag + 3, str, strlen(str) + 1);
		data += 2;
		len -= 2;
	}
	osmo_ipa_msg_push_header(nmsg, IPAC_PROTO_IPACCESS);
	return nmsg;
}

struct msgb *ipa_cli_id_ack(void)
{
	struct msgb *nmsg2;

	nmsg2 = osmo_ipa_msg_alloc(0);
	if (nmsg2 == NULL)
		return NULL;

	*msgb_put(nmsg2, 1) = IPAC_MSGT_ID_ACK;
	osmo_ipa_msg_push_header(nmsg2, IPAC_PROTO_IPACCESS);

	return nmsg2;
}

int
osmo_ipa_parse_msg_id_resp(struct msgb *msg, struct ipaccess_unit *unit_data)
{
	struct tlv_parsed tlvp;
	char *unitid;
	int len, ret;

	DEBUGP(DLINP, "ID_RESP\n");
	/* parse tags, search for Unit ID */
	ret = ipa_ccm_id_resp_parse(&tlvp, (const uint8_t *)msg->l2h + 1, msgb_l2len(msg)-1);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"with malformed TLVs\n");
		return -EINVAL;
	}
	if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"without unit ID\n");
		return  -EINVAL;
	}
	len = TLVP_LEN(&tlvp, IPAC_IDTAG_UNIT);
	if (len < 1) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"with too small unit ID\n");
		return -EINVAL;
	}
	unitid = (char *) TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT);
	unitid[len - 1] = '\0';

	if (osmo_ipa_parse_unitid(unitid, unit_data) < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to parse IPA IDTAG\n");
		return -EINVAL;
	}

	return 0;
}

#define MSG_CB_IPA_INFO_OFFSET 0

/* Check and remove headers (in case of p == IPAC_PROTO_OSMO, also the IPA extension header).
 * Returns a negative number on error, otherwise the number of octets removed */
static inline int ipa_check_pull_headers(struct msgb *msg)
{
	int ret;
	size_t octets_removed = 0;
	msg->l1h = msg->data;
	struct ipa_head *ih = (struct ipa_head *)msg->data;
	osmo_ipa_msgb_cb_proto(msg) = ih->proto;

	if ((ret = osmo_ipa_process_msg(msg)) < 0) {
		LOGP(DLINP, LOGL_ERROR, "Error processing IPA message\n");
		return -EIO;
	}
	msgb_pull(msg, sizeof(struct ipa_head));
	octets_removed += sizeof(struct ipa_head);
	msg->l2h = msg->data;
	if (ih->proto != IPAC_PROTO_OSMO)
		return octets_removed;

	osmo_ipa_msgb_cb_proto_ext(msg) = msg->data[0];
	msgb_pull(msg, sizeof(struct ipa_head_ext));
	octets_removed += sizeof(struct ipa_head_ext);
	return octets_removed;
}

/*! Segmentation callback used by libosmo-netif streaming backend
 *  See definition of `struct osmo_io_ops` for callback semantics
 *  \param[out] msg	Original `struct msgb` received via osmo_io
 *  \returns		The total packet length indicated by the first header,
 *			otherwise negative number on error. Constants:
 *			-EAGAIN,  if the header has not been read yet,
 *			-ENOBUFS, if the header declares a payload too large
 */
int osmo_ipa_segmentation_cb(struct msgb *msg)
{
	const struct ipa_head *hh = (const struct ipa_head *) msg->data;
	size_t payload_len, total_len;
	size_t available = msgb_length(msg) + msgb_tailroom(msg);
	int removed_octets = 0;

	if (msgb_length(msg) < sizeof(*hh)) {
		/* Haven't even read the entire header */
		return -EAGAIN;
	}
	payload_len = osmo_ntohs(hh->len);
	total_len = sizeof(*hh) + payload_len;
	if (OSMO_UNLIKELY(available < total_len)) {
		LOGP(DLINP, LOGL_ERROR, "Not enough space left in message buffer. "
					"Have %zu octets, but need %zu\n",
					available, total_len);
		return -ENOBUFS;
	}
	if (total_len <= msgb_length(msg)) {
		removed_octets = ipa_check_pull_headers(msg);
		if (removed_octets < 0) {
			LOGP(DLINP, LOGL_ERROR, "Error pulling IPA headers\n");
			return removed_octets;
		}
	}
	return total_len;
}

/* Push IPA headers; if we have IPAC_PROTO_OSMO this also takes care of the
 * extension header */
static inline void ipa_push_headers(enum ipaccess_proto p, enum ipaccess_proto_ext pe,
				    struct msgb *msg)
{
	if (p == IPAC_PROTO_OSMO)
		ipa_prepend_header_ext(msg, pe);
	osmo_ipa_msg_push_header(msg, p);
}

/*! \brief Enqueue IPA data to be sent via an Osmocom stream server
 *  \param[in] conn Stream Server through which we want to send
 *  \param[in] p   Protocol transported by IPA.
 *  \param[in] pe  Ignored, unless p == IPAC_PROTO_OSMO, in which case this specifies the
 *		 Osmocom protocol extension
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_ipa_stream_srv_send(struct osmo_stream_srv *conn, enum ipaccess_proto p,
			      enum ipaccess_proto_ext pe, struct msgb *msg)
{
	OSMO_ASSERT(msg);
	ipa_push_headers(p, pe, msg);
	osmo_stream_srv_send(conn, msg);
}

/*! \brief Enqueue data to be sent via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param[in] p   Protocol transported by IPA.
 *  \param[in] pe  Ignored, unless p == IPAC_PROTO_OSMO, in which case this specifies the
 *		   Osmocom protocol extension
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_ipa_stream_cli_send(struct osmo_stream_cli *cli, enum ipaccess_proto p,
			      enum ipaccess_proto_ext pe, struct msgb *msg)
{
	OSMO_ASSERT(msg);
	ipa_push_headers(p, pe, msg);
	osmo_stream_cli_send(cli, msg);
}
