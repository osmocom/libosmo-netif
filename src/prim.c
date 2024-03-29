/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 * All Rights Reserved
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <inttypes.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/prim.h>
#include <osmocom/netif/stream.h>

struct osmo_prim_pkt_hdr {
	uint32_t sap;    /*!< Service Access Point Identifier */
	uint16_t primitive;    /*!< Primitive number */
	uint16_t operation; /*! Primitive Operation (enum osmo_prim_operation) */
} __attribute__ ((packed));

/* Here we take advantage of the fact that sizeof(struct
 * osmo_prim_pkt_hdr) <= sizeof(struct osmo_prim_hdr), so we don't need
 * to allocate headroom when serializing later.
 */
osmo_static_assert(sizeof(struct osmo_prim_pkt_hdr) <= sizeof(struct osmo_prim_hdr),
		   osmo_prim_msgb_alloc_validate_headroom);

/*! Allocate a primitive of given type and its associated msgb.
*  \param[in] sap Service Access Point
*  \param[in] primitive Primitive Number
*  \param[in] operation Primitive Operation (REQ/RESP/IND/CONF)
*  \param[in] alloc_len Total length (including struct osmo_prim_hdr) to allocate for the primitive
*  \returns Pointer to allocated prim_hdr inisde its own msgb. The osmo_prim_hdr
*	    is pre-alocated & pre-filled.
*/
struct osmo_prim_hdr *osmo_prim_msgb_alloc(unsigned int sap, unsigned int primitive,
					  enum osmo_prim_operation operation, size_t alloc_len)
{
	struct msgb *msg;
	struct osmo_prim_hdr *oph;

	if (alloc_len < sizeof(*oph))
		return NULL;

	msg = msgb_alloc(alloc_len, "osmo_prim_msgb_alloc");
	oph = (struct osmo_prim_hdr *)msgb_put(msg, sizeof(*oph));
	osmo_prim_init(oph, sap, primitive, operation, msg);
	msg->l2h = msg->tail;

	return oph;
}

struct osmo_prim_srv_link {
	void *priv;
	char *addr;
	int log_cat; /* Defaults to DLGLOBAL */
	struct osmo_stream_srv_link *stream;
	osmo_prim_srv_conn_cb opened_conn_cb;
	osmo_prim_srv_conn_cb closed_conn_cb;
	osmo_prim_srv_rx_sapi_version rx_sapi_version_cb;
	osmo_prim_srv_rx_cb rx_cb;
	size_t rx_msgb_alloc_len;
};

struct osmo_prim_srv {
	void *priv;
	struct osmo_prim_srv_link *link; /* backpointer */
	struct osmo_stream_srv *stream;
};

/******************************
 * CONTROL SAP
 ******************************/
#define OSMO_PRIM_CTL_SAPI		0xffffffff
#define OSMO_PRIM_CTL_API_VERSION	0

enum sap_ctl_prim_type {
	SAP_CTL_PRIM_HELLO,
	_SAP_CTL_PRIM_MAX
};

const struct value_string sap_ctl_prim_type_names[] = {
	OSMO_VALUE_STRING(SAP_CTL_PRIM_HELLO),
	{ 0, NULL }
};

/* HNB_CTL_PRIM_HELLO.ind, UL */
struct sap_ctl_hello_param {
	uint32_t sapi; /* SAPI for which we negotiate version */
	uint16_t api_version; /* The intended version */
} __attribute__ ((packed));

struct sap_ctl_prim {
	struct osmo_prim_hdr hdr;
	union {
		struct sap_ctl_hello_param hello_req;
		struct sap_ctl_hello_param hello_cnf;
	} u;
} __attribute__ ((packed));

static struct sap_ctl_prim *_sap_ctl_makeprim_hello_cnf(uint32_t sapi, uint16_t api_version)
{
	struct sap_ctl_prim *ctl_prim;

	ctl_prim = (struct sap_ctl_prim *)osmo_prim_msgb_alloc(
						OSMO_PRIM_CTL_SAPI, SAP_CTL_PRIM_HELLO, PRIM_OP_CONFIRM,
						sizeof(struct osmo_prim_hdr) + sizeof(struct sap_ctl_hello_param));
	msgb_put(ctl_prim->hdr.msg, sizeof(struct sap_ctl_hello_param));
	ctl_prim->u.hello_cnf.sapi = sapi;
	ctl_prim->u.hello_cnf.api_version = api_version;

	return ctl_prim;
}

/******************************
 * osmo_prim_srv
 ******************************/
#define LOGSRV(srv, lvl, fmt, args...) LOGP((srv)->link->log_cat, lvl, fmt, ## args)

static int _srv_sap_ctl_rx_hello_req(struct osmo_prim_srv *prim_srv, struct sap_ctl_hello_param *hello_ind)
{
	struct sap_ctl_prim *prim_resp;
	int rc;

	LOGSRV(prim_srv, LOGL_INFO, "Rx CTL-HELLO.req SAPI=%u API_VERSION=%u\n", hello_ind->sapi, hello_ind->api_version);

	if (hello_ind->sapi == OSMO_PRIM_CTL_SAPI)
		rc = hello_ind->api_version ==  OSMO_PRIM_CTL_API_VERSION ? OSMO_PRIM_CTL_API_VERSION : -1;
	else if (prim_srv->link->rx_sapi_version_cb)
		rc = prim_srv->link->rx_sapi_version_cb(prim_srv, hello_ind->sapi, hello_ind->api_version);
	else	/* Accept whatever version by default: */
		rc = hello_ind->api_version;

	if (rc < 0) {
		LOGSRV(prim_srv, LOGL_ERROR,
		       "SAPI=%u API_VERSION=%u not supported! destroying connection\n",
		       hello_ind->sapi, hello_ind->api_version);
		osmo_stream_srv_set_flush_and_destroy(prim_srv->stream);
		return rc;
	}
	prim_resp = _sap_ctl_makeprim_hello_cnf(hello_ind->sapi, (uint16_t)rc);
	LOGSRV(prim_srv, LOGL_INFO, "Tx CTL-HELLO.cnf SAPI=%u API_VERSION=%u\n",
	       hello_ind->sapi, prim_resp->u.hello_cnf.api_version);
	rc = osmo_prim_srv_send(prim_srv, prim_resp->hdr.msg);
	return rc;
}

static int _srv_sap_ctl_rx(struct osmo_prim_srv *prim_srv, struct osmo_prim_hdr *oph)
{
	switch (oph->operation) {
	case PRIM_OP_REQUEST:
		switch (oph->primitive) {
		case SAP_CTL_PRIM_HELLO:
			return _srv_sap_ctl_rx_hello_req(prim_srv, (struct sap_ctl_hello_param *)msgb_data(oph->msg));
		default:
			LOGSRV(prim_srv, LOGL_ERROR, "Rx unknown CTL SAP primitive %u (len=%u)\n",
			     oph->primitive, msgb_length(oph->msg));
			return -EINVAL;
		}
		break;
	case PRIM_OP_RESPONSE:
	case PRIM_OP_INDICATION:
	case PRIM_OP_CONFIRM:
	default:
		LOGSRV(prim_srv, LOGL_ERROR, "Rx CTL SAP unexpected primitive operation %s-%s (len=%u)\n",
		     get_value_string(sap_ctl_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg));
		return -EINVAL;
	}
}

static int _osmo_prim_srv_read_cb(struct osmo_stream_srv *srv)
{
	struct osmo_prim_srv *prim_srv = osmo_stream_srv_get_data(srv);
	struct osmo_prim_pkt_hdr *pkth;
	struct msgb *msg;
	struct osmo_prim_hdr oph;
	int rc;

	msg = msgb_alloc_c(prim_srv, sizeof(*pkth) + prim_srv->link->rx_msgb_alloc_len,
			   "osmo_prim_srv_link_rx");
	if (!msg)
		return -ENOMEM;
	rc = osmo_stream_srv_recv(srv, msg);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN) {
			msgb_free(msg);
			return 0;
		}
		goto close;
	}

	if (rc < sizeof(*pkth)) {
		LOGSRV(prim_srv, LOGL_ERROR, "Received %d bytes on UD Socket, but primitive hdr size "
		     "is %zu, discarding\n", rc, sizeof(*pkth));
		msgb_free(msg);
		return 0;
	}
	pkth = (struct osmo_prim_pkt_hdr *)msgb_data(msg);

	/* De-serialize message: */
	osmo_prim_init(&oph, pkth->sap, pkth->primitive, pkth->operation, msg);
	msgb_pull(msg, sizeof(*pkth));

	switch (oph.sap) {
	case OSMO_PRIM_CTL_SAPI:
		rc = _srv_sap_ctl_rx(prim_srv, &oph);
		break;
	default:
		if (prim_srv->link->rx_cb)
			rc = prim_srv->link->rx_cb(prim_srv, &oph);
		break;
	}
	/* as we always synchronously process the message in _osmo_prim_srv_link_rx() and
	 * its callbacks, we can free the message here. */
	msgb_free(msg);

	return rc;

close:
	msgb_free(msg);
	osmo_prim_srv_close(prim_srv);
	return -1;
}

static void osmo_prim_srv_free(struct osmo_prim_srv *prim_srv);
static int _osmo_prim_srv_closed_cb(struct osmo_stream_srv *srv)
{
	struct osmo_prim_srv *prim_srv = osmo_stream_srv_get_data(srv);
	struct osmo_prim_srv_link *prim_link = prim_srv->link;
	if (prim_link->closed_conn_cb)
		return prim_link->closed_conn_cb(prim_srv);
	osmo_prim_srv_free(prim_srv);
	return 0;
}

/*! Allocate a primitive of given type and its associated msgb.
*  \param[in] srv The osmo_prim_srv_link instance where message is to be sent through
*  \param[in] msg msgb containing osmo_prim_hdr plus extra content, allocated through \ref osmo_prim_msgb_alloc()
*  \returns zero on success, negative on error */
int osmo_prim_srv_send(struct osmo_prim_srv *prim_srv, struct msgb *msg)
{
	struct osmo_prim_hdr *oph;
	struct osmo_prim_pkt_hdr *pkth;
	unsigned int sap;
	unsigned int primitive;
	enum osmo_prim_operation operation;

	OSMO_ASSERT(prim_srv);

	/* Serialize the oph: */
	oph = (struct osmo_prim_hdr *)msgb_data(msg);
	OSMO_ASSERT(oph && msgb_length(msg) >= sizeof(*oph));
	sap = oph->sap;
	primitive = oph->primitive;
	operation = oph->operation;
	msgb_pull(msg, sizeof(*oph));
	pkth = (struct osmo_prim_pkt_hdr *)msgb_push(msg, sizeof(*pkth));
	pkth->sap = sap;
	pkth->primitive = primitive;
	pkth->operation = operation;

	/* Finally enqueue the msg */
	osmo_stream_srv_send(prim_srv->stream, msg);

	return 0;
}

static struct osmo_prim_srv *osmo_prim_srv_alloc(struct osmo_prim_srv_link *prim_link, int fd)
{
	struct osmo_prim_srv *prim_srv;
	prim_srv = talloc_zero(prim_link, struct osmo_prim_srv);
	if (!prim_srv)
		return NULL;
	prim_srv->link = prim_link;
	prim_srv->stream = osmo_stream_srv_create(prim_link, prim_link->stream, fd,
					     _osmo_prim_srv_read_cb,
					     _osmo_prim_srv_closed_cb,
					     prim_srv);
	if (!prim_srv->stream) {
		talloc_free(prim_srv);
		return NULL;
	}
	/* Inherit link priv pointer by default, user can later set it through API: */
	prim_srv->priv = prim_link->priv;
	return prim_srv;
}

static void osmo_prim_srv_free(struct osmo_prim_srv *prim_srv)
{
	talloc_free(prim_srv);
}

void osmo_prim_srv_set_name(struct osmo_prim_srv *prim_srv, const char *name)
{
	osmo_stream_srv_set_name(prim_srv->stream, name);
}

struct osmo_prim_srv_link *osmo_prim_srv_get_link(struct osmo_prim_srv *prim_srv)
{
	return prim_srv->link;
}

void osmo_prim_srv_set_priv(struct osmo_prim_srv *prim_srv, void *priv)
{
	prim_srv->priv = priv;
}

void *osmo_prim_srv_get_priv(const struct osmo_prim_srv *prim_srv)
{
	return prim_srv->priv;
}

void osmo_prim_srv_close(struct osmo_prim_srv *prim_srv)
{
	osmo_stream_srv_destroy(prim_srv->stream);
	/* we free prim_srv in _osmo_prim_srv_closed_cb() */
}

/******************************
 * osmo_prim_srv_link
 ******************************/

#define LOGSRVLINK(srv, lvl, fmt, args...) LOGP((srv)->log_cat, lvl, fmt, ## args)

/* accept connection coming from PCU */
static int _osmo_prim_srv_link_accept(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_prim_srv *prim_srv;
	struct osmo_prim_srv_link *prim_link = osmo_stream_srv_link_get_data(link);

	prim_srv = osmo_prim_srv_alloc(prim_link, fd);

	if (prim_link->opened_conn_cb)
		return prim_link->opened_conn_cb(prim_srv);

	return 0;
}

struct osmo_prim_srv_link *osmo_prim_srv_link_alloc(void *ctx)
{
	struct osmo_prim_srv_link *prim_link;
	prim_link = talloc_zero(ctx, struct osmo_prim_srv_link);
	if (!prim_link)
		return NULL;
	prim_link->stream = osmo_stream_srv_link_create(prim_link);
	if (!prim_link->stream) {
		talloc_free(prim_link);
		return NULL;
	}
	osmo_stream_srv_link_set_data(prim_link->stream, prim_link);
	osmo_stream_srv_link_set_domain(prim_link->stream, AF_UNIX);
	osmo_stream_srv_link_set_type(prim_link->stream, SOCK_SEQPACKET);
	osmo_stream_srv_link_set_accept_cb(prim_link->stream, _osmo_prim_srv_link_accept);

	prim_link->log_cat = DLGLOBAL;
	prim_link->rx_msgb_alloc_len = 1600 - sizeof(struct osmo_prim_pkt_hdr);
	return prim_link;
}

void osmo_prim_srv_link_free(struct osmo_prim_srv_link *prim_link)
{
	if (!prim_link)
		return;

	if (prim_link->stream) {
		osmo_stream_srv_link_close(prim_link->stream);
		osmo_stream_srv_link_destroy(prim_link->stream);
		prim_link->stream = NULL;
	}
	talloc_free(prim_link);
}

void osmo_prim_srv_link_set_name(struct osmo_prim_srv_link *prim_link, const char *name)
{
	osmo_stream_srv_link_set_name(prim_link->stream, name);
}

int osmo_prim_srv_link_set_addr(struct osmo_prim_srv_link *prim_link, const char *path)
{
	osmo_talloc_replace_string(prim_link, &prim_link->addr, path);
	osmo_stream_srv_link_set_addr(prim_link->stream, path);
	return 0;
}

const char *osmo_prim_srv_link_get_addr(struct osmo_prim_srv_link *prim_link)
{
	return prim_link->addr;
}

void osmo_prim_srv_link_set_priv(struct osmo_prim_srv_link *prim_link, void *priv)
{
	prim_link->priv = priv;
}

void *osmo_prim_srv_link_get_priv(const struct osmo_prim_srv_link *prim_link)
{
	return prim_link->priv;
}

void osmo_prim_srv_link_set_log_category(struct osmo_prim_srv_link *prim_link, int log_cat)
{
	prim_link->log_cat = log_cat;
}

void osmo_prim_srv_link_set_opened_conn_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_conn_cb opened_conn_cb)
{
	prim_link->opened_conn_cb = opened_conn_cb;
}
void osmo_prim_srv_link_set_closed_conn_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_conn_cb closed_conn_cb)
{
	prim_link->closed_conn_cb = closed_conn_cb;
}

void osmo_prim_srv_link_set_rx_sapi_version_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_rx_sapi_version rx_sapi_version_cb)
{
	prim_link->rx_sapi_version_cb = rx_sapi_version_cb;
}

void osmo_prim_srv_link_set_rx_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_rx_cb rx_cb)
{
	prim_link->rx_cb = rx_cb;
}

void osmo_prim_srv_link_set_rx_msgb_alloc_len(struct osmo_prim_srv_link *prim_link, size_t alloc_len)
{
	prim_link->rx_msgb_alloc_len = alloc_len;
}

int osmo_prim_srv_link_open(struct osmo_prim_srv_link *prim_link)
{
	int rc;

	if (!prim_link->addr) {
		LOGSRVLINK(prim_link, LOGL_ERROR, "Cannot open, Address not configured\n");
		return -1;
	}

	rc = osmo_stream_srv_link_open(prim_link->stream);

	LOGSRVLINK(prim_link, LOGL_INFO, "Started listening on Lower Layer Unix Domain Socket: %s\n", prim_link->addr);

	return rc;
}
