/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH.
 * Authors: Max Suraev
 *	    Alexander Rehbein
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <osmocom/netif/ipa.h>
#include <osmocom/netif/stream.h>

#define RECONNECT_TIMEOUT_SECS 9

#define DSTREAMTEST 0
struct log_info_cat osmo_stream_test_cat[] = {
	[DSTREAMTEST] = {
		.name = "DSTREAMTEST",
		.description = "STREAM test",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
};

const struct log_info osmo_stream_test_log_info = {
	.filter_fn = NULL,
	.cat = osmo_stream_test_cat,
	.num_cat = ARRAY_SIZE(osmo_stream_test_cat),
};

static struct msgb *make_msgb(const char *m)
{
	struct msgb *msg = msgb_alloc(512, "STREAM test");
	if (!msg) {
		printf("Unable to allocate message\n");
		return NULL;
	}

	if (m)
		msgb_printf(msg, "%s", m);

	return msg;
}

#define ASTR(rec) ((rec) ? "autoreconnecting" : "non-reconnecting")

/* client defs */
#define LOGCLI(cli, fmt, args...) do { \
		struct timeval tv; \
		osmo_gettimeofday(&tv, NULL); \
		printf("{%lu.%06lu} [%s] Client's %s(): " fmt, \
		       (unsigned int long) tv.tv_sec, (unsigned int long) tv.tv_usec, \
		       osmo_stream_cli_get_data(cli) ? "OK" : "NA", __func__, ##args); \
	} while (0)

#define CLI_SND(cli, m) do {						\
		struct msgb *msg = make_msgb(m);			\
		LOGCLI(cli, "sent %d bytes message: %s\n",		\
		       msg->len, msgb_hexdump(msg));			\
		osmo_stream_cli_send(cli, msg);				\
	} while(0)

/* client callbacks */
static int connect_cb_cli(struct osmo_stream_cli *cli)
{
	void *recon = osmo_stream_cli_get_data(cli);
	LOGCLI(cli, "callback triggered <%s>\n", recon ? "reconnected" : "initial");
	if (recon) {
		LOGCLI(cli, "closing connection\n");
		osmo_stream_cli_close(cli);
	} else
		CLI_SND(cli, "Hi! from connect callback :-P");

	return 0;
}

static int read_cb_cli(struct osmo_stream_cli *cli)
{
	int bytes;
	void *cli_data = osmo_stream_cli_get_data(cli);
	struct msgb *msg = make_msgb(NULL);
	if (!msg)
		return -ENOMEM;

	LOGCLI(cli, "callback triggered\n");

	bytes = osmo_stream_cli_recv(cli, msg);
	if (bytes < 0) {
		LOGCLI(cli, "unable to receive message\n");
		return -EINVAL;
	}

	if (bytes)
		LOGCLI(cli, "received %d(%d) bytes: %s\n", bytes, msg->len, msgb_hexdump(msg));
	else {
		/* N. B: normally receiving 0 bytes means that we should close the connection and re-establish it
		   but to test autoreconnection logic we ignore it in here to let the test run till completion */
		LOGCLI(cli, "0-byte read, auto-reconnect will be triggered if enabled\n");
		osmo_gettimeofday_override_add(RECONNECT_TIMEOUT_SECS, 0);
	}

	if (!cli_data) {
		LOGCLI(cli, "initial read, contacting server\n");

		osmo_stream_cli_set_data(cli, msg);
		CLI_SND(cli, "Doh, responding to server :-D");
	}
	msgb_free(msg);

	return 0;
}

/* client helpers */
static struct osmo_stream_cli *init_client_reconnection(struct osmo_stream_cli *cli, bool autoreconnect)
{
	/* setting negative timeout ensures that we disable reconnection logic */
	osmo_stream_cli_set_reconnect_timeout(cli, autoreconnect ? RECONNECT_TIMEOUT_SECS : -1);

	if (osmo_stream_cli_open(cli) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}

/* Without explicit timeout set with osmo_stream_cli_set_reconnect_timeout() default value is used.
static struct osmo_stream_cli *init_client_reconnection_broken1(struct osmo_stream_cli *cli, bool autoreconnect)
{
	if (osmo_stream_cli_open2(cli, autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}
That's why those those functions result in exact the same output despite inverse use of autoreconnect parameter.
static struct osmo_stream_cli *init_client_reconnection_broken2(struct osmo_stream_cli *cli, bool autoreconnect)
{
	if (osmo_stream_cli_open2(cli, !autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}

Variant below are also equivalent to each other.
static struct osmo_stream_cli *init_client_reconnection_broken1(struct osmo_stream_cli *cli, bool autoreconnect)
{
	osmo_stream_cli_set_reconnect_timeout(cli, (!autoreconnect) ? 2 : -1);
	if (osmo_stream_cli_open2(cli, autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}

static struct osmo_stream_cli *init_client_reconnection_broken2(struct osmo_stream_cli *cli, bool autoreconnect)
{
	osmo_stream_cli_set_reconnect_timeout(cli, (!autoreconnect) ? 2 : -1);
	if (osmo_stream_cli_open2(cli, !autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}
Note: the result differs from normal init_client_reconnection()
*/

/* Setting reconnection value explicitly as follows is equivalent to normal init_client_reconnection()
static struct osmo_stream_cli *init_client_reconnection_broken1(struct osmo_stream_cli *cli, bool autoreconnect)
{
	osmo_stream_cli_set_reconnect_timeout(cli, autoreconnect ? 2 : -1);
	if (osmo_stream_cli_open2(cli, autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}

static struct osmo_stream_cli *init_client_reconnection_broken2(struct osmo_stream_cli *cli, bool autoreconnect)
{
	osmo_stream_cli_set_reconnect_timeout(cli, autoreconnect ? 2 : -1);
	if (osmo_stream_cli_open2(cli, !autoreconnect) < 0) {
		LOGCLI(cli, "unable to open client\n");
		return NULL;
	}

	return cli;
}
*/

static struct osmo_stream_cli *make_client(void *ctx, const char *host, unsigned port, bool autoreconnect)
{
	struct osmo_stream_cli *cli = osmo_stream_cli_create(ctx);
	if (!cli) {
		printf("Unable to create client\n");
		return NULL;
	}

	printf("Prepare %s stream client...\n", ASTR(autoreconnect));

	osmo_stream_cli_set_local_port(cli, 8976);
	osmo_stream_cli_set_name(cli, "cli_test");
	osmo_stream_cli_set_addr(cli, host);
	osmo_stream_cli_set_port(cli, port);
	osmo_stream_cli_set_connect_cb(cli, connect_cb_cli);
	osmo_stream_cli_set_read_cb(cli, read_cb_cli);

	/* using
	   return init_client_reconnection_broken1(cli, autoreconnect);
	   or
	   return init_client_reconnection_broken2(cli, autoreconnect);
	   will result in exactly the same output which might or might not be the same as with
	   init_client_reconnection() - see preceeding notes */
	return init_client_reconnection(cli, autoreconnect);
}

/* server defs */
#define LOGLNK(lnk, fmt, args...) \
	printf("[%s] Server's %s(): " fmt, osmo_stream_srv_link_get_data(lnk) ? "OK" : "NA", __func__, ##args)

#define LOGSRV(srv, fmt, args...) do { \
		struct timeval tv; \
		osmo_gettimeofday(&tv, NULL); \
		printf("{%lu.%06lu} [%s|%s] Server's %s(): " fmt, \
		       (unsigned int long) tv.tv_sec, (unsigned int long) tv.tv_usec, \
		       osmo_stream_srv_get_data(srv) ? "OK" : "NA", \
		       osmo_stream_srv_link_get_data(osmo_stream_srv_get_master(srv)) ? "OK" : "NA", \
		       __func__, ##args); \
	} while (0)

#define SRV_SND(srv, m) do {						\
		struct msgb *msg = make_msgb(m);			\
		LOGSRV(srv, "sent %d bytes message: %s\n",		\
		       msg->len, msgb_hexdump(msg));			\
		osmo_stream_srv_send(srv, msg);				\
	} while(0)

/* server helpers */
static bool subsequent_read(struct osmo_stream_srv *srv)
{
	if (osmo_stream_srv_get_data(srv))
		return true;

	osmo_stream_srv_set_data(srv, srv);

	return false;
}

static void request_test_stop(struct osmo_stream_srv *srv)
{
	osmo_stream_srv_link_set_data(osmo_stream_srv_get_master(srv), NULL);
}

static bool test_stop_requested(struct osmo_stream_srv_link *lnk)
{
	if (osmo_stream_srv_link_get_data(lnk))
		return false;
	return true;
}

/* server callbacks */
int read_cb_srv(struct osmo_stream_srv *srv)
{
	int bytes;
	struct msgb *msg = make_msgb(NULL);
	if (!msg)
		return -ENOMEM;

	LOGSRV(srv, "callback triggered\n");

	bytes = osmo_stream_srv_recv(srv, msg);
	if (bytes <= 0) {
		if (bytes < 0)
			LOGSRV(srv, "unable to receive message: %s\n", strerror(-bytes));
		else {
			LOGSRV(srv, "client have already closed connection\n");

			/* if client have already closed the connection,
			   than it must be subsequent (after reconnect) call */
			request_test_stop(srv);
		}
		msgb_free(msg);
		osmo_stream_srv_destroy(srv);
		return -EINVAL;
	} else {
		LOGSRV(srv, "received %d(%d) bytes: %s\n", bytes, msg->len, msgb_hexdump(msg));
		SRV_SND(srv, __func__);
	}

	msgb_free(msg);

	if (subsequent_read(srv)) {
		LOGSRV(srv, "force client disconnect on subsequent call\n");
		osmo_stream_srv_destroy(srv);
	} else
		LOGSRV(srv, "keep initial client connection\n");

	return 0;
}

static int close_cb_srv(struct osmo_stream_srv *ignored)
{
	return 0;
}

static int accept_cb_srv(struct osmo_stream_srv_link *lnk, int fd)
{
	struct osmo_stream_srv *srv = osmo_stream_srv_create(osmo_stream_srv_link_get_data(lnk), lnk, fd,
							     read_cb_srv, close_cb_srv, NULL);
	if (!srv) {
		LOGLNK(lnk, "error while creating connection\n");
		return -EINVAL;
	}
	osmo_stream_srv_set_name(srv, "srv_test");

	return 0;
}


static void test_recon(void *ctx, const char *host, unsigned port, unsigned steps, struct osmo_stream_srv_link *lnk,
		       bool autoreconnect)
{
	struct timeval tv;
	struct osmo_stream_cli *cli;
	if (osmo_stream_srv_link_open(lnk) < 0) {
		printf("Unable to open server\n");
		osmo_stream_srv_link_destroy(lnk);
		return;
	}
	cli = make_client(ctx, host, port, autoreconnect);
	if (!cli)
		return;


	printf("=======================================\n");
	printf("Client/Server entering %s event loop...\n", ASTR(autoreconnect));
	printf("=======================================\n");

	osmo_stream_srv_link_set_data(lnk, ctx);

	while(steps--) {
		osmo_gettimeofday_override_add(0, 1); /* small increment to easily spot iterations */
		osmo_select_main(0);
		osmo_gettimeofday(&tv, NULL);
		fprintf(stderr, "\n{%lu.%06lu} %s test step %u [client %s, server %s], FD reg %u\n",
			(unsigned int long) tv.tv_sec, (unsigned int long) tv.tv_usec,
			ASTR(autoreconnect), steps,
			osmo_stream_cli_get_data(cli) ? "OK" : "NA",
			osmo_stream_srv_link_get_data(lnk) ? "OK" : "NA",
			osmo_fd_is_registered(osmo_stream_cli_get_ofd(cli)));

		if (test_stop_requested(lnk)) {
			printf("{%lu.%06lu} Server requested test termination\n",
			       (unsigned int long) tv.tv_sec, (unsigned int long) tv.tv_usec);
			steps = 0;
		}
	}

	osmo_stream_cli_destroy(cli);
	osmo_stream_srv_link_close(lnk);
	printf("{%lu.%06lu} %s test complete.\n\n",
	       (unsigned int long) tv.tv_sec, (unsigned int long) tv.tv_usec,
	       ASTR(autoreconnect));
}

/* Segmentation test code (using IPA) */
#define IPAC_MSG_PING_LEN 0x01
static const uint8_t ipac_msg_ping[] = {
	0x00, IPAC_MSG_PING_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSGT_PING
};
#define IPAC_MSG_PONG_LEN 0x01
static const uint8_t ipac_msg_pong[] = {
	0x00, IPAC_MSG_PONG_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSGT_PONG
};
#define IPAC_MSG_IDREQ_PAYLOAD_INITIALIZER \
	IPAC_MSGT_ID_GET, \
	0x01, IPAC_IDTAG_UNITNAME
static const uint8_t ipac_msg_idreq_payload[] = {
	IPAC_MSG_IDREQ_PAYLOAD_INITIALIZER
};
#define IPAC_MSG_ID_REQ_LEN 0x03
static const uint8_t ipac_msg_idreq[] = {
	0x00, IPAC_MSG_ID_REQ_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSG_IDREQ_PAYLOAD_INITIALIZER
};
#define ipac_msg_idreq_third (sizeof(ipac_msg_idreq)/3)
#define ipac_msg_idreq_last_third (sizeof(ipac_msg_idreq) - 2 * ipac_msg_idreq_third)
#define IPAC_MSG_ID_RESP_LEN 0x07
static const uint8_t ipac_msg_idresp[] = {
	0x00, IPAC_MSG_ID_RESP_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSGT_ID_RESP,
	0x01, IPAC_IDTAG_UNITNAME, 0xde, 0xad, 0xbe, 0xef
};

#define put_ipa_msg(unsigned_char_ptr, struct_msgb_ptr, byte_array) do {\
	(unsigned_char_ptr) = msgb_put(struct_msgb_ptr, sizeof(byte_array));\
	memcpy(unsigned_char_ptr, byte_array, sizeof(byte_array));\
} while (0)

/* Array indices correspond to enum values stringified on the right */
static const char * const IPAC_MSG_TYPES[] = {
	[0] = "IPAC_MSGT_PING",
	[1] = "IPAC_MSGT_PONG",
	[2] = "UNEXPECTED VALUE",
	[3] = "UNEXPECTED VALUE",
	[4] = "IPAC_MSGT_ID_GET",
	[5] = "IPAC_MSGT_ID_RESP",
};

#define IPAC_MSGT_OFFSET 3
/* Append a message to UCHAR_PTR_DST. SRC_IPAC_MSG_BUF is expected to be a
 * buffer containing an IPA message of type IPAC_PROTO_ACCESS that is
 * syntactically correct up to offset 3 (IPAC_MSGT_OFFSET).
 * Uses a counter so that appended messages can be distinguished easily in the logs */
#define CLI_APPEND_MSG(OSMO_STREAM_CLI_PTR, UCHAR_PTR_DST, STRUCT_MSGB_PTR, SRC_IPAC_MSG_BUF) do {\
	LOGCLI(OSMO_STREAM_CLI_PTR, "[%u-cli] Appending msg of type %s into buffer\n",\
	       ++test_segm_ipa_stream_srv_msglognum_cli, IPAC_MSG_TYPES[SRC_IPAC_MSG_BUF[IPAC_MSGT_OFFSET]]);\
	LOGCLI(OSMO_STREAM_CLI_PTR, "\t(msg dump: %s)\n", osmo_hexdump(SRC_IPAC_MSG_BUF,\
	       sizeof(SRC_IPAC_MSG_BUF)));\
	put_ipa_msg(UCHAR_PTR_DST, STRUCT_MSGB_PTR, SRC_IPAC_MSG_BUF);\
} while (0)

static unsigned test_segm_ipa_stream_srv_msglognum_cli = 0;
static int test_segm_ipa_stream_srv_cli_connect_cb(struct osmo_stream_cli *cli)
{
	unsigned char *data;
	struct msgb *m = msgb_alloc_headroom(128, 0, "IPA messages");
	if (m == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return -ENOMEM;
	}

	/* Send 4 and 1/3 messages */
	/* Append 4 */
	CLI_APPEND_MSG(cli, data, m, ipac_msg_ping);
	CLI_APPEND_MSG(cli, data, m, ipac_msg_pong);
	CLI_APPEND_MSG(cli, data, m, ipac_msg_ping);
	CLI_APPEND_MSG(cli, data, m, ipac_msg_idresp);
	/* Append 1/3 */
	LOGCLI(cli, "[(0%u + 1/3)-cli] Appending 1st third of msg of type %s into buffer\n",
	       test_segm_ipa_stream_srv_msglognum_cli, IPAC_MSG_TYPES[ipac_msg_idreq[3]]);
	LOGCLI(cli, "\t(dump: %s)\n", osmo_hexdump(ipac_msg_idreq, ipac_msg_idreq_third));
	data = msgb_put(m, ipac_msg_idreq_third);
	memcpy(data, ipac_msg_idreq, ipac_msg_idreq_third);

	LOGCLI(cli, "Sending 4 + 1/3 messages as one:\n");
	LOGCLI(cli, "\t(msg dump: %s)\n\n", osmo_hexdump(m->data, m->len));
	osmo_stream_cli_send(cli, m);
	return 0;
}

static bool test_segm_ipa_stream_srv_all_msgs_processed = false;

static void send_last_third(void *osmo_stream_cli_arg)
{
	struct osmo_stream_cli *osc = osmo_stream_cli_arg;
	unsigned char *data;
	struct msgb *reply = msgb_alloc_headroom(128, 0, "IPA delayed reply");

	LOGCLI(osc, "Delay for sending last third of message is over\n");
	if (reply == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return;
	}
	LOGCLI(osc, "[%u-cli] Appending: Last third of IPAC_MSGT_ID_GET\n",
	       ++test_segm_ipa_stream_srv_msglognum_cli);
	data = msgb_put(reply, ipac_msg_idreq_last_third);
	memcpy(data, ipac_msg_idreq + 2 * ipac_msg_idreq_third,
	       ipac_msg_idreq_last_third);
	/* Append two entire messages */
	CLI_APPEND_MSG(osc, data, reply, ipac_msg_pong);
	CLI_APPEND_MSG(osc, data, reply, ipac_msg_pong);
	LOGCLI(osc, "\tSending:"
		    "[ Last third of IPAC_MSGT_ID_GET | IPAC_MSGT_PONG | IPAC_MSGT_PONG ]\n");
	LOGCLI(osc, "\t(msg dump: %s)\n\n", osmo_hexdump(reply->data, reply->len));
	osmo_stream_cli_send(osc, reply);
}

static struct osmo_timer_list fragmented_send_tl_cli;

static int test_segm_ipa_stream_srv_cli_read_cb(struct osmo_stream_cli *osc, int res, struct msgb *msg)
{
	unsigned char *data;
	struct ipa_head *h = (struct ipa_head *) msg->l1h;
	uint8_t ipac_msg_type = *msg->data;
	struct msgb *reply;

	if (res < 0) {
		fprintf(stderr, "cannot receive message (res = %d)\n", res);
		msgb_free(msg);
		return -ENOMSG;
	}

	LOGCLI(osc, "Received message from stream (payload len = %" PRIu16 ")\n", msgb_length(msg));
	if (5 < ipac_msg_type) {
		fprintf(stderr, "Received unexpected IPAC message type %"PRIu8"\n", ipac_msg_type);
		msgb_free(msg);
		return -ENOMSG;
	}
	LOGCLI(osc, "\tType: %s\n", IPAC_MSG_TYPES[ipac_msg_type]);
	if (ipac_msg_type == IPAC_MSGT_ID_GET) {
		LOGCLI(osc, "Got IPAC_MSGT_ID_GET from server\n");
		LOGCLI(osc, "[(%u + 2/3) -cli] Appending: Second third of IPAC_MSGT_ID_GET\n",
		       test_segm_ipa_stream_srv_msglognum_cli);
		reply = msgb_alloc_headroom(128, 0, "IPA reply");
		if (reply == NULL) {
			fprintf(stderr, "Cannot allocate message\n");
			return -ENOMEM;
		}
		data = msgb_put(reply, ipac_msg_idreq_third);
		memcpy(data, ipac_msg_idreq + ipac_msg_idreq_third,
		       ipac_msg_idreq_third);
		LOGCLI(osc, "\tSending: Second third of IPAC_MSGT_ID_GET\n");
		LOGCLI(osc, "\t(msg dump: %s)\n", osmo_hexdump(reply->data, reply->len));
		osmo_stream_cli_send(osc, reply);
		osmo_timer_setup(&fragmented_send_tl_cli, send_last_third, osc);
		osmo_timer_add(&fragmented_send_tl_cli);
		osmo_timer_schedule(&fragmented_send_tl_cli, 0, 500000);
	} else if (ipac_msg_type == IPAC_MSGT_ID_RESP) {
		LOGCLI(osc, "\tresult=  %s\n",
		       osmo_hexdump((const unsigned char *)h, sizeof(*h) + h->len));
		LOGCLI(osc, "\texpected=%s\n",
		       osmo_hexdump(ipac_msg_idresp, sizeof(ipac_msg_idresp)));
	}
	msgb_free(msg);
	printf("\n");
	return 0;
}

struct osmo_stream_cli *test_segm_ipa_stream_srv_run_client(void *ctx)
{
	struct osmo_stream_cli *osc = osmo_stream_cli_create(ctx);
	if (osc == NULL) {
		fprintf(stderr, "osmo_stream_cli_create_iofd()\n");
		return NULL;
	}
	osmo_stream_cli_set_addr(osc, "127.0.0.11");
	osmo_stream_cli_set_local_port(osc, 8977);
	osmo_stream_cli_set_port(osc, 1111);
	osmo_stream_cli_set_connect_cb(osc, test_segm_ipa_stream_srv_cli_connect_cb);
	osmo_stream_cli_set_read_cb2(osc, test_segm_ipa_stream_srv_cli_read_cb);
	osmo_stream_cli_set_nodelay(osc, true);
	if (osmo_stream_cli_open(osc) < 0) {
		fprintf(stderr, "Cannot open stream client\n");
		return NULL;
	}
	osmo_stream_cli_set_segmentation_cb(osc, osmo_ipa_segmentation_cb);

	return osc;
}

int test_segm_ipa_stream_srv_srv_read_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg)
{
	static unsigned msgnum_srv = 0;
	struct ipa_head *ih = (struct ipa_head *)msg->l1h;
	unsigned char *data;
	struct msgb *m;
	uint8_t msgt;

	if (res <= 0) {
		if (res < 0)
			LOGSRV(conn, "cannot receive message: %s\n", strerror(-res));
		else
			LOGSRV(conn, "client closed connection\n");
		msgb_free(msg);
		osmo_stream_srv_destroy(conn);
		return -EBADF;
	}

	LOGSRV(conn, "[%u-srv] Received IPA message from stream (payload len = %" PRIu16 ")\n",
	       ++msgnum_srv, msgb_length(msg));
	LOGSRV(conn, "\tmsg buff data (including stripped headers): %s\n",
	       osmo_hexdump((unsigned char *)ih, osmo_ntohs(ih->len) + sizeof(*ih)));
	LOGSRV(conn, "\tIPA payload: %s\n", osmo_hexdump(ih->data, osmo_ntohs(ih->len)));

	msgt = *msg->l2h; /* Octet right after IPA header */
	LOGSRV(conn, "\tType: %s\n", IPAC_MSG_TYPES[msgt]);
	LOGSRV(conn, "\t(msg dump: %s)\n", osmo_hexdump(msg->l1h, msg->len + sizeof(struct ipa_head)));

	msgb_free(msg);

	if (msgt == IPAC_MSGT_ID_RESP) { /*  */
		LOGSRV(conn, "Send IPAC_MSGT_ID_GET to trigger client to send next third\n\n");
		m = osmo_ipa_msg_alloc(128);
		if (m == NULL) {
			fprintf(stderr, "Cannot allocate message\n");
			return -ENOMEM;
		}
		put_ipa_msg(data, m, ipac_msg_idreq_payload);
		osmo_ipa_msg_push_headers(m, IPAC_PROTO_IPACCESS, -1);
		osmo_stream_srv_send(conn, m);
	} else if (msgnum_srv == 7 && msgt == IPAC_MSGT_PONG) {
		test_segm_ipa_stream_srv_all_msgs_processed = true;
		osmo_stream_srv_destroy(conn);
	}
	return 0;
}

static int test_segm_ipa_stream_srv_srv_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	void *ctx = osmo_stream_srv_link_get_data(srv);
	struct osmo_stream_srv *oss =
		osmo_stream_srv_create2(ctx, srv, fd, NULL);
	if (oss == NULL) {
		fprintf(stderr, "Error while creating connection\n");
		return -1;
	}
	osmo_stream_srv_set_segmentation_cb(oss, osmo_ipa_segmentation_cb);
	osmo_stream_srv_set_read_cb(oss, test_segm_ipa_stream_srv_srv_read_cb);
	return 0;
}

static void test_segm_ipa_stream_srv_run(void *ctx, const char *host, unsigned port,
				  struct osmo_stream_srv_link *srv)
{
	struct osmo_stream_cli *osc;
	const char *testname = "test_segm_ipa_stream_srv";
	osmo_stream_srv_link_set_accept_cb(srv,
		test_segm_ipa_stream_srv_srv_accept_cb);
	if (osmo_stream_srv_link_open(srv) < 0) {
		printf("Unable to open server\n");
		exit(1);
	}
	osc = test_segm_ipa_stream_srv_run_client(ctx);

	printf("______________________________________Running test %s______________________________________\n", testname);
	alarm(2);

	while (!test_segm_ipa_stream_srv_all_msgs_processed) {
		osmo_gettimeofday_override_add(0, 1); /* small increment to easily spot iterations */
		osmo_select_main(1);
	}
	alarm(0);
	printf("==================================Test %s complete========================================\n\n", testname);
	if (osc)
		osmo_stream_cli_destroy(osc);
	osmo_stream_srv_link_close(srv);
}

static void sigalarm_handler(int _foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

static struct osmo_timer_list fragmented_send_tl_srv;
static struct osmo_timer_list fragmented_send_tl_srv_destroy;

static unsigned test_segm_ipa_stream_cli_srv_msglognum = 0;

/* Like CLI_APPEND_MSG, but for server side */
#define SRV_APPEND_MSG(OSMO_STREAM_SRV_PTR, UCHAR_PTR_DST, STRUCT_MSGB_PTR, SRC_IPAC_MSG_BUF) do {\
	LOGSRV(OSMO_STREAM_SRV_PTR, "[%u-srv] Appending msg of type %s into buffer\n",\
		++test_segm_ipa_stream_cli_srv_msglognum, IPAC_MSG_TYPES[SRC_IPAC_MSG_BUF[IPAC_MSGT_OFFSET]]);\
	LOGSRV(OSMO_STREAM_SRV_PTR, "\t(msg dump: %s)\n", osmo_hexdump(SRC_IPAC_MSG_BUF,\
	       sizeof(SRC_IPAC_MSG_BUF)));\
	put_ipa_msg(UCHAR_PTR_DST, STRUCT_MSGB_PTR, SRC_IPAC_MSG_BUF);\
} while (0)

static void destroy_conn(void *osmo_stream_srv_arg)
{
	osmo_stream_srv_destroy(osmo_stream_srv_arg);
}

static void send_last_third_srv(void *osmo_stream_srv_arg)
{
	struct osmo_stream_srv *oss = osmo_stream_srv_arg;
	unsigned char *data;
	struct msgb *reply = msgb_alloc_headroom(128, 0, "IPA delayed reply");

	LOGSRV(oss, "Delay for sending last third of message is over\n");
	if (reply == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return;
	}
	LOGSRV(oss, "[%u-srv] Appending: Last third of IPAC_MSGT_ID_GET\n",
	       ++test_segm_ipa_stream_cli_srv_msglognum);
	data = msgb_put(reply, ipac_msg_idreq_last_third);
	memcpy(data, ipac_msg_idreq + 2 * ipac_msg_idreq_third,
	       ipac_msg_idreq_last_third);
	/* Append two entire messages */
	SRV_APPEND_MSG(oss, data, reply, ipac_msg_pong);
	SRV_APPEND_MSG(oss, data, reply, ipac_msg_pong);
	LOGSRV(oss, "\tSending:"
		    "[ Last third of IPAC_MSGT_ID_GET | IPAC_MSGT_PONG | IPAC_MSGT_PONG ]\n");
	LOGSRV(oss, "\t(msg dump: %s)\n\n", osmo_hexdump(reply->data, reply->len));
	osmo_stream_srv_send(oss, reply);
	osmo_timer_setup(&fragmented_send_tl_srv_destroy, destroy_conn, oss);
	osmo_timer_add(&fragmented_send_tl_srv_destroy);
	/* 2 select loop iterations needed, timing only 1 will leave the client side hanging while waiting
	 * to receive the last messages */
	osmo_timer_schedule(&fragmented_send_tl_srv_destroy, 0, 2);
}

int test_segm_ipa_stream_cli_srv_read_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg)
{
	unsigned char *data;
	struct ipa_head *h = (struct ipa_head *) msg->l1h;
	uint8_t ipa_msg_type;
	struct msgb *reply;

	if (res <= 0) {
		if (res < 0)
			LOGSRV(conn, "cannot receive message: %s\n", strerror(-res));
		else
			LOGSRV(conn, "client closed connection\n");
		msgb_free(msg);
		osmo_stream_srv_destroy(conn);
		return -EBADF;
	}

	ipa_msg_type = ((uint8_t *)h)[sizeof(struct ipa_head)];

	reply = msgb_alloc_headroom(128, 0, "IPA reply");
	if (reply == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return -ENOMEM;
	}
	LOGSRV(conn, "Received message from stream (total len including stripped headers = %zu)\n",
	       osmo_ntohs(h->len) + sizeof(*h));
	if (5 < ipa_msg_type) {
		fprintf(stderr, "Received unexpected IPAC message type %"PRIu8"\n", ipa_msg_type);
		return -ENOMSG;
	}
	LOGSRV(conn, "\tType: %s\n", IPAC_MSG_TYPES[ipa_msg_type]);
	if (ipa_msg_type == IPAC_MSGT_ID_GET) {
		LOGSRV(conn, "Got IPAC_MSGT_ID_GET from client\n");
		LOGSRV(conn, "[(%u + 2/3) -srv] Appending: Second third of IPAC_MSGT_ID_GET\n",
		       test_segm_ipa_stream_cli_srv_msglognum);
		data = msgb_put(reply, ipac_msg_idreq_third);
		memcpy(data, ipac_msg_idreq + ipac_msg_idreq_third,
		       ipac_msg_idreq_third);
		LOGSRV(conn, "\tSending: Second third of IPAC_MSGT_ID_GET\n");
		LOGSRV(conn, "\t(msg dump: %s)\n", osmo_hexdump(reply->data, reply->len));
		osmo_stream_srv_send(conn, reply);
		osmo_timer_setup(&fragmented_send_tl_srv, send_last_third_srv, conn);
		osmo_timer_add(&fragmented_send_tl_srv);
		osmo_timer_schedule(&fragmented_send_tl_srv, 0, 125000);
	} else if (ipa_msg_type == IPAC_MSGT_ID_RESP) {
		LOGSRV(conn, "\tresult=  %s\n",
		       osmo_hexdump((const unsigned char *)h, sizeof(*h) + h->len));
		LOGSRV(conn, "\texpected=%s\n",
		       osmo_hexdump(ipac_msg_idresp, sizeof(ipac_msg_idresp)));
	}
	printf("\n");
	return 0;
}

static int test_segm_ipa_stream_cli_srv_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	void *ctx = osmo_stream_srv_link_get_data(srv);
	struct osmo_stream_srv *oss =
		osmo_stream_srv_create2(ctx, srv, fd, NULL);
	unsigned char *data;
	struct msgb *m = msgb_alloc_headroom(128, 0, "IPA messages");
	if (oss == NULL) {
		fprintf(stderr, "Error while creating connection\n");
		return -1;
	}
	if (m == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return -ENOMEM;
	}
	osmo_stream_srv_set_segmentation_cb(oss, osmo_ipa_segmentation_cb);
	osmo_stream_srv_set_read_cb(oss, test_segm_ipa_stream_cli_srv_read_cb);

	/* Send 4 and 1/3 messages, as done analogously in test_segm_ipa_stream_srv_cli_connect_cb() */
	/* Append 4 */
	SRV_APPEND_MSG(oss, data, m, ipac_msg_ping);
	SRV_APPEND_MSG(oss, data, m, ipac_msg_pong);
	SRV_APPEND_MSG(oss, data, m, ipac_msg_ping);
	SRV_APPEND_MSG(oss, data, m, ipac_msg_idresp);
	/* Append 1/3 */
	LOGSRV(oss, "[(0%u + 1/3)-srv] Appending 1st third of msg of type %s into buffer\n",
	       test_segm_ipa_stream_cli_srv_msglognum, IPAC_MSG_TYPES[ipac_msg_idreq[3]]);
	LOGSRV(oss, "\t(dump: %s)\n", osmo_hexdump(ipac_msg_idreq, ipac_msg_idreq_third));
	data = msgb_put(m, ipac_msg_idreq_third);
	memcpy(data, ipac_msg_idreq, ipac_msg_idreq_third);

	LOGSRV(oss, "Sending 4 + 1/3 messages as one:\n");
	LOGSRV(oss, "\t(msg dump: %s)\n\n", osmo_hexdump(m->data, m->len));
	osmo_stream_srv_send(oss, m);
	return 0;
}

static bool test_segm_ipa_stream_cli_all_msgs_processed = false;

static int test_segm_ipa_stream_cli_cli_read_cb(struct osmo_stream_cli *osc, int res, struct msgb *msg)
{
	static unsigned msgnum_cli = 0;
	unsigned char *data;
	struct msgb *m;
	uint8_t *msgt = msg->data;
	LOGCLI(osc, "[%u-cli] Received message from stream (len = %" PRIu16 ")\n",
	       ++msgnum_cli, msgb_length(msg));
	LOGCLI(osc, "\tmsg buff data: %s\n", osmo_hexdump(msg->data, msg->len));
	LOGCLI(osc, "\tIPA payload: %s\n", osmo_hexdump(msg->data, msg->len));
	LOGCLI(osc, "\tType: %s\n", IPAC_MSG_TYPES[*msgt]);
	LOGCLI(osc, "\t(msg dump (including stripped headers): %s)\n",
	       osmo_hexdump(msg->l1h, sizeof(struct ipa_head) + msg->len));
	if (*msgt == IPAC_MSGT_ID_RESP) {
		LOGCLI(osc, "Send IPAC_MSGT_ID_GET to trigger server to send next third\n\n");
		m = msgb_alloc_headroom(128, sizeof(struct ipa_head) +
					     sizeof(struct ipa_head_ext), "IPA messages");
		if (m == NULL) {
			fprintf(stderr, "Cannot allocate message\n");
			return -ENOMEM;
		}
		put_ipa_msg(data, m, ipac_msg_idreq_payload);
		osmo_ipa_msg_push_headers(m, IPAC_PROTO_IPACCESS, -1);
		osmo_stream_cli_send(osc, m);
	} else if (msgnum_cli == 7 && *msgt == IPAC_MSGT_PONG) {
		test_segm_ipa_stream_cli_all_msgs_processed = true;
	}
	return 0;
}

static struct osmo_stream_cli *test_segm_ipa_stream_cli_run_client(void *ctx)
{
	struct osmo_stream_cli *osc = osmo_stream_cli_create(ctx);
	if (osc == NULL) {
		fprintf(stderr, "osmo_stream_cli_create_iofd()\n");
		return NULL;
	}
	osmo_stream_cli_set_addr(osc, "127.0.0.11");
	osmo_stream_cli_set_local_port(osc, 8977);
	osmo_stream_cli_set_port(osc, 1112);
	osmo_stream_cli_set_read_cb2(osc, test_segm_ipa_stream_cli_cli_read_cb);
	osmo_stream_cli_set_nodelay(osc, true);
	osmo_stream_cli_set_segmentation_cb(osc, osmo_ipa_segmentation_cb);
	if (osmo_stream_cli_open(osc) < 0) {
		fprintf(stderr, "Cannot open stream client\n");
		return NULL;
	}

	return osc;
}

static void test_segm_ipa_stream_cli_run(void *ctx, const char *host, unsigned port,
				  struct osmo_stream_srv_link *srv)
{
	const char *testname = "test_segm_ipa_stream_cli";
	struct osmo_stream_cli *osc = NULL;
	osmo_stream_srv_link_set_accept_cb(srv,
		test_segm_ipa_stream_cli_srv_accept_cb);
	osmo_stream_srv_link_set_port(srv, 1112);
	if (osmo_stream_srv_link_open(srv) < 0) {
		printf("Unable to open server\n");
		exit(1);
	}
	osc = test_segm_ipa_stream_cli_run_client(ctx);

	printf("______________________________________Running test %s______________________________________\n", testname);
	alarm(2);

	while (!test_segm_ipa_stream_cli_all_msgs_processed) {
		osmo_gettimeofday_override_add(0, 1); /* small increment to easily spot iterations */
		osmo_select_main(1);
	}
	alarm(0);
	printf("==================================Test %s complete========================================\n\n", testname);
	if (osc)
		osmo_stream_cli_destroy(osc);
	osmo_stream_srv_link_close(srv);
}

int main(void)
{

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	struct osmo_stream_srv_link *srv;
	char *host = "127.0.0.11";
	unsigned port = 1111;
	void *tall_test = talloc_named_const(NULL, 1, "osmo_stream_test");

	osmo_gettimeofday_override = true;
	osmo_gettimeofday_override_time.tv_sec = 2;
	osmo_gettimeofday_override_time.tv_usec = 0;

	osmo_init_logging2(tall_test, &osmo_stream_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);

	printf("Preparing stream server...\n");
	srv = osmo_stream_srv_link_create(tall_test);
	if (!srv) {
		printf("Unable to create server\n");
		return EXIT_FAILURE;
	}

	osmo_stream_srv_link_set_name(srv, "srv_link_test");
	osmo_stream_srv_link_set_addr(srv, host);
	osmo_stream_srv_link_set_port(srv, port);
	osmo_stream_srv_link_set_accept_cb(srv, accept_cb_srv);
	osmo_stream_srv_link_set_nodelay(srv, true);

	test_recon(tall_test, host, port, 12, srv, true);
	test_recon(tall_test, host, port, 8, srv, false);

	osmo_stream_srv_link_set_data(srv, tall_test);
	test_segm_ipa_stream_srv_run(tall_test, host, port, srv);
	test_segm_ipa_stream_cli_run(tall_test, host, port, srv);

	printf("Stream tests completed\n");

	osmo_stream_srv_link_destroy(srv);
	log_fini();
	talloc_free(tall_test);
	return EXIT_SUCCESS;
}
