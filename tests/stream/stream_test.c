/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH.
 * Author: Max Suraev
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
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
		printf("{%lu.%06lu} [%s] Client's %s(): " fmt, tv.tv_sec, tv.tv_usec, \
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
		printf("{%lu.%06lu} [%s|%s] Server's %s(): " fmt,  tv.tv_sec, tv.tv_usec, \
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

	return 0;
}


static void test_recon(void *ctx, const char *host, unsigned port, unsigned steps, struct osmo_stream_srv_link *lnk,
		       bool autoreconnect)
{
	struct timeval tv;
	struct osmo_stream_cli *cli = make_client(ctx, host, port, autoreconnect);
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
			tv.tv_sec, tv.tv_usec, ASTR(autoreconnect), steps,
			osmo_stream_cli_get_data(cli) ? "OK" : "NA",
			osmo_stream_srv_link_get_data(lnk) ? "OK" : "NA",
			osmo_fd_is_registered(osmo_stream_cli_get_ofd(cli)));

		if (test_stop_requested(lnk)) {
			printf("{%lu.%06lu} Server requested test termination\n",
			       tv.tv_sec, tv.tv_usec);
			steps = 0;
		}
	}

	osmo_stream_cli_destroy(cli);
	printf("{%lu.%06lu} %s test complete.\n\n", tv.tv_sec, tv.tv_usec, ASTR(autoreconnect));
}

struct ipa_head {
	uint16_t len;
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

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
#define IPAC_MSG_ID_REQ_LEN 0x03
static const uint8_t ipac_msg_idreq[] = {
	0x00, IPAC_MSG_PING_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSGT_ID_GET,
	0x01, IPAC_IDTAG_UNITNAME
};
#define ipac_msg_idreq_half (sizeof (ipac_msg_idreq)/2)
#define ipac_msg_idreq_other_half (sizeof (ipac_msg_idreq) - ipac_msg_idreq_half)
#define IPAC_MSG_ID_RESP_LEN 0x07
static const uint8_t ipac_msg_idresp[] = {
	0x00, IPAC_MSG_PING_LEN,
	IPAC_PROTO_IPACCESS,
	IPAC_MSGT_ID_RESP,
	0x01, IPAC_IDTAG_UNITNAME, 0xde, 0xad, 0xbe, 0xef
};

#define put_ipa_msg(unsigned_char_ptr, struct_msgb_ptr, byte_array) do {\
	(unsigned_char_ptr) = msgb_put(struct_msgb_ptr, sizeof (byte_array));\
	memcpy(unsigned_char_ptr, byte_array, sizeof (byte_array));\
} while (0)

static int test_segmentation_cli_connect_cb(struct osmo_stream_cli *cli)
{
	printf("Connect callback triggered (segmentation test)\n");

	unsigned char *data;
	void *recon = osmo_stream_cli_get_data(cli);
	struct msgb *m = msgb_alloc_headroom(128, 0, "IPA messages");
	if (m == NULL) {
		fprintf(stderr, "Cannot allocate message\n");
		return -ENOMEM;
	}

	/* Send 4 and 1/2 messages */
	put_ipa_msg(data, m, ipac_msg_ping);
	put_ipa_msg(data, m, ipac_msg_pong);
	put_ipa_msg(data, m, ipac_msg_idreq);
	put_ipa_msg(data, m, ipac_msg_idresp);
	data = msgb_put(m, ipac_msg_idreq_half);
	memcpy(data, ipac_msg_idreq, ipac_msg_idreq_half);
	osmo_stream_cli_send(cli, m);

	if (recon) {
		printf("Closing connection\n");
		osmo_stream_cli_close(cli);
	} else
		printf("Connect callback\n");

	return 0;
}

static int ipa_process_msg(struct msgb *msg)
{
	struct ipa_head *h = (struct ipa_head *)msg->data;
	int len;
	size_t ipa_msg_len = osmo_ntohs(h->len);
	if (msg->len < sizeof (struct ipa_head)) {
		fprintf(stderr, "IPA message too small\n");
		return -EIO;
	}
	len = sizeof (struct ipa_head) + ipa_msg_len;
	if (len > msg->len) {
		fprintf(stderr, "Bad IPA message header "
				"hdrlen=%u < datalen=%u\n",
			len, msg->len);
		return -EIO;
	}
	/* msg->l2h = msg->data + sizeof (struct ipa_head); */
	return 0;
}

/* Array indices correspond to enum values stringified on the right */
static const char *IPAC_MSG_TYPES[] = {
	[0] = "IPAC_MSGT_PING",
	[1] = "IPAC_MSGT_PONG",
	[2] = "UNEXPECTED VALUE",
	[3] = "UNEXPECTED VALUE",
	[4] = "IPAC_MSGT_ID_GET",
	[5] = "IPAC_MSGT_ID_RESP",
};

static bool all_msgs_sent = false;

static int test_segmentation_stream_cli_read_cb(struct osmo_stream_cli *osc, struct msgb *m)
{
	unsigned char *data;
	struct ipa_head *h = (struct ipa_head *) m->data;
	int rc;
	uint8_t ipa_msg_type = h->data[0];
	if ((rc = ipa_process_msg(m)) < 0)
		return rc;
	printf("Received message from stream (len=%" PRIu16 ")\n", msgb_length(m));
	if (ipa_msg_type < 0 || 5 < ipa_msg_type) {
		fprintf(stderr, "Received message from stream (len=%" PRIu16 ")\n",
			msgb_length(m));
		return -ENOMSG;
	}
	printf("Type: %s\n", IPAC_MSG_TYPES[ipa_msg_type]);
	if (ipa_msg_type == IPAC_MSGT_ID_GET) {
		printf("Got back IPAC_MSGT_ID_GET from server."
		       "Sending second half of IPAC_MSGT_ID_RESP\n");
		data = msgb_put(m, ipac_msg_idreq_other_half);
		memcpy(data, ipac_msg_idreq + ipac_msg_idreq_other_half,
		       ipac_msg_idreq_other_half);
		osmo_stream_cli_send(osc, m);
		all_msgs_sent = true;
	} else if (ipa_msg_type == IPAC_MSGT_ID_RESP) {
		printf("result=  %s\n", osmo_hexdump(m->data, m->len));
		printf("expected=%s\n",
		       osmo_hexdump(ipac_msg_idresp, sizeof(ipac_msg_idresp)));
	}
	return 0;
}

static void *test_segmentation_run_client()
{
	struct osmo_stream_cli *osc;
	struct timespec start, now;
	int rc;
	void *ctx = talloc_named_const(NULL, 0, "test_segmentation_run_client");

	(void) msgb_talloc_ctx_init(ctx, 0);
	osc = osmo_stream_cli_create_iofd(ctx, "IPA test client");
	if (osc == NULL) {
		fprintf(stderr, "osmo_stream_cli_create_iofd()\n");
		return NULL;
	}
	osmo_stream_cli_set_addr(osc, "127.0.0.11");
	osmo_stream_cli_set_port(osc, 1111);
	osmo_stream_cli_set_connect_cb(osc, test_segmentation_cli_connect_cb);
	osmo_stream_cli_set_data(osc, ctx);
	osmo_stream_cli_set_iofd_read_cb(osc, test_segmentation_stream_cli_read_cb);
	osmo_stream_cli_set_nodelay(osc, true);
	if (osmo_stream_cli_open(osc) < 0) {
		fprintf(stderr, "Cannot open stream client\n");
		return NULL;
	}

	rc = clock_gettime(CLOCK_MONOTONIC, &start);
	if (rc < 0) {
		fprintf(stderr, "clock_gettime(): %s\n", strerror(errno));
		return NULL;
	}
	// int tdiff_secs = 0;
	// while (!all_msgs_sent && tdiff_secs < 1) {
	// for (; !all_msgs_sent;);

	return NULL; // Adapt?
}

static void test_segmentation_ipa(void *ctx, const char *host, unsigned port,
				  struct osmo_stream_srv_link *srv)
{
	int rc;
	struct timespec start, now;
	osmo_stream_srv_link_set_stream_proto(srv, OSMO_STREAM_IPAC);
	osmo_stream_srv_link_set_data(srv, ctx);
	pthread_t pt;
	test_segmentation_run_client();
	// rc = pthread_create(&pt, NULL, test_segmentation_run_client, (void *)srv);
	// if (rc != 0) {
	// 	fprintf(stderr, "pthread_create(): %s\n", strerror(errno));
	// 	return;
	// }

	rc = clock_gettime(CLOCK_MONOTONIC, &start);
	if (rc < 0) {
		fprintf(stderr, "clock_gettime(): %s\n", strerror(errno));
		return;
	}
	int tdiff_secs = 0;
	// while (!all_msgs_sent && tdiff_secs < 1) {
	while (!all_msgs_sent) {
		osmo_gettimeofday_override_add(0, 1); /* small increment to easily spot iterations */
		osmo_select_main(0);
		rc = clock_gettime(CLOCK_MONOTONIC, &now);
		if (rc < 0) {
			fprintf(stderr, "clock_gettime(): %s\n", strerror(errno));
			return;
		}
		tdiff_secs = now.tv_sec - start.tv_sec;
	}

	osmo_stream_srv_link_unset_stream_proto(srv);
	return;
}

int test_segmentation_stream_srv_read_cb(struct osmo_stream_srv *conn, struct msgb *msg)
{
	LOGP(DSTREAMTEST, LOGL_DEBUG, "received message from stream (len=%d)\n", msgb_length(msg));
	ipa_process_msg(msg);
	osmo_stream_srv_send(conn, msg);
	return 0;
}


static int test_segmentation_stream_srv_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	void *ctx = talloc_named_const(NULL, 0, "test_segmentation_stream_srv_accept_cb");
	struct osmo_stream_srv *oss =
		osmo_stream_srv_create_iofd(ctx, "srv link", srv, fd,
					    test_segmentation_stream_srv_read_cb,
					    close_cb_srv, NULL);
	if (oss == NULL) {
		fprintf(stderr, "Error while creating connection\n");
		return -1;
	}

	return 0;
}

int main(void)
{
	struct osmo_stream_srv_link *srv;
	char *host = "127.0.0.11";
	unsigned port = 1111;
	void *tall_test = talloc_named_const(NULL, 1, "osmo_stream_test");

	osmo_gettimeofday_override = true;
	osmo_gettimeofday_override_time.tv_sec = 2;
	osmo_gettimeofday_override_time.tv_usec = 0;

	msgb_talloc_ctx_init(tall_test, 0);
	osmo_init_logging2(tall_test, &osmo_stream_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
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

	osmo_stream_srv_link_set_addr(srv, host);
	osmo_stream_srv_link_set_port(srv, port);
	osmo_stream_srv_link_set_accept_cb(srv, accept_cb_srv);

	if (osmo_stream_srv_link_open(srv) < 0) {
		printf("Unable to open server\n");
		return EXIT_FAILURE;
	}

	test_recon(tall_test, host, port, 12, srv, true);
	test_recon(tall_test, host, port, 8, srv, false);
	osmo_stream_srv_link_destroy(srv);

	osmo_stream_srv_link_set_accept_cb(srv,
		test_segmentation_stream_srv_accept_cb);
	test_segmentation_ipa(tall_test, host, port, srv);


	printf("Stream tests completed\n");

	return EXIT_SUCCESS;
}
