/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH.
 * Author: Max Suraev
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/timer.h>

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
	osmo_stream_srv_set_name(srv, "srv_test");

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

	osmo_stream_srv_link_set_name(srv, "srv_link_test");
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
	printf("Stream tests completed\n");

	return EXIT_SUCCESS;
}
