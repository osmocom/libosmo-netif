/* IPA stream srv example */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

static void *tall_test;

#define DSTREAMTEST 0

struct log_info_cat osmo_stream_srv_test_cat[] = {
	[DSTREAMTEST] = {
		.name = "DSTREAMTEST",
		.description = "STREAMSERVER-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info osmo_stream_srv_test_log_info = {
	.filter_fn = NULL,
	.cat = osmo_stream_srv_test_cat,
	.num_cat = ARRAY_SIZE(osmo_stream_srv_test_cat),
};

static struct osmo_stream_srv_link *srv;
static struct osmo_stream_srv *conn;

void sighandler(int foo)
{
	LOGP(DSTREAMTEST, LOGL_NOTICE, "closing STREAMSERVER.\n");
	exit(EXIT_SUCCESS);
}

int read_cb(struct osmo_stream_srv *conn, struct msgb *msg)
{
	LOGP(DSTREAMTEST, LOGL_DEBUG, "received message from stream (len=%d)\n", msgb_length(msg));

	if (osmo_ipa_process_msg(msg) < 0) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "Bad IPA message\n");
		msgb_free(msg);
		return 0;
	}

	osmo_stream_srv_send(conn, msg);
	return 0;
}

static int close_cb(struct osmo_stream_srv *dummy)
{
	conn = NULL;
	return 0;
}

static int accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	if (conn != NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "Sorry, this example only "
			"supports one client simultaneously\n");
		return -1;
	}

	conn = osmo_stream_srv_create_iofd(tall_test, "srv link", srv, fd,
				       read_cb, close_cb, NULL);
	if (conn == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR,
			"error while creating connection\n");
		return -1;
	}

	return 0;
}

int main(void)
{
	tall_test = talloc_named_const(NULL, 1, "osmo_stream_srv_test");
	msgb_talloc_ctx_init(tall_test, 0);
	osmo_init_logging2(tall_test, &osmo_stream_srv_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/*
	 * initialize stream srv.
	 */

	srv = osmo_stream_srv_link_create(tall_test);
	if (srv == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	osmo_stream_srv_link_set_addr(srv, "127.0.0.1");
	osmo_stream_srv_link_set_port(srv, 10000);
	osmo_stream_srv_link_set_accept_cb(srv, accept_cb);
	osmo_stream_srv_link_set_nodelay(srv, true);
	osmo_stream_srv_link_set_stream_proto(srv, OSMO_STREAM_IPAC);

	if (osmo_stream_srv_link_open(srv) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DSTREAMTEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
