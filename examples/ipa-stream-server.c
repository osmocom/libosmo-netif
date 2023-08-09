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

void sighandler(int foo)
{
	LOGP(DSTREAMTEST, LOGL_NOTICE, "closing STREAMSERVER.\n");
	exit(EXIT_SUCCESS);
}

int read_cb(struct osmo_stream_srv *conn, struct msgb *msg)
{
	LOGP(DSTREAMTEST, LOGL_DEBUG, "received message from stream (payload len=%d)\n", msgb_length(msg));

	osmo_ipa_stream_srv_send(conn, osmo_ipa_msgb_cb_proto(msg), osmo_ipa_msgb_cb_proto_ext(msg), msg);
	return 0;
}

static int close_cb(struct osmo_stream_srv *dummy)
{
	return 0;
}

static int accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct osmo_stream_srv *conn;
	conn = osmo_stream_srv_create2(tall_test, srv, fd, NULL);
	if (conn == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR,
			"error while creating connection\n");
		return -1;
	}
	osmo_stream_srv_set_read_cb(conn, read_cb);
	osmo_stream_srv_set_closed_cb(conn, close_cb);
	osmo_stream_srv_set_segmentation_cb(conn, osmo_ipa_segmentation_cb);

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
	osmo_stream_srv_link_set_name(srv, "ipa_link");

	if (osmo_stream_srv_link_open(srv) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DSTREAMTEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
