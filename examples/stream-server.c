/* stream server example */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/stream.h>

static void *tall_test;

#define DSTREAMTEST 0

struct log_info_cat osmo_stream_srv_test_cat[] = {
	[DSTREAMTEST] = {
		.name = "DSTREAMTEST",
		.description = "STREAMSERVER-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
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
	LOGP(DSTREAMTEST, LOGL_NOTICE, "receiving message from stream... ");

	LOGPC(DSTREAMTEST, LOGL_NOTICE, "got %d bytes: %s\n", msg->len, msgb_hexdump(msg));

	msgb_free(msg);
	return 0;
}

static int close_cb(struct osmo_stream_srv *dummy)
{
	LOGPC(DSTREAMTEST, LOGL_ERROR, "client closed connection\n");
	conn = NULL;
	return 0;
}

static int accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	char buf[OSMO_SOCK_NAME_MAXLEN];

	if (conn != NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "Sorry, this example only "
			"support one client simultaneously\n");
		return -1;
	}

	conn = osmo_stream_srv_create2(tall_test, srv, fd, NULL);
	if (conn == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR,
			"error while creating connection\n");
		return -1;
	}
	osmo_stream_srv_set_name(conn, "stream_server");
	osmo_stream_srv_set_read_cb(conn, read_cb);
	osmo_stream_srv_set_closed_cb(conn, close_cb);

	osmo_sock_get_name_buf(buf, OSMO_SOCK_NAME_MAXLEN, fd);
	LOGP(DSTREAMTEST, LOGL_NOTICE, "accepted client: %s\n", buf);

	return 0;
}

static int kbd_cb(struct osmo_fd *fd, unsigned int what)
{
	char buf[1024];
	struct msgb *msg;
	uint8_t *ptr;
	int ret;

	ret = read(STDIN_FILENO, buf, sizeof(buf));
	if (ret < 1)
		return 0;

	LOGP(DSTREAMTEST, LOGL_NOTICE, "read %d byte from keyboard\n", ret);

	if (conn == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "no client, skipping\n");
		return 0;
	}

	msg = msgb_alloc(1024, "osmo_stream_srv_test");
	if (msg == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	ptr = msgb_put(msg, ret);
	memcpy(ptr, buf, ret);
	osmo_stream_srv_send(conn, msg);

	LOGP(DSTREAMTEST, LOGL_NOTICE, "message of %d bytes sent\n", msg->len);

	return 0;
}

static void signal_handler(int signum)
{
	switch (signum) {
	case SIGUSR1:
		talloc_report(tall_test, stderr);
		break;
	}
}

int main(int argc, char **argv)
{
	struct osmo_fd *kbd_ofd;
	bool use_sctp = false;
	const char *use_local_addr = "127.0.0.1";
	int opt;

	while ((opt = getopt(argc, argv, "sl:")) != -1) {
		switch (opt) {
		case 's':
			use_sctp = true;
			break;
		case 'l':
			use_local_addr = optarg;
			break;
		default:
			exit(0);
		}
	}

	signal(SIGUSR1, &signal_handler);

	tall_test = talloc_named_const(NULL, 1, "osmo_stream_srv_test");
	msgb_talloc_ctx_init(tall_test, 0);
	osmo_init_logging2(tall_test, &osmo_stream_srv_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/*
	 * initialize stream srv.
	 */

	srv = osmo_stream_srv_link_create(tall_test);
	if (srv == NULL) {
		fprintf(stderr, "cannot create server link\n");
		exit(EXIT_FAILURE);
	}
	osmo_stream_srv_link_set_addr(srv, use_local_addr);
	osmo_stream_srv_link_set_port(srv, 10000);
	if (use_sctp)
		osmo_stream_srv_link_set_proto(srv, IPPROTO_SCTP);
	osmo_stream_srv_link_set_accept_cb(srv, accept_cb);

	if (osmo_stream_srv_link_open(srv) < 0) {
		fprintf(stderr, "cannot open server link\n");
		exit(EXIT_FAILURE);
	}

	kbd_ofd = talloc_zero(tall_test, struct osmo_fd);
	if (!kbd_ofd) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "OOM\n");
		exit(EXIT_FAILURE);
	}
	osmo_fd_setup(kbd_ofd, STDIN_FILENO, OSMO_FD_READ, kbd_cb, srv, 0);
	osmo_fd_register(kbd_ofd);

	LOGP(DSTREAMTEST, LOGL_NOTICE, "Entering main loop on %s\n", osmo_stream_srv_link_get_sockname(srv));

	while(1) {
		osmo_select_main(0);
	}
}
