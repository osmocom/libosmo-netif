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

int read_cb(struct osmo_stream_srv *conn)
{
	int bytes;
	struct msgb *msg;

	LOGP(DSTREAMTEST, LOGL_NOTICE, "receiving message from stream... ");

	msg = msgb_alloc(1024, "STREAMSERVER/test");
	if (msg == NULL) {
		LOGPC(DSTREAMTEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}

	bytes = osmo_stream_srv_recv(conn, msg);

	if (bytes <= 0) {
		if (bytes < 0)
			LOGPC(DSTREAMTEST, LOGL_ERROR, "cannot receive message: %s\n", strerror(-bytes));
		else
			LOGPC(DSTREAMTEST, LOGL_ERROR, "client closed connection\n");
		osmo_stream_srv_destroy(conn);
	} else
		LOGPC(DSTREAMTEST, LOGL_NOTICE, "got %d (%d) bytes: %s\n", bytes, msg->len, msgb_hexdump(msg));

	msgb_free(msg);
	return 0;
}

static int close_cb(struct osmo_stream_srv *dummy)
{
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

	conn = osmo_stream_srv_create(tall_test, srv, fd, read_cb,
					 close_cb, NULL);
	if (conn == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR,
			"error while creating connection\n");
		return -1;
	}

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

int main(void)
{
	struct osmo_fd *kbd_ofd;

	tall_test = talloc_named_const(NULL, 1, "osmo_stream_srv_test");
	msgb_talloc_ctx_init(tall_test, 0);
	osmo_init_logging2(tall_test, &osmo_stream_srv_test_log_info);
	log_set_log_level(osmo_stderr_target, 1);
	log_set_category_filter(osmo_stderr_target, DLINP, 0, LOGL_INFO);

	/*
	 * initialize stream srv.
	 */

	srv = osmo_stream_srv_link_create(tall_test);
	if (srv == NULL) {
		fprintf(stderr, "cannot create server link\n");
		exit(EXIT_FAILURE);
	}
	osmo_stream_srv_link_set_addr(srv, "127.0.0.1");
	osmo_stream_srv_link_set_port(srv, 10000);
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
