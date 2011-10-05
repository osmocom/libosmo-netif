/* LAPD over datagram user-mode example. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <osmocom/abis/lapd.h>

#include <osmocom/netif/datagram.h>

#define DLAPDTEST 0

struct log_info_cat lapd_test_cat[] = {
	[DLAPDTEST] = {
		.name = "DLAPDTEST",
		.description = "LAPD-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info lapd_test_log_info = {
	.filter_fn = NULL,
	.cat = lapd_test_cat,
	.num_cat = ARRAY_SIZE(lapd_test_cat),
};

static struct datagram_conn *conn;
static struct lapd_instance *lapd;
static int sapi = 63, tei = 0;

void sighandler(int foo)
{
	lapd_sap_stop(lapd, tei, sapi);
	lapd_instance_free(lapd);
	LOGP(DLINP, LOGL_NOTICE, "closing LAPD.\n");
	exit(EXIT_SUCCESS);
}

static int read_cb(struct datagram_server_conn *conn, struct msgb *msg)
{
	int error;

	LOGP(DLINP, LOGL_NOTICE, "received message from datagram\n");

	if (lapd_receive(lapd, msg, &error) < 0) {
		LOGP(DLINP, LOGL_ERROR, "lapd_receive returned error!\n");
		return -1;
	}
	return 0;
}

static void *tall_test;

void lapd_tx_cb(struct msgb *msg, void *cbdata)
{
	LOGP(DLINP, LOGL_NOTICE, "sending message over datagram\n");
	datagram_conn_send(conn, msg);
}

void lapd_rx_cb(struct osmo_dlsap_prim *dp, uint8_t tei, uint8_t sapi,
		void *rx_cbdata)
{
	struct msgb *msg = dp->oph.msg;

	switch (dp->oph.primitive) {
	case PRIM_DL_EST:
		DEBUGP(DLAPDTEST, "DL_EST: sapi(%d) tei(%d)\n", sapi, tei);
		break;
	case PRIM_DL_REL:
		DEBUGP(DLAPDTEST, "DL_REL: sapi(%d) tei(%d)\n", sapi, tei);
		break;
	case PRIM_DL_DATA:
	case PRIM_DL_UNIT_DATA:
		if (dp->oph.operation == PRIM_OP_INDICATION) {
			msg->l2h = msg->l3h;
			DEBUGP(DLAPDTEST, "RX: %s sapi=%d tei=%d\n",
				osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)),
				sapi, tei);
			return;
		}
		break;
	case PRIM_MDL_ERROR:
		DEBUGP(DLMI, "MDL_EERROR: cause(%d)\n", dp->u.error_ind.cause);
		break;
	default:
		printf("ERROR: unknown prim\n");
		break;
	}
}

static int kbd_cb(struct osmo_fd *fd, unsigned int what)
{
	char buf[1024];
	struct msgb *msg;
	uint8_t *ptr;
	int ret;

	ret = read(STDIN_FILENO, buf, sizeof(buf));

	LOGP(DLAPDTEST, LOGL_NOTICE, "read %d byte from keyboard\n", ret);

	msg = msgb_alloc(1024, "LAPD/test");
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "lapd: cannot allocate message\n");
		return 0;
	}
	ptr = msgb_put(msg, strlen(buf));
	memcpy(ptr, buf, ret);

	lapd_transmit(lapd, tei, sapi, msg);

	LOGP(DLAPDTEST, LOGL_NOTICE, "message of %d bytes sent\n", msg->len);

	return 0;
}

int main(void)
{
	struct osmo_fd *kbd_ofd;

	tall_test = talloc_named_const(NULL, 1, "lapd_test");

	osmo_init_logging(&lapd_test_log_info);
	log_set_log_level(osmo_stderr_target, 1);
	/*
	 * initialize LAPD stuff.
	 */

	lapd = lapd_instance_alloc(0, lapd_tx_cb, NULL, lapd_rx_cb, NULL,
				   &lapd_profile_sat);
	if (lapd == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate instance\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * initialize datagram socket.
	 */

	conn = datagram_conn_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	datagram_conn_set_local_addr(conn, "127.0.0.1");
	datagram_conn_set_local_port(conn, 10000);
	datagram_conn_set_remote_addr(conn, "127.0.0.1");
	datagram_conn_set_remote_port(conn, 10001);
	datagram_conn_set_read_cb(conn, read_cb);

	if (datagram_conn_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	if (lapd_sap_start(lapd, tei, sapi) < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot start user-side LAPD\n");
		exit(EXIT_FAILURE);
	}

	kbd_ofd = talloc_zero(tall_test, struct osmo_fd);
	if (!kbd_ofd) {
		LOGP(DLAPDTEST, LOGL_ERROR, "OOM\n");
		exit(EXIT_FAILURE);
	}
	kbd_ofd->fd = STDIN_FILENO;
	kbd_ofd->when = BSC_FD_READ;
	kbd_ofd->data = conn;
	kbd_ofd->cb = kbd_cb;
	osmo_fd_register(kbd_ofd);

	LOGP(DLINP, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
