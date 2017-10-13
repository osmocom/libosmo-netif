#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/netif/datagram.h>

#define MAX_MSG 255
#define NUM_MSG 11
#define DUDP_TEST 0
#define THOST "127.0.0.1"
#define SPORT 15000
#define CPORT 15001

static struct osmo_dgram *conn;
static void *tall_test;
bool please_dont_die = true;

static void sighandler(int foo)
{
	LOGP(DLINP, LOGL_NOTICE, "closing UDP test...\n");
	osmo_dgram_close(conn);
	osmo_dgram_destroy(conn);
	please_dont_die = false;
}

static inline struct msgb *print_recv(struct osmo_dgram *conn)
{
	struct msgb *msg = msgb_alloc(MAX_MSG, "UDP/test");
	int bytes;

	LOGP(DUDP_TEST, LOGL_NOTICE, "received datagram: ");

	if (!msg) {
		LOGPC(DUDP_TEST, LOGL_ERROR, "can't allocate message\n");
		return NULL;
	}

	/* receive message: */
	bytes = osmo_dgram_recv(conn, msg);
	if (bytes < 0) {
		LOGPC(DUDP_TEST, LOGL_ERROR, "can't receive message: %u\n", -bytes);
		msgb_free(msg);
		return NULL;
	}

	/* process message: */
	LOGPC(DUDP_TEST, LOGL_NOTICE, "[%u] %s\n", bytes, msgb_hexdump(msg));

	return msg;
}

static inline bool dgram_init(const char *host, uint16_t lport, uint16_t rport, void *read_cb)
{
	const struct log_info_cat udp_test_cat[] = {
		[DUDP_TEST] = {
			.name = "DUDP_TEST",
			.description = "UDP test",
			.color = "\033[1;35m",
			.enabled = 1, .loglevel = LOGL_NOTICE,
		},
	};

	const struct log_info udp_test_log_info = {
		.filter_fn = NULL,
		.cat = udp_test_cat,
		.num_cat = ARRAY_SIZE(udp_test_cat),
	};

	signal(SIGINT, sighandler);

	tall_test = talloc_named_const(NULL, 1, "udp_test");

	osmo_init_logging(&udp_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_NOTICE);

	conn = osmo_dgram_create(tall_test);
	if (!conn) {
		LOGP(DUDP_TEST, LOGL_ERROR, "cannot create UDP socket\n");
		return false;
	}

	osmo_dgram_set_local_addr(conn, host);
	osmo_dgram_set_local_port(conn, lport);
	osmo_dgram_set_remote_addr(conn, host);
	osmo_dgram_set_remote_port(conn, rport);
	osmo_dgram_set_read_cb(conn, read_cb);

	if (osmo_dgram_open(conn) < 0) {
		LOGP(DUDP_TEST, LOGL_ERROR, "cannot open client connection %s:%u -> %s:%u\n", host, lport, host, rport);
		return false;
	}

	return true;
}

static inline void main_loop(const char *host, uint16_t lport, uint16_t rport)
{
	LOGP(DUDP_TEST, LOGL_NOTICE, "Entering main loop: %s:%u -> %s:%u\n", host, lport, host, rport);

	while(please_dont_die)
		osmo_select_main(0);
}

/* Smart message trimmer:
 * for all positive i trims msg to i - 1
 * for i = 0 trims msg to 0
 * for all positive x adds x to msg
*/
/*! Smart message trimmer.
 *  \param[in] msg message buffer
 *  \param[in] i trim value: for all positive i, msg is trimmed to i - 1, otherwise msg is trimmed to 0
 *  \param[in] x message content: for all positive x, x is added to msg, otherwise it's ignored
 */
static inline bool mtrim(struct msgb *msg, uint8_t i, uint8_t x)
{
	if (msgb_trim(msg, i ? i - 1 : i) != 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to trim message by %u\n", i);
		return false;
	}

	if (x)
		msgb_put_u8(msg, x);

	return true;
}
