#include "udp-test.h"

static int read_cb(struct osmo_dgram *conn)
{
	struct msgb *msg = print_recv(conn);
	if (!msg)
		return -1;

	if (msgb_length(msg))
		if (msgb_data(msg)[0] >= NUM_MSG - 1)
			please_dont_die = false; /* end test: */

	msgb_free(msg);

	return 0;
}

int main(int argc, char **argv)
{
	uint8_t i;

	if (!dgram_init(THOST, CPORT, SPORT, read_cb))
		exit(EXIT_FAILURE);

	for(i = 0; i < NUM_MSG + 1; i++) {
		/* N. B: moving this alocation outside of the loop will result in segfault */
		struct msgb *msg = msgb_alloc(MAX_MSG, "UDP/client");
		if (!msg) {
			LOGP(DUDP_TEST, LOGL_ERROR, "cann't allocate message\n");
			return EXIT_FAILURE;
		}

		if (!mtrim(msg, i, i))
			return EXIT_FAILURE;

		LOGP(DUDP_TEST, LOGL_NOTICE, "queue [%u] %s\n", msgb_length(msg), msgb_hexdump(msg));
		osmo_dgram_send(conn, msg);
	}

	main_loop(THOST, CPORT, SPORT);

	return 0;
}
