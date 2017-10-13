#include "udp-test.h"

int read_cb(struct osmo_dgram *conn)
{
	int bytes;
	struct msgb *msg = print_recv(conn);

	if (!msg)
		return -1;

	/* build reply: */
	bytes = msgb_length(msg);

	if (!mtrim(msg, 0, bytes))
		return -1;

	/* sent reply: */
	osmo_dgram_send(conn, msg);

	/* end test: */
	if (bytes > NUM_MSG - 1)
		please_dont_die = false;

	return 0;
}

int main(int argc, char **argv)
{
	if (!dgram_init(THOST, SPORT, CPORT, read_cb))
		return EXIT_FAILURE;

	main_loop(THOST, SPORT, CPORT);

	return 0;
}
