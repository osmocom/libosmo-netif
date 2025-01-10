/*
 * Themyscira Wireless RTP endpoint implementation: RTP Rx path
 * via osmo_io callback.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/twjit.h>

static void rtp_rx_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg,
		      const struct osmo_sockaddr *saddr)
{
	struct osmo_twrtp *endp = osmo_iofd_get_data(iofd);

	if (!msg)
		return;
	if (!endp->remote_set) {
		msgb_free(msg);
		return;
	}
	if (osmo_sockaddr_cmp(saddr, &endp->rtp_remote)) {
		endp->stats.rx_rtp_badsrc++;
		msgb_free(msg);
		return;
	}
	endp->stats.rx_rtp_pkt++;
	if (endp->twjit_rx_enable)
		osmo_twjit_input(endp->twjit, msg);
	else if (endp->raw_rx_cb)
		endp->raw_rx_cb(endp, endp->raw_rx_cb_data, msg);
	else
		msgb_free(msg);
}

const struct osmo_io_ops _osmo_twrtp_iops_rtp = {
	.recvfrom_cb = rtp_rx_cb,
};

void osmo_twrtp_set_raw_rx_cb(struct osmo_twrtp *endp, osmo_twrtp_raw_rx_cb cb,
			      void *user_data)
{
	endp->raw_rx_cb = cb;
	endp->raw_rx_cb_data = user_data;
}
