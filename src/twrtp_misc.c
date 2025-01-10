/*
 * Themyscira Wireless RTP endpoint implementation: miscellaneous
 * functions that don't belong anywhere else.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>

const struct osmo_twrtp_stats *osmo_twrtp_get_stats(struct osmo_twrtp *endp)
{
	return &endp->stats;
}

bool osmo_twrtp_got_rtcp_rr(struct osmo_twrtp *endp)
{
	return endp->rtcp_rx.got_rr;
}

uint32_t osmo_twrtp_rr_lost_word(struct osmo_twrtp *endp)
{
	return endp->rtcp_rx.rr_lost_word;
}

int32_t osmo_twrtp_rr_lost_cumulative(struct osmo_twrtp *endp)
{
	int32_t lost_count;

	lost_count = endp->rtcp_rx.rr_lost_word & 0xFFFFFF;
	if (lost_count & 0x800000)
		lost_count |= 0xFF000000;
	return lost_count;
}

uint32_t osmo_twrtp_rr_jitter_last(struct osmo_twrtp *endp)
{
	return endp->rtcp_rx.rr_jitter;
}

uint32_t osmo_twrtp_rr_jitter_max(struct osmo_twrtp *endp)
{
	return endp->rtcp_rx.rr_jitter_max;
}

int osmo_twrtp_set_dscp(struct osmo_twrtp *endp, uint8_t dscp)
{
	int rc;

	rc = osmo_sock_set_dscp(osmo_iofd_get_fd(endp->iofd_rtp), dscp);
	if (rc < 0)
		return rc;
	return osmo_sock_set_dscp(osmo_iofd_get_fd(endp->iofd_rtcp), dscp);
}

int osmo_twrtp_set_socket_prio(struct osmo_twrtp *endp, int prio)
{
	int rc;

	rc = osmo_sock_set_priority(osmo_iofd_get_fd(endp->iofd_rtp), prio);
	if (rc < 0)
		return rc;
	return osmo_sock_set_priority(osmo_iofd_get_fd(endp->iofd_rtcp), prio);
}
