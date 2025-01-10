/*
 * Themyscira Wireless RTP endpoint implementation: RTCP Rx path
 * via osmo_io callback.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>	/* for network byte order functions */

#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/rtcp_defs.h>

static void parse_rtcp(struct osmo_twrtp *endp, struct msgb *msg)
{
	struct twrtp_endp_rtcp_rx *rxs = &endp->rtcp_rx;
	struct rtcp_sr_rr_hdr *base_hdr;
	struct rtcp_sr_block *sr;
	struct rtcp_rr_block *rr;
	unsigned rc, i;

	if (msg->len < sizeof(struct rtcp_sr_rr_hdr)) {
invalid:	endp->stats.rx_rtcp_invalid++;
		return;
	}
	base_hdr = (struct rtcp_sr_rr_hdr *) msg->data;
	msgb_pull(msg, sizeof(struct rtcp_sr_rr_hdr));
	if ((base_hdr->v_p_rc & 0xC0) != 0x80)
		goto invalid;
	switch (base_hdr->pt) {
	case RTCP_PT_SR:
		if (msg->len < sizeof(struct rtcp_sr_block))
			goto invalid;
		sr = (struct rtcp_sr_block *) msg->data;
		msgb_pull(msg, sizeof(struct rtcp_sr_block));
		rxs->got_sr = true;
		osmo_clock_gettime(CLOCK_MONOTONIC, &rxs->sr_rx_time);
		rxs->sr_ssrc = ntohl(base_hdr->ssrc);
		rxs->sr_ntp_sec = ntohl(sr->ntp_sec);
		rxs->sr_ntp_fract = ntohl(sr->ntp_fract) >> 16;
		break;
	case RTCP_PT_RR:
		break;
	default:
		goto invalid;
	}
	rc = base_hdr->v_p_rc & 0x1F;
	if (msg->len < sizeof(struct rtcp_rr_block) * rc)
		goto invalid;
	for (i = 0; i < rc; i++) {
		rr = (struct rtcp_rr_block *) msg->data;
		msgb_pull(msg, sizeof(struct rtcp_rr_block));
		if (ntohl(rr->ssrc) != endp->tx.ssrc) {
			endp->stats.rx_rtcp_wrong_ssrc++;
			continue;
		}
		rxs->got_rr = true;
		rxs->rr_lost_word = ntohl(rr->lost_word);
		rxs->rr_jitter = ntohl(rr->jitter);
		if (rxs->rr_jitter > rxs->rr_jitter_max)
			rxs->rr_jitter_max = rxs->rr_jitter;
	}
}

static void rtcp_rx_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg,
			const struct osmo_sockaddr *saddr)
{
	struct osmo_twrtp *endp = osmo_iofd_get_data(iofd);

	if (!msg)
		return;
	if (!endp->remote_set) {
		msgb_free(msg);
		return;
	}
	if (osmo_sockaddr_cmp(saddr, &endp->rtcp_remote)) {
		endp->stats.rx_rtcp_badsrc++;
		msgb_free(msg);
		return;
	}
	endp->stats.rx_rtcp_pkt++;
	parse_rtcp(endp, msg);
	msgb_free(msg);
}

const struct osmo_io_ops _osmo_twrtp_iops_rtcp = {
	.recvfrom_cb = rtcp_rx_cb,
};
