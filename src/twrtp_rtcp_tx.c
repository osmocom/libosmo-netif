/*
 * Themyscira Wireless RTP endpoint implementation: RTCP Tx functionality.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>	/* for network byte order functions */

#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/twjit.h>
#include <osmocom/netif/rtcp_defs.h>

#define	NTP_EPOCH_MJD	15020
#define	UNIX_EPOCH_MJD	40587

#define	NTP_UNIX_EPOCH_DIFF	((UNIX_EPOCH_MJD-NTP_EPOCH_MJD) * 86400UL)
#define	TWO_TO_32_DOUBLE	4294967296.0

static void fill_rr_block(struct osmo_twrtp *endp, struct rtcp_rr_block *rr)
{
	struct osmo_twjit *twjit = endp->twjit;
	const struct osmo_twjit_rr_info *rri = osmo_twjit_get_rr_info(twjit);
	const struct twrtp_endp_rtcp_rx *rxs = &endp->rtcp_rx;
	struct twrtp_endp_rtcp_tx *txs = &endp->rtcp_tx;
	uint32_t delta_expect, delta_rcvd;
	int32_t cumulative_lost, newly_lost;
	uint32_t lost_fract, lost_word;
	struct timespec now, time_delta;

	cumulative_lost = (int32_t)(rri->expected_pkt - rri->rx_packets);
	if (cumulative_lost > 0x7FFFFF)
		cumulative_lost = 0x7FFFFF;
	else if (cumulative_lost < -0x800000)
		cumulative_lost = -0x800000;
	delta_expect = rri->expected_pkt - txs->last_expected;
	txs->last_expected = rri->expected_pkt;
	delta_rcvd = rri->rx_packets - txs->last_received;
	txs->last_received = rri->rx_packets;
	newly_lost = (int32_t)(delta_expect - delta_rcvd);
	if (delta_expect == 0 || newly_lost <= 0)
		lost_fract = 0;
	else
		lost_fract = (newly_lost << 8) / delta_expect;
	lost_word = (lost_fract << 8) | (cumulative_lost & 0xFFFFFF);

	rr->ssrc = htonl(rri->ssrc);
	rr->lost_word = htonl(lost_word);
	rr->max_seq_ext = htonl(rri->max_seq_ext);
	rr->jitter = htonl(rri->jitter_accum >> 4);

	if (rxs->got_sr && rxs->sr_ssrc == rri->ssrc) {
		osmo_clock_gettime(CLOCK_MONOTONIC, &now);
		time_delta.tv_sec = now.tv_sec - rxs->sr_rx_time.tv_sec;
		time_delta.tv_nsec = now.tv_nsec - rxs->sr_rx_time.tv_nsec;
		if (time_delta.tv_nsec < 0) {
			time_delta.tv_sec--;
			time_delta.tv_nsec += 1000000000;
		}
		rr->lsr_sec = htons(rxs->sr_ntp_sec);
		rr->lsr_fract = htons(rxs->sr_ntp_fract);
		rr->dlsr_sec = htons(time_delta.tv_sec);
		rr->dlsr_fract = htons(time_delta.tv_nsec / 1000000000.0f *
					65536.0f);
	} else {
		rr->lsr_sec = 0;
		rr->lsr_fract = 0;
		rr->dlsr_sec = 0;
		rr->dlsr_fract = 0;
	}
}

int _osmo_twrtp_send_rtcp(struct osmo_twrtp *endp, bool send_sr,
			  const struct timespec *utc, uint32_t rtp_ts)
{
	bool send_rr = false;
	struct msgb *msg;
	struct rtcp_sr_rr_hdr *hdr;
	struct rtcp_sr_block *sr;
	struct rtcp_rr_block *rr;
	uint8_t *sdes_out;
	int rc;

	if (!endp->register_done || !endp->remote_set || !endp->sdes_buf)
		return -EINVAL;
	if (endp->twjit && osmo_twjit_got_any_input(endp->twjit))
		send_rr = true;
	if (!send_sr && !send_rr)
		return -ENODATA;	/* nothing to send, neither SR nor RR */
	msg = msgb_alloc_c(endp, sizeof(struct rtcp_sr_rr_hdr) +
			   sizeof(struct rtcp_sr_block) +
			   sizeof(struct rtcp_rr_block) + endp->sdes_len,
			   "ThemWi-RTCP-Tx");
	if (!msg)
		return -ENOMEM;

	hdr = (struct rtcp_sr_rr_hdr *)
			msgb_put(msg, sizeof(struct rtcp_sr_rr_hdr));
	hdr->v_p_rc = send_rr ? 0x81 : 0x80;
	if (send_sr) {
		hdr->pt = RTCP_PT_SR;
		hdr->len = htons(send_rr ? 12 : 6);
	} else {
		hdr->pt = RTCP_PT_RR;
		hdr->len = htons(7);
	}
	hdr->ssrc = htonl(endp->tx.ssrc);
	if (send_sr) {
		sr = (struct rtcp_sr_block *)
				msgb_put(msg, sizeof(struct rtcp_sr_block));
		sr->ntp_sec = htonl(utc->tv_sec + NTP_UNIX_EPOCH_DIFF);
		sr->ntp_fract = htonl(utc->tv_nsec / 1000000000.0 *
					TWO_TO_32_DOUBLE);
		sr->rtp_ts = htonl(rtp_ts);
		sr->pkt_count = htonl(endp->stats.tx_rtp_pkt);
		sr->octet_count = htonl(endp->stats.tx_rtp_bytes);
	}
	if (send_rr) {
		rr = (struct rtcp_rr_block *)
				msgb_put(msg, sizeof(struct rtcp_rr_block));
		fill_rr_block(endp, rr);
	}
	sdes_out = msgb_put(msg, endp->sdes_len);
	memcpy(sdes_out, endp->sdes_buf, endp->sdes_len);

	rc = osmo_iofd_sendto_msgb(endp->iofd_rtcp, msg, 0, &endp->rtcp_remote);
	if (rc < 0) {
		msgb_free(msg);
		return rc;
	}
	endp->stats.tx_rtcp_pkt++;
	return 0;
}

int osmo_twrtp_send_rtcp_rr(struct osmo_twrtp *endp)
{
	return _osmo_twrtp_send_rtcp(endp, false, NULL, 0);
}

void osmo_twrtp_set_auto_rtcp_interval(struct osmo_twrtp *endp,
					uint16_t interval)
{
	endp->auto_rtcp_interval = interval;
}

int osmo_twrtp_set_sdes(struct osmo_twrtp *endp, const char *cname,
			const char *name, const char *email, const char *phone,
			const char *loc, const char *tool, const char *note)
{
	uint16_t len_str, len_padded, len_with_hdr, len;
	struct rtcp_sr_rr_hdr *hdr;
	uint8_t *dp;

	if (!cname)
		return -EINVAL;
	len_str = strlen(cname) + 2;
	if (name)
		len_str += strlen(name) + 2;
	if (email)
		len_str += strlen(email) + 2;
	if (phone)
		len_str += strlen(phone) + 2;
	if (loc)
		len_str += strlen(loc) + 2;
	if (tool)
		len_str += strlen(tool) + 2;
	if (note)
		len_str += strlen(note) + 2;
	len_padded = (len_str + 4) & ~3;
	len_with_hdr = len_padded + sizeof(struct rtcp_sr_rr_hdr);

	if (endp->sdes_buf)
		talloc_free(endp->sdes_buf);
	endp->sdes_buf = talloc_size(endp, len_with_hdr);
	if (!endp->sdes_buf)
		return -ENOMEM;

	hdr = (struct rtcp_sr_rr_hdr *) endp->sdes_buf;
	hdr->v_p_rc = 0x81;
	hdr->pt = RTCP_PT_SDES;
	hdr->len = htons(len_with_hdr / 4 - 1);
	hdr->ssrc = htonl(endp->tx.ssrc);
	dp = endp->sdes_buf + sizeof(struct rtcp_sr_rr_hdr);
	*dp++ = SDES_ITEM_CNAME;
	*dp++ = len = strlen(cname);
	memcpy(dp, cname, len);
	dp += len;
	if (name) {
		*dp++ = SDES_ITEM_NAME;
		*dp++ = len = strlen(name);
		memcpy(dp, name, len);
		dp += len;
	}
	if (email) {
		*dp++ = SDES_ITEM_EMAIL;
		*dp++ = len = strlen(email);
		memcpy(dp, email, len);
		dp += len;
	}
	if (phone) {
		*dp++ = SDES_ITEM_PHONE;
		*dp++ = len = strlen(phone);
		memcpy(dp, phone, len);
		dp += len;
	}
	if (loc) {
		*dp++ = SDES_ITEM_LOC;
		*dp++ = len = strlen(loc);
		memcpy(dp, loc, len);
		dp += len;
	}
	if (tool) {
		*dp++ = SDES_ITEM_TOOL;
		*dp++ = len = strlen(tool);
		memcpy(dp, tool, len);
		dp += len;
	}
	if (note) {
		*dp++ = SDES_ITEM_NOTE;
		*dp++ = len = strlen(note);
		memcpy(dp, note, len);
		dp += len;
	}
	memset(dp, 0, len_padded - len_str);

	endp->sdes_len = len_with_hdr;
	return 0;
}
