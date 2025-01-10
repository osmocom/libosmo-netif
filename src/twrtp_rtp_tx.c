/*
 * Themyscira Wireless RTP endpoint implementation: RTP Tx functionality.
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
#include <osmocom/core/timer.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/rtp.h>

static uint32_t gen_timestamp(struct timespec *now, struct osmo_twrtp *endp)
{
	uint32_t ts;

	ts = now->tv_sec * endp->ts_units_per_sec +
	     now->tv_nsec / endp->ns_to_ts_units;
	ts += endp->tx.ts_addend;
	return ts;
}

int osmo_twrtp_tx_quantum(struct osmo_twrtp *endp, const uint8_t *payload,
			  unsigned payload_len, uint8_t payload_type,
			  bool marker, bool auto_marker, bool send_rtcp)
{
	struct msgb *msg;
	struct timespec now;
	uint32_t restart_ts;
	int32_t ts_delta;
	struct rtp_hdr *rtph;
	uint8_t *pl_out;
	int rc;

	if (!endp->register_done || !endp->remote_set)
		return -EINVAL;
	msg = msgb_alloc_c(endp, sizeof(struct rtp_hdr) + payload_len,
			   "ThemWi-RTP-Tx");
	if (!msg) {
		osmo_twrtp_tx_skip(endp);
		return -ENOMEM;
	}

	/* timestamp generation is where we do some trickery */
	osmo_clock_gettime(CLOCK_REALTIME, &now);
	if (!endp->tx.started) {
		endp->tx.ts = gen_timestamp(&now, endp);
		endp->tx.started = true;
		endp->tx.restart = false;
		if (auto_marker)
			marker = true;
	} else if (endp->tx.restart) {
		restart_ts = gen_timestamp(&now, endp);
		ts_delta = (int32_t)(restart_ts - endp->tx.ts);
		if (ts_delta <= 0) {
			/* shouldn't happen, unless something funky w/clock */
			endp->tx.ts++;
		} else {
			if (ts_delta % endp->ts_quantum == 0)
				restart_ts++;
			endp->tx.ts = restart_ts;
		}
		endp->tx.restart = false;
		if (auto_marker)
			marker = true;
	}

	rtph = (struct rtp_hdr *) msgb_put(msg, sizeof(struct rtp_hdr));
	rtph->version = RTP_VERSION;
	rtph->padding = 0;
	rtph->extension = 0;
	rtph->csrc_count = 0;
	rtph->marker = marker;
	rtph->payload_type = payload_type;
	rtph->sequence = htons(endp->tx.seq);
	rtph->timestamp = htonl(endp->tx.ts);
	rtph->ssrc = htonl(endp->tx.ssrc);
	pl_out = msgb_put(msg, payload_len);
	memcpy(pl_out, payload, payload_len);
	endp->tx.seq++;
	endp->tx.ts += endp->ts_quantum;

	rc = osmo_iofd_sendto_msgb(endp->iofd_rtp, msg, 0, &endp->rtp_remote);
	if (rc < 0) {
		msgb_free(msg);
		return rc;
	}
	endp->stats.tx_rtp_pkt++;
	endp->stats.tx_rtp_bytes += payload_len;

	if (endp->auto_rtcp_interval) {
		endp->auto_rtcp_count++;
		if (endp->auto_rtcp_count >= endp->auto_rtcp_interval) {
			endp->auto_rtcp_count = 0;
			send_rtcp = true;
		}
	}
	if (send_rtcp) {
		_osmo_twrtp_send_rtcp(endp, true, &now,
				      endp->tx.ts - endp->ts_quantum);
	}

	return 0;
}

void osmo_twrtp_tx_skip(struct osmo_twrtp *endp)
{
	if (!endp->tx.started || endp->tx.restart)
		return;
	endp->tx.ts += endp->ts_quantum;
}

void osmo_twrtp_tx_restart(struct osmo_twrtp *endp)
{
	endp->tx.restart = true;
}

int osmo_twrtp_tx_forward(struct osmo_twrtp *endp, struct msgb *msg)
{
	return osmo_iofd_sendto_msgb(endp->iofd_rtp, msg, 0, &endp->rtp_remote);
}
