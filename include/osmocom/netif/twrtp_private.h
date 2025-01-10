/*
 * Themyscira Wireless RTP endpoint implementation:
 * internal definitions confined to twrtp code inside libosmo-netif.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>

#include <osmocom/netif/twrtp.h>

struct twrtp_endp_tx {
	uint32_t ssrc;
	uint32_t ts;
	uint32_t ts_addend;
	uint16_t seq;
	bool started;
	bool restart;
};

struct twrtp_endp_rtcp_rx {
	uint32_t sr_ssrc;
	uint16_t sr_ntp_sec;
	uint16_t sr_ntp_fract;
	struct timespec sr_rx_time;
	uint32_t rr_lost_word;
	uint32_t rr_jitter;
	uint32_t rr_jitter_max;
	bool got_sr;
	bool got_rr;
};

struct twrtp_endp_rtcp_tx {
	uint32_t last_received;
	uint32_t last_expected;
};

struct osmo_twjit;

struct osmo_twrtp {
	/* the root of the matter: the two sockets */
	struct osmo_io_fd *iofd_rtp;
	struct osmo_io_fd *iofd_rtcp;
	struct osmo_sockaddr rtp_remote;
	struct osmo_sockaddr rtcp_remote;
	/* count of RTP timestamp units per quantum */
	uint32_t ts_quantum;
	/* scaling factors for RTP Tx timestamp computation */
	uint32_t ts_units_per_sec;
	uint32_t ns_to_ts_units;
	/* RTP Rx path: twjit and raw options */
	struct osmo_twjit *twjit;
	osmo_twrtp_raw_rx_cb raw_rx_cb;
	void *raw_rx_cb_data;
	/* RTP Tx state */
	struct twrtp_endp_tx tx;
	/* RTCP info */
	struct twrtp_endp_rtcp_rx rtcp_rx;
	struct twrtp_endp_rtcp_tx rtcp_tx;
	uint8_t *sdes_buf;
	uint16_t sdes_len;
	uint16_t auto_rtcp_interval;
	uint16_t auto_rtcp_count;
	/* always have to have stats */
	struct osmo_twrtp_stats stats;
	/* bool flags at the end for structure packing optimization */
	bool register_done;
	bool remote_set;
	bool twjit_rx_enable;
};

/* internal linkage */

extern const struct osmo_io_ops _osmo_twrtp_iops_rtp;
extern const struct osmo_io_ops _osmo_twrtp_iops_rtcp;

int _osmo_twrtp_send_rtcp(struct osmo_twrtp *endp, bool send_sr,
			  const struct timespec *utc, uint32_t rtp_ts);
