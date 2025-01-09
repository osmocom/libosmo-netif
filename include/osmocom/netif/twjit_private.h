/*
 * Themyscira Wireless RTP jitter buffer implementation:
 * internal definitions confined to twjit code inside libosmo-netif.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/netif/twjit.h>

/*
 * Each twjit instance has two sub-buffers; each subbuf is a queue of
 * received RTP packets that have the same SSRC and whose timestamps
 * increment in the expected cadence, with each ts delta being an
 * integral multiple of the samples-per-quantum constant.
 */
struct twjit_subbuf {
	uint32_t ssrc;
	uint32_t head_ts;
	struct llist_head queue;
	uint32_t depth;
	uint32_t delta_ms;		/* used only in starting state */
	/* thinning mechanism */
	uint16_t drop_int_count;
	/* running config for this subbuf */
	struct osmo_twjit_config conf;
};

/*
 * Each twjit instance is in one of 4 fundamental states at any moment,
 * as enumerated here.
 */
enum twjit_state {
	TWJIT_STATE_EMPTY,
	TWJIT_STATE_HUNT,
	TWJIT_STATE_FLOWING,
	TWJIT_STATE_HANDOVER,
};

/* Main structure for one instance of twjit */
struct osmo_twjit {
	/* pointer to config structure given to osmo_twjit_create(),
	 * memory must remain valid, but content can change at any time. */
	const struct osmo_twjit_config *ext_config;
	/* count of RTP timestamp units per quantum */
	uint32_t ts_quantum;
	/* quanta per second, used to scale max_future_sec */
	uint16_t quanta_per_sec;
	/* scaling factors for time delta conversions */
	uint16_t ts_units_per_ms;
	uint32_t ts_units_per_sec;
	uint32_t ns_to_ts_units;
	/* operational state */
	enum twjit_state state;
	struct twjit_subbuf sb[2];
	uint8_t read_sb;	/* 0 or 1 */
	uint8_t write_sb;	/* ditto */
	/* info about the most recent Rx packet */
	uint32_t last_ts;
	uint16_t last_seq;
	bool got_first_packet;
	struct timespec last_arrival;
	uint32_t last_arrival_delta;
	/* analytics for RTCP RR, also remembers last SSRC */
	struct osmo_twjit_rr_info rr_info;
	/* stats over lifetime of this instance */
	struct osmo_twjit_stats stats;
};
