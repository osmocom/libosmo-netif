/*
 * Themyscira Wireless RTP jitter buffer implementation:
 * public API definition for Osmocom-integrated version.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
 * Each instance of twjit in the present version exists as struct osmo_twjit.
 * This structure is opaque, and always constitutes a talloc context.
 */
struct osmo_twjit;

/*
 * twjit configuration tunings, usually set via vty.  This config structure
 * always has to be provided in order to create a twjit instance.
 */
struct osmo_twjit_config {
	/* buffer depth: starting minimum and high watermark */
	uint16_t bd_start;
	uint16_t bd_hiwat;
	/* interval for thinning of too-deep standing queue */
	uint16_t thinning_int;
	/* guard against time traveler RTP packets */
	uint16_t max_future_sec;
	/* min and max time delta in starting state, 0 means not set */
	uint16_t start_min_delta;
	uint16_t start_max_delta;
};

/*
 * Stats collected during the lifetime of a twjit instance.
 */
struct osmo_twjit_stats {
	/* normal operation */
	uint32_t rx_packets;
	uint32_t delivered_pkt;
	uint32_t handovers_in;
	uint32_t handovers_out;
	/* undesirable, but not totally unexpected */
	uint32_t too_old;
	uint32_t underruns;
	uint32_t ho_underruns;
	uint32_t output_gaps;
	uint32_t thinning_drops;
	/* unusual error events */
	uint32_t bad_packets;
	uint32_t duplicate_ts;
	/* independent analysis of Rx packet stream */
	uint32_t ssrc_changes;
	uint32_t seq_skips;
	uint32_t seq_backwards;
	uint32_t seq_repeats;
	uint32_t intentional_gaps;
	uint32_t ts_resets;
	uint32_t jitter_max;
};

/*
 * Info collected from the incoming RTP data stream
 * for the purpose of generating RTCP reception report blocks.
 * Key point: unlike the counters in struct osmo_twjit_stats,
 * all RR info is reset to initial whenever incoming SSRC changes,
 * as necessitated by RTCP data model being organized per SSRC.
 */
struct osmo_twjit_rr_info {
	uint32_t ssrc;
	uint32_t rx_packets;
	uint32_t base_seq;
	uint32_t max_seq_ext;
	uint32_t expected_pkt;
	uint32_t jitter_accum;
};

/* twjit module API functions */

struct osmo_twjit *osmo_twjit_create(void *ctx, uint16_t clock_khz,
				     uint16_t quantum_ms,
				     const struct osmo_twjit_config *config);
void osmo_twjit_destroy(struct osmo_twjit *twjit);

void osmo_twjit_new_config(struct osmo_twjit *twjit,
			   const struct osmo_twjit_config *config);
void osmo_twjit_reset(struct osmo_twjit *twjit);

struct msgb;

/* RTP input, takes ownership of msgb */
void osmo_twjit_input(struct osmo_twjit *twjit, struct msgb *msg);

/* output function, to be called by TDM/GSM/etc fixed-timing side */
struct msgb *osmo_twjit_output(struct osmo_twjit *twjit);

/* Stats and RR info structures are contained inside opaque struct osmo_twjit.
 * We need to provide access to these stats and RR info structures to API
 * users, but we don't want to make the whole twjit instance struct public.
 * Also we would like to have fast external access to these stats, hence an API
 * that copies our stats to caller-provided storage would be very inefficient.
 * Compromise: we allow direct external access to just these selected parts
 * of the full internal state structure by providing API functions that
 * return pointers to these selected parts.
 */
const struct osmo_twjit_stats *
osmo_twjit_get_stats(struct osmo_twjit *twjit);

const struct osmo_twjit_rr_info *
osmo_twjit_get_rr_info(struct osmo_twjit *twjit);

/* When we compose outgoing RTCP packets in the upper layer of twrtp,
 * we need to know whether or not we have received at least one valid
 * RTP data packet so far.  If we haven't received any RTP yet, then
 * we have no Rx SSRC, all data in struct osmo_twjit_rr_info are invalid,
 * and we cannot send RTCP reception reports.
 */
bool osmo_twjit_got_any_input(struct osmo_twjit *twjit);

/* vty configuration functions */

void osmo_twjit_init_defaults(struct osmo_twjit_config *config);

void osmo_twjit_vty_init(int twjit_node);

struct vty;

int osmo_twjit_config_write(struct vty *vty,
			    const struct osmo_twjit_config *conf,
			    const char *name, const char *prefix);
