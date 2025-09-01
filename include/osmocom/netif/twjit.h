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

#include <osmocom/core/msgb.h>

/*! \defgroup twjit Themyscira Wireless RTP jitter buffer implementation
 *  @{
 *
 *  The present twjit layer is an interface mechanism from an incoming
 *  RTP stream to an output application that has fixed timing requirements,
 *  e.g., the Tx side of GSM Um TCH or a T1/E1 TDM interface.
 *
 *  There also exists a detailed document titled _Guide to ThemWi RTP
 *  endpoint library_, located here:
 *  https://www.freecalypso.org/TW-doc/twrtp-guide-latest.pdf
 *  (See TW-doc directory listing for other formats and previous versions.)
 *  This document is required reading for anyone seeking to properly
 *  understand the present jitter buffer facility, its domain of application
 *  and how to use it.  Specific section references to this document
 *  will be made in subsequent comments.
 *
 *  FIXME: create an Osmocom-controlled version of this document
 *  that describes the version of twrtp+twjit modified for inclusion
 *  in Osmocom.
 */

/*! Each instance of twjit in the present version exists as struct osmo_twjit.
 *  This structure is opaque, and always constitutes a talloc context. */
struct osmo_twjit;

/*! A config structure is also needed, containing tunable settings
 *  that are usually managed via vty.  This config structure is separate
 *  from individual twjit instances because there will be many more
 *  twjit instances than config instances: there will be a separate
 *  twjit instance for every call or other RTP stream handled by the
 *  application, but only one twjit config structure in the app's
 *  vty config tree, or a few such config instances as appropriate
 *  per app design.
 *
 *  This config structure is likewise opaque and also constitutes a talloc
 *  context. */
struct osmo_twjit_config;

/*! Stats collected during the lifetime of a twjit instance.
 *  For a detailed description of each of these counters, see Chapter 3
 *  of twrtp guide document.
 *
 *  This stats structure is never allocated or accessed in a writable
 *  manner by applications; instead it is allocated inside the library
 *  as part of opaque struct osmo_twjit, while applications are given
 *  const pointers to these structs.
 */
struct osmo_twjit_stats {
	/* For ABI reasons, none of the following fields may be deleted
	 * or reordered! */

	/* normal operation */
	uint32_t rx_packets;
	uint32_t delivered_pkt;
	uint32_t handovers_in;
	uint32_t handovers_out;
	uint32_t marker_resets;
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
	/* New fields may be added here at the end; once added, they become
	 * permanent like the initially defined ones. */
};

/*! Info collected from the incoming RTP data stream
 *  for the purpose of generating RTCP reception report blocks.
 *  See twrtp guide document section 5.1.
 *
 *  Key point: unlike the counters in struct osmo_twjit_stats,
 *  all RR info is reset to initial whenever incoming SSRC changes,
 *  as necessitated by RTCP data model being organized per SSRC.
 *
 *  The same ABI considerations apply to this struct as osmo_twjit_stats.
 */
struct osmo_twjit_rr_info {
	/* For ABI reasons, none of the following fields may be deleted
	 * or reordered! */

	/*! received SSRC to which all following info applies */
	uint32_t ssrc;
	/*! count of "received packets" for RTCP RR packet loss calculation */
	uint32_t rx_packets;
	/*! "base" sequence number for "expected packets" computation */
	uint32_t base_seq;
	/*! "extended highest sequence number" field of RTCP RR */
	uint32_t max_seq_ext;
	/*! count of "expected packets" for RTCP RR packet loss calculation */
	uint32_t expected_pkt;
	/*! "interarrival jitter" measure of RFC 3550, accumulator for the
	 *  leaky integrator algorithm prescribed by the RFC, sans-FP version.
	 *  Right-shift this accumulator by 4 bits when emitting RTCP RR. */
	uint32_t jitter_accum;
	/* New fields may be added here at the end; once added, they become
	 * permanent like the initially defined ones. */
};

/* twjit API: managing configuration structures */

struct osmo_twjit_config *osmo_twjit_config_alloc(void *ctx);
void osmo_twjit_config_free(struct osmo_twjit_config *conf);

int osmo_twjit_config_set_buffer_depth(struct osmo_twjit_config *conf,
					uint16_t bd_start, uint16_t bd_hiwat);
int osmo_twjit_config_set_thinning_int(struct osmo_twjit_config *conf,
					uint16_t thinning_int);
int osmo_twjit_config_set_max_future_sec(struct osmo_twjit_config *conf,
					 uint16_t max_future_sec);
int osmo_twjit_config_set_start_min_delta(struct osmo_twjit_config *conf,
					  uint16_t delta_ms);
int osmo_twjit_config_set_start_max_delta(struct osmo_twjit_config *conf,
					  uint16_t delta_ms);
int osmo_twjit_config_set_handover_on_marker(struct osmo_twjit_config *conf,
					     bool hom);

/* twjit API: actual twjit instances */

struct osmo_twjit *osmo_twjit_create(void *ctx, uint16_t clock_khz,
				     uint16_t quantum_ms,
				     const struct osmo_twjit_config *config);
void osmo_twjit_destroy(struct osmo_twjit *twjit);

int osmo_twjit_set_config(struct osmo_twjit *twjit,
			  const struct osmo_twjit_config *config);
void osmo_twjit_reset(struct osmo_twjit *twjit);

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
bool osmo_twjit_rr_info_valid(struct osmo_twjit *twjit);

/* vty configuration functions */

void osmo_twjit_vty_init(int twjit_node);

struct vty;

int osmo_twjit_config_write(struct vty *vty,
			    const struct osmo_twjit_config *conf,
			    const char *prefix);

/*! @} */
