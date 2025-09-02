/*
 * Themyscira Wireless RTP endpoint implementation:
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
#include <osmocom/core/socket.h>

/*! \defgroup twrtp Themyscira Wireless RTP endpoint implementation
 *  @{
 *
 * osmo_twrtp is a complete RTP endpoint.  It is primarily designed
 * to be used together with twjit to build a bidirectional interface
 * between an RTP stream and a fixed timing system such as GSM Um TCH
 * or T1/E1 Abis, but it also has limited support for endpoints without
 * twjit.  A twrtp endpoint without twjit is either an output-only
 * endpoint (playout of in-band tones and announcements etc), or one
 * side of a pair of endpoints that forward RTP packets to each other
 * without delay.
 *
 * The basic workflow is:
 *
 * 1. Create a twrtp instance with osmo_twrtp_create().  The decision
 *    to use or not use twjit is fixed at this time; if twjit is to be
 *    used, struct osmo_twjit_config needs to be provided.
 *
 * 2. Create and bind a pair of local UDP sockets for RTP and RTCP,
 *    or supply osmo_twrtp with an already-obtained pair of file descriptors
 *    for the same.  Most users will find the high-level API
 *    osmo_twrtp_bind_local() most suitable, but some applications may
 *    prefer to use the low-level API osmo_twrtp_supply_fds() instead.
 *
 * 3. Set the IP:port address of the remote RTP end with
 *    osmo_twrtp_set_remote().
 *
 * 4. Traffic can now be sent and received as detailed below.
 *
 * Receiving RTP traffic, interworking to a fixed timing system:
 *
 * 1. Provide struct osmo_twjit_config to osmo_twrtp_create(), so the twrtp
 *    instance will be created with twjit included.
 *
 * 2. When you are ready to start receiving traffic, call
 *    osmo_twrtp_twjit_rx_ctrl() with rx_enable argument set to true.
 *
 * 3. Once you've made the above call, commit to calling
 *    osmo_twrtp_twjit_rx_poll() every 20 ms (or whatever your quantum
 *    duration is) as timed by your GSM Um TCH or TDM system, every tick
 *    without fail.
 *
 * 4. You can pause operation by calling osmo_twrtp_twjit_rx_ctrl() with
 *    rx_enable argument set to false, and then later restart by returning
 *    to step 2 above.  When you pause, the Rx jitter buffer will be
 *    flushed, and when you restart Rx, twjit will restart from empty state.
 *
 * Sending RTP traffic, coming from a fixed timing system:
 *
 * 1. Make the first call to osmo_twrtp_tx_quantum() whenever you are ready
 *    to send out the first quantum.
 *
 * 2. Once you've made that first call, commit to sending either another
 *    quantum or an intentional gap (osmo_twrtp_tx_skip()) every 20 ms
 *    without fail, as timed by your GSM Um TCH, T1/E1 TDM or other fixed
 *    timing system.
 *
 * 3. If you need to pause Tx output and restart later, or if some
 *    discontinuity occurs in your fixed timing system where you know that
 *    your interval between quantum sends is not the proper 20 ms or whatever
 *    your quantum duration is, call osmo_twrtp_tx_restart(), telling the
 *    library to reset the RTP timescale in its subsequent output.
 *
 * No-delay forwarding operation from one twrtp endpoint to another:
 *
 * 1. On the receiving side, call osmo_twrtp_set_raw_rx_cb() to set up an
 *    unbuffered/non-delayed Rx callback function.
 *
 * 2. In that Rx callback function, forward the packet to the other endpoint
 *    with osmo_twrtp_tx_forward().
 *
 * 3. If you are building an MGW that mostly does forwarding as described here,
 *    but occasionally inserts its own in-band tones or announcements, you can
 *    switch in real time between just-described forwarding and "native"
 *    osmo_twrtp_tx_quantum() output.  The receiving RTP end will see
 *    "handover" events as SSRC switches between the one emitted by twrtp
 *    and the one coming from the other remote party.  Actual timing will
 *    also switch, as there is no realistic way your own 20 ms timing for
 *    announcement playout will exactly match the timing of the RTP stream
 *    switched from the other remote party.
 *
 * RTCP handling is mostly internal to the library - as a user, you don't need
 * to concern yourself with it.  More precisely, incoming RTCP packets are
 * always handled internally; if you wish to send out RTCP, you have to set
 * SDES and decide if you wish to send out SR or RR packets.  Automatic
 * emission of an SR packet after every so many RTP packets, with an RR block
 * included in that SR, is the most common and most useful mode.  OTOH, if
 * your RTP application does not use RTCP, you don't need to concern yourself
 * with RTCP at all: don't configure or enable RTCP sending, and ignore the
 * existence of the built-in RTCP receiver.  Any received RTCP packets will
 * still be parsed, but you can ignore the data that result from this parsing.
 *
 * For a more detailed description, please consult the full twrtp guide
 * document that can be found in doc/twrtp directory.  This document is
 * required reading for anyone seeking to properly understand twrtp, its
 * domain of application and all of its capabilities, beyond the brief
 * summary given above.  Specific section references to this document
 * will be made in subsequent comments.
 */

/*! Each instance of twrtp in the present version exists as struct osmo_twrtp.
 *  This structure is opaque, and always constitutes a talloc context. */
struct osmo_twrtp;

/*! Stats collected during the lifetime of a twrtp instance.
 *  For a detailed description of each of these counters, see Chapter 6
 *  of twrtp guide document.
 *
 *  This stats structure is never allocated or accessed in a writable
 *  manner by applications; instead it is allocated inside the library
 *  as part of opaque struct osmo_twrtp, while applications are given
 *  const pointers to these structs.
 */
struct osmo_twrtp_stats {
	/* For ABI reasons, none of the following fields may be deleted
	 * or reordered! */
	uint32_t rx_rtp_pkt;
	uint32_t rx_rtp_badsrc;
	uint32_t rx_rtcp_pkt;
	uint32_t rx_rtcp_badsrc;
	uint32_t rx_rtcp_invalid;
	uint32_t rx_rtcp_wrong_ssrc;
	uint32_t tx_rtp_pkt;
	uint32_t tx_rtp_bytes;
	uint32_t tx_rtcp_pkt;
	/* New fields may be added here at the end; once added, they become
	 * permanent like the initially defined ones. */
};

/* declare structs that are used in our API */

struct osmo_twjit;
struct osmo_twjit_config;
struct osmo_twjit_stats;
struct osmo_twjit_rr_info;

/* public API functions: create & destroy, local and remote addresses */

struct osmo_twrtp *
osmo_twrtp_create(void *ctx, uint16_t clock_khz, uint16_t quantum_ms,
		  bool random_ts_seq,
		  const struct osmo_twjit_config *twjit_config);
void osmo_twrtp_destroy(struct osmo_twrtp *endp);

int osmo_twrtp_supply_fds(struct osmo_twrtp *endp, int rtp_fd, int rtcp_fd);
int osmo_twrtp_bind_local(struct osmo_twrtp *endp,
			  const struct osmo_sockaddr *rtp_addr, bool bind_rtcp);
int osmo_twrtp_set_remote(struct osmo_twrtp *endp,
			  const struct osmo_sockaddr *rtp_addr);

/* receiving incoming RTP via twjit */

void osmo_twrtp_twjit_rx_ctrl(struct osmo_twrtp *endp, bool rx_enable);

/* output function, to be called by TDM/GSM/etc fixed-timing side */
struct msgb *osmo_twrtp_twjit_rx_poll(struct osmo_twrtp *endp);

/* receiving incoming RTP without twjit */

/* callback function takes ownership of msgb *if* it returns true */
typedef bool (*osmo_twrtp_raw_rx_cb)(struct osmo_twrtp *endp, void *user_data,
				     struct msgb *msg);

void osmo_twrtp_set_raw_rx_cb(struct osmo_twrtp *endp, osmo_twrtp_raw_rx_cb cb,
			      void *user_data);

/* RTP Tx direction */

int osmo_twrtp_tx_quantum(struct osmo_twrtp *endp, const uint8_t *payload,
			  unsigned payload_len, uint8_t payload_type,
			  bool marker, bool auto_marker, bool send_rtcp);
void osmo_twrtp_tx_skip(struct osmo_twrtp *endp);
void osmo_twrtp_tx_restart(struct osmo_twrtp *endp);

int osmo_twrtp_tx_forward(struct osmo_twrtp *endp, struct msgb *msg);

/* support for emitting RTCP SR & RR */

int osmo_twrtp_set_sdes(struct osmo_twrtp *endp, const char *cname,
			const char *name, const char *email, const char *phone,
			const char *loc, const char *tool, const char *note);
void osmo_twrtp_set_auto_rtcp_interval(struct osmo_twrtp *endp,
					uint16_t interval);

int osmo_twrtp_send_rtcp_rr(struct osmo_twrtp *endp);

/* information retrieval functions */

struct osmo_twjit *osmo_twrtp_get_twjit(struct osmo_twrtp *endp);

const struct osmo_twrtp_stats *osmo_twrtp_get_stats(struct osmo_twrtp *endp);

/* have we received at least one RTCP RR matching our RTP Tx output? */
bool osmo_twrtp_got_rtcp_rr(struct osmo_twrtp *endp);

/* retrieving RTCP RR info: valid only if above function returned true */
uint32_t osmo_twrtp_rr_lost_word(struct osmo_twrtp *endp);
int32_t osmo_twrtp_rr_lost_cumulative(struct osmo_twrtp *endp);
uint32_t osmo_twrtp_rr_jitter_last(struct osmo_twrtp *endp);
uint32_t osmo_twrtp_rr_jitter_max(struct osmo_twrtp *endp);

/* socket-related miscellany */

int osmo_twrtp_get_rtp_fd(struct osmo_twrtp *endp);
int osmo_twrtp_get_rtcp_fd(struct osmo_twrtp *endp);

int osmo_twrtp_set_dscp(struct osmo_twrtp *endp, uint8_t dscp);
int osmo_twrtp_set_socket_prio(struct osmo_twrtp *endp, int prio);

/*! @} */
