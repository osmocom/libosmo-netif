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
#include <osmocom/core/socket.h>

/*
 * Each instance of twrtp in the present version exists as struct osmo_twrtp.
 * This structure is opaque, and always constitutes a talloc context.
 */
struct osmo_twrtp;

/*
 * Stats collected during the lifetime of a twrtp instance.
 */
struct osmo_twrtp_stats {
	uint32_t rx_rtp_pkt;
	uint32_t rx_rtp_badsrc;
	uint32_t rx_rtcp_pkt;
	uint32_t rx_rtcp_badsrc;
	uint32_t rx_rtcp_invalid;
	uint32_t rx_rtcp_wrong_ssrc;
	uint32_t tx_rtp_pkt;
	uint32_t tx_rtp_bytes;
	uint32_t tx_rtcp_pkt;
};

/* declare structs that are used in our API */

struct msgb;
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

int osmo_twrtp_bind_local_ipv4(struct osmo_twrtp *endp,
				const struct in_addr *ip, uint16_t port);
int osmo_twrtp_bind_local_ipv6(struct osmo_twrtp *endp,
				const struct in6_addr *ip6, uint16_t port);
int osmo_twrtp_bind_local_sin(struct osmo_twrtp *endp,
				const struct sockaddr_in *sin);
int osmo_twrtp_bind_local_sin6(struct osmo_twrtp *endp,
				const struct sockaddr_in6 *sin6);

void osmo_twrtp_set_remote_ipv4(struct osmo_twrtp *endp,
				const struct in_addr *ip, uint16_t port);
void osmo_twrtp_set_remote_ipv6(struct osmo_twrtp *endp,
				const struct in6_addr *ip6, uint16_t port);
void osmo_twrtp_set_remote_sin(struct osmo_twrtp *endp,
				const struct sockaddr_in *sin);
void osmo_twrtp_set_remote_sin6(struct osmo_twrtp *endp,
				const struct sockaddr_in6 *sin6);

/* receiving incoming RTP via twjit */

void osmo_twrtp_twjit_rx_enable(struct osmo_twrtp *endp);
void osmo_twrtp_twjit_rx_disable(struct osmo_twrtp *endp);

/* output function, to be called by TDM/GSM/etc fixed-timing side */
struct msgb *osmo_twrtp_twjit_rx_poll(struct osmo_twrtp *endp);

void osmo_twrtp_new_twjit_config(struct osmo_twrtp *endp,
				 const struct osmo_twjit_config *config);

/* receiving incoming RTP without twjit */

/* callback function takes ownership of msgb! */
typedef void (*osmo_twrtp_raw_rx_cb)(struct osmo_twrtp *endp, void *user_data,
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

/* stats retrieval: valid with or without twjit */

const struct osmo_twrtp_stats *osmo_twrtp_get_stats(struct osmo_twrtp *endp);

/* have we received at least one RTCP RR matching our RTP Tx output? */
bool osmo_twrtp_got_rtcp_rr(struct osmo_twrtp *endp);

/* retrieving RTCP RR info: valid only if above function returned true */
uint32_t osmo_twrtp_rr_lost_word(struct osmo_twrtp *endp);
int32_t osmo_twrtp_rr_lost_cumulative(struct osmo_twrtp *endp);
uint32_t osmo_twrtp_rr_jitter_last(struct osmo_twrtp *endp);
uint32_t osmo_twrtp_rr_jitter_max(struct osmo_twrtp *endp);

/* retrieving additional info from twjit layer */

const struct osmo_twjit_stats *
osmo_twrtp_get_twjit_stats(struct osmo_twrtp *endp);

const struct osmo_twjit_rr_info *
osmo_twrtp_get_twjit_rr_info(struct osmo_twrtp *endp);

bool osmo_twrtp_twjit_got_input(struct osmo_twrtp *endp);

/* socket-related miscellany */

int osmo_twrtp_set_dscp(struct osmo_twrtp *endp, uint8_t dscp);
int osmo_twrtp_set_socket_prio(struct osmo_twrtp *endp, int prio);
