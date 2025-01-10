/*
 * Themyscira Wireless RTP endpoint implementation: interface to twjit
 * layer below.  Use of twjit is optional in the strict sense, but it
 * is used most of the time.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdbool.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/twjit.h>

void osmo_twrtp_twjit_rx_enable(struct osmo_twrtp *endp)
{
	OSMO_ASSERT(endp->twjit);
	endp->twjit_rx_enable = true;
}

void osmo_twrtp_twjit_rx_disable(struct osmo_twrtp *endp)
{
	OSMO_ASSERT(endp->twjit);
	endp->twjit_rx_enable = false;
	osmo_twjit_reset(endp->twjit);
}

struct msgb *osmo_twrtp_twjit_rx_poll(struct osmo_twrtp *endp)
{
	return osmo_twjit_output(endp->twjit);
}

void osmo_twrtp_new_twjit_config(struct osmo_twrtp *endp,
				 const struct osmo_twjit_config *config)
{
	osmo_twjit_new_config(endp->twjit, config);
}

const struct osmo_twjit_stats *
osmo_twrtp_get_twjit_stats(struct osmo_twrtp *endp)
{
	return osmo_twjit_get_stats(endp->twjit);
}

const struct osmo_twjit_rr_info *
osmo_twrtp_get_twjit_rr_info(struct osmo_twrtp *endp)
{
	return osmo_twjit_get_rr_info(endp->twjit);
}

bool osmo_twrtp_twjit_got_input(struct osmo_twrtp *endp)
{
	return osmo_twjit_got_any_input(endp->twjit);
}
