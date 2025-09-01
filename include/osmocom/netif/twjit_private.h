/*
 * Themyscira Wireless RTP jitter buffer implementation:
 * internal config structure.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*! \cond private */

/*! twjit configuration tunings, usually set via vty.
 *  This config structure always has to be provided in order to
 *  create a twjit instance.  However, due to ABI concerns
 *  (retaining ability to add new fields to this structure),
 *  the struct itself has been made opaque, with actual definition
 *  visible only inside the library.
 *
 *  In most twjit-using applications, the library's vty module
 *  will take care of both displaying and changing these tunable
 *  settings.  However, setter APIs are also provided for non-vty
 *  users.
 *
 *  The set of configurable parameters contained in this structure
 *  is covered in twrtp guide document section 2.4.
 */
struct osmo_twjit_config {
	/*! buffer depth: starting minimum, formally called flow-starting
	 *  fill level.  Document section: 2.3.3. */
	uint16_t bd_start;
	/*! buffer depth: high water mark, formally called high water mark
	 *  fill level.  Document section: 2.3.4.2. */
	uint16_t bd_hiwat;
	/*! interval for thinning of too-deep standing queue;
	 *  document section: 2.3.4.2. */
	uint16_t thinning_int;
	/*! guard against time traveler RTP packets, 1 s units;
	 *  document section: 2.3.4.3. */
	uint16_t max_future_sec;
	/*! min time delta in starting state, 1 ms units, 0 means not set;
	 *  document section: 2.3.3.2. */
	uint16_t start_min_delta;
	/*! max time delta in starting state, 1 ms units, 0 means not set;
	 *  document section: 2.3.3.2. */
	uint16_t start_max_delta;
	/*! Osmocom addition, not in ThemWi original: should RTP packets
	 *  with M bit set cause a handover or HUNT state reset just like
	 *  an SSRC change?  With this option enabled, M bit is treated
	 *  like an SSRC change in that the timestamp is not considered
	 *  at all, on the reasoning that the sender may have switched
	 *  to an entirely unrelated source of timestamps. */
	bool handover_on_marker;
};

/*! \endcond */
