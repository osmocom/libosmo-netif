/*
 * Themyscira Wireless RTP jitter buffer implementation: basic functions,
 * everything that isn't factored out into input handling, output handling
 * or vty config modules.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/twjit.h>
#include <osmocom/netif/twjit_private.h>

void osmo_twjit_init_defaults(struct osmo_twjit_config *config)
{
	memset(config, 0, sizeof(struct osmo_twjit_config));

	/* While the theoretical minimum starting fill level is 1, the
	 * practically useful minimum (achieving lowest latency, but not
	 * incurring underruns in normal healthy operation) is 2 for typical
	 * network configurations that combine elements with "perfect" 20 ms
	 * timing (T1/E1 interfaces, external IP-PSTN links, software
	 * transcoders timed by system clock etc) and GSM-to-IP OsmoBTS
	 * whose 20 ms timing contains the small inherent jitter of TDMA. */
	config->bd_start = 2;

	/* The high water mark setting determines when the standing queue
	 * thinning mechanism kicks in.  A standing queue that is longer
	 * than the starting fill level will occur when the flow starts
	 * during a network latency spike, but then the network latency
	 * goes down.  If this setting is too high, deep standing queues
	 * will persist, adding needless latency to speech or CSD.
	 * If this setting is too low, the thinning mechanism will be
	 * too invasive, needlessly and perhaps frequently deleting a quantum
	 * of speech or data from the stream and incurring a phase shift.
	 * Starting fill level plus 2 seems like a good default. */
	config->bd_hiwat = 4;

	/* When the standing queue thinning mechanism does kick in,
	 * it drops every Nth packet, where N is the thinning interval.
	 * Given that this mechanism forcibly deletes a quantum of speech
	 * or data from the stream, these induced disruptions should be
	 * spaced out, and the managing operator should also keep in mind
	 * that the incurred phase shift may be a problem for some
	 * applications, particularly CSD.  Our current default is
	 * a prime number, reducing the probability that the thinning
	 * mechanism will interfere badly with intrinsic features of the
	 * stream being thinned.  17 quantum units at 20 ms per quantum
	 * is 340 ms, which should be sufficiently long spacing to make
	 * speech quantum deletions tolerable. */
	config->thinning_int = 17;

	/* With RTP timestamps being 32 bits and with the usual RTP
	 * clock rate of 8000 timestamp units per second, a packet may
	 * arrive that claims to be as far as 3 days into the future.
	 * Such aberrant RTP packets are jocularly referred to as
	 * time travelers.  Assuming that actual time travel either
	 * does not exist at all or at least does not happen in the
	 * present context, we reason that when such "time traveler" RTP
	 * packets do arrive, we must be dealing with the effect of a
	 * software bug or misdesign or misconfiguration in whatever
	 * foreign network element is sending us RTP.  In any case,
	 * irrespective of the cause, we must be prepared for the
	 * possibility of seeming "time travel" in the incoming RTP stream.
	 * We implement an arbitrary threshold: if the received RTP ts
	 * is too far into the future, we treat that packet as the
	 * beginning of a new stream, same as SSRC change or non-quantum
	 * ts increment.  This threshold has 1 s granularity, which is
	 * sufficient for its intended purpose of catching gross errors.
	 * The minimum setting of this threshold is 1 s, but let's
	 * default to 10 s, being generous to networks with really bad
	 * latency. */
	config->max_future_sec = 10;
}

/* create and destroy functions */

struct osmo_twjit *osmo_twjit_create(void *ctx, uint16_t clock_khz,
				     uint16_t quantum_ms,
				     const struct osmo_twjit_config *config)
{
	struct osmo_twjit *twjit;

	twjit = talloc_zero(ctx, struct osmo_twjit);
	if (!twjit)
		return NULL;

	twjit->ext_config = config;
	twjit->state = TWJIT_STATE_EMPTY;
	INIT_LLIST_HEAD(&twjit->sb[0].queue);
	INIT_LLIST_HEAD(&twjit->sb[1].queue);
	twjit->ts_quantum = (uint32_t) quantum_ms * clock_khz;
	twjit->quanta_per_sec = 1000 / quantum_ms;
	twjit->ts_units_per_ms = clock_khz;
	twjit->ts_units_per_sec = (uint32_t) clock_khz * 1000;
	twjit->ns_to_ts_units = 1000000 / clock_khz;

	return twjit;
}

void osmo_twjit_destroy(struct osmo_twjit *twjit)
{
	msgb_queue_free(&twjit->sb[0].queue);
	msgb_queue_free(&twjit->sb[1].queue);
	talloc_free(twjit);
}

/* Here is how twjit config works: every twjit instance remembers
 * a pointer to struct osmo_twjit_config, either the initial one
 * given to osmo_twjit_create() or an updated one set with
 * osmo_twjit_new_config().  However, the memory holding this
 * config structure remains owned by the application, and all
 * config settings therein may be freely changed by vty at any time.
 * In the case of changes to twjit config after the call to
 * osmo_twjit_create(), whether these changes are done by feeding
 * a new config structure to osmo_twjit_new_config() or by changing
 * values in the previously-supplied structure, all changes take
 * effect atomically whenever a new sub-buffer is initialized,
 * upon receiving the first RTP packet into a completely empty
 * buffer or upon receiving a packet that constitutes handover.
 */
void osmo_twjit_new_config(struct osmo_twjit *twjit,
			   const struct osmo_twjit_config *config)
{
	twjit->ext_config = config;
}

/* The following reset function is intended to be called when the
 * application stops doing regular (once every time quantum) reads
 * from the jitter buffer, but may resume this activity later.
 * All packet Rx state and queues are cleared, but "lifetime"
 * statistical counters are NOT reset.
 */
void osmo_twjit_reset(struct osmo_twjit *twjit)
{
	msgb_queue_free(&twjit->sb[0].queue);
	msgb_queue_free(&twjit->sb[1].queue);
	twjit->state = TWJIT_STATE_EMPTY;
	twjit->sb[0].depth = 0;
	twjit->sb[1].depth = 0;
	twjit->got_first_packet = false;
}

/* simple information retrieval functions */

const struct osmo_twjit_stats *
osmo_twjit_get_stats(struct osmo_twjit *twjit)
{
	return &twjit->stats;
}

const struct osmo_twjit_rr_info *
osmo_twjit_get_rr_info(struct osmo_twjit *twjit)
{
	return &twjit->rr_info;
}

bool osmo_twjit_got_any_input(struct osmo_twjit *twjit)
{
	return twjit->got_first_packet;
}
