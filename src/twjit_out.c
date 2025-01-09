/*
 * Themyscira Wireless RTP jitter buffer implementation:
 * output to the fixed timing system.
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
#include <osmocom/core/utils.h>

#include <osmocom/netif/twjit.h>
#include <osmocom/netif/twjit_private.h>

static bool starting_sb_is_ready(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];

	if (sb->depth < sb->conf.bd_start)
		return false;
	if (sb->delta_ms < sb->conf.start_min_delta)
		return false;
	return true;
}

static bool read_sb_is_empty(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->read_sb];

	return sb->depth == 0;
}

static struct msgb *pull_from_read_sb(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->read_sb];
	struct msgb *msg;

	OSMO_ASSERT(!llist_empty(&sb->queue));
	OSMO_ASSERT(sb->depth > 0);
	msg = llist_entry(sb->queue.next, struct msgb, list);
	if (msg->cb[0] == sb->head_ts) {
		llist_del(&msg->list);
		twjit->stats.delivered_pkt++;
	} else {
		msg = NULL;
		twjit->stats.output_gaps++;
	}
	sb->head_ts += twjit->ts_quantum;
	sb->depth--;
	return msg;
}

static void read_sb_thinning(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->read_sb];
	struct msgb *msg;

	if (sb->drop_int_count) {
		sb->drop_int_count--;
		return;
	}
	if (sb->depth <= sb->conf.bd_hiwat)
		return;
	twjit->stats.thinning_drops++;
	msg = pull_from_read_sb(twjit);
	if (msg)
		msgb_free(msg);
	sb->drop_int_count = sb->conf.thinning_int - 2;
}

static void toss_read_queue(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->read_sb];

	msgb_queue_free(&sb->queue);
	sb->depth = 0;
}

struct msgb *osmo_twjit_output(struct osmo_twjit *twjit)
{
	switch (twjit->state) {
	case TWJIT_STATE_EMPTY:
		return NULL;
	case TWJIT_STATE_HUNT:
		if (!starting_sb_is_ready(twjit))
			return NULL;
		twjit->state = TWJIT_STATE_FLOWING;
		twjit->read_sb = twjit->write_sb;
		return pull_from_read_sb(twjit);
	case TWJIT_STATE_FLOWING:
		if (read_sb_is_empty(twjit)) {
			twjit->state = TWJIT_STATE_EMPTY;
			return NULL;
		}
		read_sb_thinning(twjit);
		return pull_from_read_sb(twjit);
	case TWJIT_STATE_HANDOVER:
		if (starting_sb_is_ready(twjit)) {
			toss_read_queue(twjit);
			twjit->stats.handovers_out++;
			twjit->state = TWJIT_STATE_FLOWING;
			twjit->read_sb = twjit->write_sb;
			return pull_from_read_sb(twjit);
		}
		if (read_sb_is_empty(twjit)) {
			twjit->state = TWJIT_STATE_HUNT;
			twjit->stats.ho_underruns++;
			return NULL;
		}
		read_sb_thinning(twjit);
		return pull_from_read_sb(twjit);
	default:
		OSMO_ASSERT(0);
	}
}
