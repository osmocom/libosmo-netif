/*
 * Themyscira Wireless RTP jitter buffer implementation: input processing
 * of received RTP packets.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>	/* for network byte order functions */

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/twjit.h>
#include <osmocom/netif/twjit_private.h>
#include <osmocom/netif/rtp.h>

/* raw analytics on the Rx packet stream */

static void analytics_init(struct osmo_twjit *twjit, uint32_t rx_ssrc,
			   uint16_t rx_seq)
{
	struct osmo_twjit_rr_info *rri = &twjit->rr_info;

	rri->ssrc = rx_ssrc;
	rri->rx_packets = 1;
	rri->base_seq = rx_seq;
	rri->max_seq_ext = rx_seq;
	rri->expected_pkt = 1;
	rri->jitter_accum = 0;
}

static void analytics_cont(struct osmo_twjit *twjit, uint16_t rx_seq,
			   uint32_t rx_ts, const struct timespec *now)
{
	struct osmo_twjit_rr_info *rri = &twjit->rr_info;
	uint16_t seq_ext_lo = rri->max_seq_ext;
	uint16_t seq_ext_hi = rri->max_seq_ext >> 16;
	int16_t seq_delta = (int16_t)(rx_seq - twjit->last_seq);
	int16_t seq_delta2 = (int16_t)(rx_seq - seq_ext_lo);
	int32_t ts_delta = (int32_t)(rx_ts - twjit->last_ts);
	struct timespec time_delta;
	uint32_t time_delta_tsu;
	int32_t jitter_new, ts_delta_clamp;

	/* analytics for our own stats */
	if (seq_delta < 0)
		twjit->stats.seq_backwards++;
	else if (seq_delta == 0)
		twjit->stats.seq_repeats++;
	else if (seq_delta == 1) {
		if (ts_delta != twjit->ts_quantum) {
			if (ts_delta > 0 && (ts_delta % twjit->ts_quantum) == 0)
				twjit->stats.intentional_gaps++;
			else
				twjit->stats.ts_resets++;
		}
	} else
		twjit->stats.seq_skips++;

	/* analytics for RTCP RR: packet counts */
	rri->rx_packets++;
	if (seq_delta2 > 0) {
		if (rx_seq < seq_ext_lo)
			seq_ext_hi++;
		seq_ext_lo = rx_seq;
		rri->max_seq_ext = ((uint32_t) seq_ext_hi << 16) | seq_ext_lo;
		rri->expected_pkt = rri->max_seq_ext - rri->base_seq + 1;
	}

	/* time-of-arrival analytics */
	time_delta.tv_sec = now->tv_sec - twjit->last_arrival.tv_sec;
	time_delta.tv_nsec = now->tv_nsec - twjit->last_arrival.tv_nsec;
	if (time_delta.tv_nsec < 0) {
		time_delta.tv_sec--;
		time_delta.tv_nsec += 1000000000;
	}
	/* to avoid overflows in downstream math, clamp to 1 hour */
	if (time_delta.tv_sec >= 3600) {
		time_delta.tv_sec = 3600;
		time_delta.tv_nsec = 0;
	}
	/* convert to RTP timestamp units */
	time_delta_tsu = time_delta.tv_sec * twjit->ts_units_per_sec +
			 time_delta.tv_nsec / twjit->ns_to_ts_units;
	twjit->last_arrival_delta = time_delta_tsu;
	/* jitter calculation for RTCP RR */
	ts_delta_clamp = twjit->ts_units_per_sec * 3600;
	if (ts_delta > ts_delta_clamp)
		ts_delta = ts_delta_clamp;
	else if (ts_delta < -ts_delta_clamp)
		ts_delta = -ts_delta_clamp;
	jitter_new = time_delta_tsu - ts_delta;
	if (jitter_new < 0)
		jitter_new = -jitter_new;
	rri->jitter_accum += jitter_new - ((rri->jitter_accum + 8) >> 4);
	if (jitter_new > twjit->stats.jitter_max)
		twjit->stats.jitter_max = jitter_new;
}

/* actual twjit input logic */

static void
init_subbuf_first_packet(struct osmo_twjit *twjit, struct msgb *msg,
			 uint32_t rx_ssrc, uint32_t rx_ts)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];

	OSMO_ASSERT(llist_empty(&sb->queue));
	OSMO_ASSERT(sb->depth == 0);
	/* all good, proceed */
	sb->ssrc = rx_ssrc;
	sb->head_ts = rx_ts;
	msgb_enqueue(&sb->queue, msg);
	sb->depth = 1;
	memcpy(&sb->conf, twjit->ext_config, sizeof(struct osmo_twjit_config));
	sb->drop_int_count = 0;
	/* The setting of delta_ms is needed in order to pacify the check
	 * in twjit_out.c:starting_sb_is_ready() in configurations with
	 * bd_start=1.  An alternative would be to enforce start_min_delta
	 * being not set with bd_start=1, but the present solution is
	 * simpler than doing cross-enforcement between two different
	 * parameter settings in vty. */
	sb->delta_ms = UINT32_MAX;
}

enum input_decision {
	INPUT_CONTINUE,
	INPUT_TOO_OLD,
	INPUT_RESET,
};

static enum input_decision
check_input_for_subbuf(struct osmo_twjit *twjit, bool starting,
			uint32_t rx_ssrc, uint32_t rx_ts)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];
	int32_t ts_delta;

	if (rx_ssrc != sb->ssrc)
		return INPUT_RESET;
	sb->delta_ms = twjit->last_arrival_delta / twjit->ts_units_per_ms;
	ts_delta = (int32_t)(rx_ts - sb->head_ts);
	if (ts_delta < 0)
		return INPUT_TOO_OLD;
	if (ts_delta % twjit->ts_quantum)
		return INPUT_RESET;
	if (starting) {
		if (sb->conf.start_max_delta &&
		    sb->delta_ms > sb->conf.start_max_delta)
			return INPUT_RESET;
	} else {
		uint32_t fwd = ts_delta / twjit->ts_quantum;

		if (fwd >= (uint32_t) sb->conf.max_future_sec *
			   twjit->quanta_per_sec)
			return INPUT_RESET;
	}
	return INPUT_CONTINUE;
}

static void toss_write_queue(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];

	msgb_queue_free(&sb->queue);
	sb->depth = 0;
}

static void insert_pkt_write_sb(struct osmo_twjit *twjit, struct msgb *new_msg,
				uint32_t rx_ts)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];
	uint32_t ts_delta = rx_ts - sb->head_ts;
	uint32_t ins_depth = ts_delta / twjit->ts_quantum;
	struct msgb *old_msg;
	uint32_t old_ts_delta;

	/* are we increasing total depth, and can we do simple tail append? */
	if (ins_depth >= sb->depth) {
		msgb_enqueue(&sb->queue, new_msg);
		sb->depth = ins_depth + 1;
		return;
	}
	/* nope - do it the hard way */
	llist_for_each_entry(old_msg, &sb->queue, list) {
		old_ts_delta = old_msg->cb[0] - sb->head_ts;
		if (old_ts_delta == ts_delta) {
			/* two packets with the same timestamp! */
			twjit->stats.duplicate_ts++;
			msgb_free(new_msg);
			return;
		}
		if (old_ts_delta > ts_delta)
			break;
	}
	llist_add_tail(&new_msg->list, &old_msg->list);
}

static void trim_starting_sb(struct osmo_twjit *twjit)
{
	struct twjit_subbuf *sb = &twjit->sb[twjit->write_sb];
	struct msgb *msg;
	uint32_t msg_ts, ts_adv, quantum_adv;

	while (sb->depth > sb->conf.bd_start) {
		msg = msgb_dequeue(&sb->queue);
		OSMO_ASSERT(msg);
		msgb_free(msg);
		OSMO_ASSERT(!llist_empty(&sb->queue));
		msg = llist_entry(sb->queue.next, struct msgb, list);
		msg_ts = msg->cb[0];
		ts_adv = msg_ts - sb->head_ts;
		quantum_adv = ts_adv / twjit->ts_quantum;
		OSMO_ASSERT(sb->depth > quantum_adv);
		sb->head_ts = msg_ts;
		sb->depth -= quantum_adv;
	}
}

void osmo_twjit_input(struct osmo_twjit *twjit, struct msgb *msg)
{
	bool got_previous_input = twjit->got_first_packet;
	struct rtp_hdr *rtph;
	uint32_t rx_ssrc, rx_ts;
	uint16_t rx_seq;
	struct timespec now;
	enum input_decision id;

	rtph = osmo_rtp_get_hdr(msg);
	if (!rtph) {
		twjit->stats.bad_packets++;
		msgb_free(msg);
		return;
	}
	rx_ssrc = ntohl(rtph->ssrc);
	rx_ts = ntohl(rtph->timestamp);
	rx_seq = ntohs(rtph->sequence);
	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	if (!got_previous_input) {
		analytics_init(twjit, rx_ssrc, rx_seq);
		twjit->got_first_packet = true;
	} else if (rx_ssrc != twjit->rr_info.ssrc) {
		twjit->stats.ssrc_changes++;
		analytics_init(twjit, rx_ssrc, rx_seq);
	} else
		analytics_cont(twjit, rx_seq, rx_ts, &now);
	twjit->last_seq = rx_seq;
	twjit->last_ts = rx_ts;
	memcpy(&twjit->last_arrival, &now, sizeof(struct timespec));
	twjit->stats.rx_packets++;
	msg->cb[0] = rx_ts;

	switch (twjit->state) {
	case TWJIT_STATE_EMPTY:
		/* first packet into totally empty buffer */
		if (got_previous_input)
			twjit->stats.underruns++;
		twjit->state = TWJIT_STATE_HUNT;
		twjit->write_sb = 0;
		init_subbuf_first_packet(twjit, msg, rx_ssrc, rx_ts);
		return;
	case TWJIT_STATE_HUNT:
	case TWJIT_STATE_HANDOVER:
		id = check_input_for_subbuf(twjit, true, rx_ssrc, rx_ts);
		if (id == INPUT_TOO_OLD) {
			msgb_free(msg);
			return;
		}
		if (id == INPUT_RESET) {
			toss_write_queue(twjit);
			init_subbuf_first_packet(twjit, msg, rx_ssrc, rx_ts);
			return;
		}
		insert_pkt_write_sb(twjit, msg, rx_ts);
		trim_starting_sb(twjit);
		return;
	case TWJIT_STATE_FLOWING:
		id = check_input_for_subbuf(twjit, false, rx_ssrc, rx_ts);
		if (id == INPUT_TOO_OLD) {
			twjit->stats.too_old++;
			msgb_free(msg);
			return;
		}
		if (id == INPUT_RESET) {
			twjit->state = TWJIT_STATE_HANDOVER;
			twjit->write_sb = !twjit->write_sb;
			init_subbuf_first_packet(twjit, msg, rx_ssrc, rx_ts);
			twjit->stats.handovers_in++;
			return;
		}
		insert_pkt_write_sb(twjit, msg, rx_ts);
		return;
	default:
		OSMO_ASSERT(0);
	}
}
