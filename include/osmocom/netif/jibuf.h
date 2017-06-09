#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <osmocom/core/timer.h>

/*! \defgroup jibuf Osmocom Jitter Buffer
 *  @{
 */

/*! \file jibuf.h
 *  \brief Osmocom Jitter Buffer helpers
 */

typedef void (*osmo_jibuf_dequeue_cb)(struct msgb *msg, void *data);

/*! \brief A structure representing a single instance of a jitter buffer */
struct osmo_jibuf {
	void *talloc_ctx;
	bool started;
	struct osmo_timer_list timer;
	struct llist_head msg_list; /* sorted by output ts */
	uint32_t min_delay; /* in msec */
	uint32_t max_delay; /* in msec */
	uint32_t threshold_delay; /* in msec */

	osmo_jibuf_dequeue_cb dequeue_cb;
	void *dequeue_cb_data;

	/* number of pkt drops since we last changed the buffer size */
	uint32_t last_dropped;
	uint32_t consecutive_drops;

	uint32_t ref_rx_ts;
	uint32_t ref_tx_ts;
	uint16_t ref_tx_seq;

	struct timeval last_enqueue_time;
	struct timeval next_dequeue_time;

	bool skew_enabled;
	int32_t skew_us; /* src clock skew, in usec */

	struct {
		uint32_t total_enqueued;
		uint64_t total_dropped;
	} stats;
};


struct osmo_jibuf *osmo_jibuf_alloc(void *talloc_ctx);

void osmo_jibuf_delete(struct osmo_jibuf *jb);

int osmo_jibuf_enqueue(struct osmo_jibuf *jb, struct msgb *msg);

bool osmo_jibuf_empty(struct osmo_jibuf *jb);

void osmo_jibuf_set_min_delay(struct osmo_jibuf *jb, uint32_t min_delay);
void osmo_jibuf_set_max_delay(struct osmo_jibuf *jb, uint32_t max_delay);

void osmo_jibuf_enable_skew_compensation(struct osmo_jibuf *jb, bool enable);

void osmo_jibuf_set_dequeue_cb(struct osmo_jibuf *jb, osmo_jibuf_dequeue_cb dequeue_cb, void* cb_data);

/*! @} */
