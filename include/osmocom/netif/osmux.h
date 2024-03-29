#ifndef _OSMUX_H_
#define _OSMUX_H_

#include <osmocom/core/endian.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>

/*! \addtogroup osmux
 *  @{
 */

/*! \file osmux.h
 *  Osmocom multiplex protocol helpers
 */

#define OSMUX_DEFAULT_PORT 1984

/*! \struct osmux_hdr
 * OSmux header:
 *
 *	rtp_m (1 bit):		RTP M field (RFC3550, RFC4867)
 *	ft (2 bits):		0=signalling, 1=voice, 2=dummy
 *	ctr (3 bits):		Number of batched AMR payloads (starting 0)
 *	amr_f (1 bit):		AMR F field (RFC3267)
 *	amr_q (1 bit): 		AMR Q field (RFC3267)
 * 	seq (8 bits): 		Combination of RTP timestamp and seq. number
 * 	circuit_id (8 bits):	Circuit ID, ie. Call identifier.
 *	amr_ft (4 bits):	AMR FT field (RFC3267)
 * 	amr_cmr (4 bits): 	AMR CMT field (RFC3267)
 */

#define OSMUX_FT_SIGNAL		0
#define OSMUX_FT_VOICE_AMR	1
#define OSMUX_FT_DUMMY		2

/*! Osmux protocol header */
struct osmux_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t amr_q:1,
		amr_f:1,
		ctr:3,
		ft:2,
		rtp_m:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t rtp_m:1, ft:2, ctr:3, amr_f:1, amr_q:1;
#endif
	uint8_t seq;
#define OSMUX_CID_MAX		255	/* determined by circuit_id */
	uint8_t circuit_id;
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t amr_cmr:4,
		amr_ft:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t amr_ft:4, amr_cmr:4;
#endif
	uint8_t data[0];
} __attribute__((packed));

/*! one to handle all existing RTP flows */
struct osmux_in_handle {
	/*! Initial Osmux seqnum for each circuit, set during osmux_xfrm_input_open_circuit() */
	uint8_t osmux_seq;
	uint8_t batch_factor;
	uint16_t batch_size;

	struct {
		uint32_t input_rtp_msgs;
		uint32_t output_osmux_msgs;
		uint64_t input_rtp_bytes;
		uint64_t output_osmux_bytes;
	} stats;

	void (*deliver)(struct msgb *msg, void *data);
	void *data;
	char *internal_data;	/* internal data to store batch */
};

#define OSMUX_MAX_CONCURRENT_CALLS	8

typedef struct msgb *(*rtp_msgb_alloc_cb_t)(void *rtp_msgb_alloc_priv_data,
					    unsigned int msg_len);
/*! one per OSmux circuit_id, ie. one per RTP flow. */
struct osmux_out_handle {
	uint16_t rtp_seq;
	uint32_t rtp_timestamp;
	uint32_t rtp_ssrc;
	uint8_t rtp_payload_type;
	uint8_t osmux_seq_ack; /* Latest received seq num */
	struct osmo_timer_list	timer;
	struct llist_head list;
	void (*tx_cb)(struct msgb *msg, void *data); /* Used defined rtp tx callback */
	void *data; /* User defined opaque data structure */
	rtp_msgb_alloc_cb_t rtp_msgb_alloc_cb; /* User defined msgb alloc function for generated RTP pkts */
	void *rtp_msgb_alloc_cb_data; /* Opaque data pointer set by user and passed in rtp_msgb_alloc_cb() */
};

/*! return pointer to osmux payload (behind osmux_hdr) */
static inline uint8_t *osmux_get_payload(struct osmux_hdr *osmuxh)
{
	return (uint8_t *)osmuxh + sizeof(struct osmux_hdr);
}

int osmux_snprintf(char *buf, size_t size, struct msgb *msg);

/* 1500 - sizeof(iphdr) = 20 bytes - sizeof(udphdr) = 8 bytes. */
#define OSMUX_BATCH_DEFAULT_MAX		1472

struct osmux_in_handle *osmux_xfrm_input_alloc(void *ctx);
void osmux_xfrm_input_init(struct osmux_in_handle *h) OSMO_DEPRECATED("Use osmux_xfrm_input_alloc() instead");
void osmux_xfrm_input_fini(struct osmux_in_handle *h) OSMO_DEPRECATED("Use talloc_free() instead");
void osmux_xfrm_input_set_name(struct osmux_in_handle *h, const char *name);
int osmux_xfrm_input_set_batch_factor(struct osmux_in_handle *h, uint8_t batch_factor);
void osmux_xfrm_input_set_batch_size(struct osmux_in_handle *h, uint16_t batch_size);
void osmux_xfrm_input_set_initial_seqnum(struct osmux_in_handle *h, uint8_t osmux_seqnum);
void osmux_xfrm_input_set_deliver_cb(struct osmux_in_handle *h, void (*deliver_cb)(struct msgb *msg, void *data), void *data);
void *osmux_xfrm_input_get_deliver_cb_data(struct osmux_in_handle *h);

int osmux_xfrm_input_open_circuit(struct osmux_in_handle *h, int ccid, int dummy);
void osmux_xfrm_input_close_circuit(struct osmux_in_handle *h, int ccid);

int osmux_xfrm_input(struct osmux_in_handle *h, struct msgb *msg, int ccid);
void osmux_xfrm_input_deliver(struct osmux_in_handle *h);

struct osmux_out_handle *osmux_xfrm_output_alloc(void *ctx);
void osmux_xfrm_output_init(struct osmux_out_handle *h, uint32_t rtp_ssrc) OSMO_DEPRECATED("Use osmux_xfrm_output_alloc() and osmux_xfrm_output_set_rtp_*() instead");
void osmux_xfrm_output_init2(struct osmux_out_handle *h, uint32_t rtp_ssrc, uint8_t rtp_payload_type) OSMO_DEPRECATED("Use osmux_xfrm_output_alloc() and osmux_xfrm_output_set_rtp_*() instead");
void osmux_xfrm_output_set_rtp_ssrc(struct osmux_out_handle *h, uint32_t rtp_ssrc);
void osmux_xfrm_output_set_rtp_pl_type(struct osmux_out_handle *h, uint32_t rtp_payload_type);
void osmux_xfrm_output_set_tx_cb(struct osmux_out_handle *h, void (*tx_cb)(struct msgb *msg, void *data), void *data);
void osmux_xfrm_output_set_rtp_msgb_alloc_cb(struct osmux_out_handle *h, rtp_msgb_alloc_cb_t cb, void *cb_data);
int osmux_xfrm_output_sched(struct osmux_out_handle *h, struct osmux_hdr *osmuxh);
void osmux_xfrm_output_flush(struct osmux_out_handle *h);
struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg);
/*! @} */

#endif
