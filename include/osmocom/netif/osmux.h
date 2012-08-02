#ifndef _OSMUX_H_
#define _OSMUX_H_

/* OSmux header:
 *
 *	ft (4 bits):		0=signalling, 1=voice (AMR-CMR)
 * 	amr_cmr (4 bits): 	see cmr field in AMR header (RFC3267)
 * 	circuit_id (8 bits):	simplified version of RTP SSRC
 * 	seq (8-bits): 		combination of RTP timestamp and seq. number
 *	amr_f (1-bits):		AMR f bit (RFC3267)
 *	amr_ft (4-bits):	AMR ft bit (RFC3267)
 *	amr_q (1-bits): 	AMR q bit (RFC3267)
 * 	rtp_marker (1 bits):	RTP marker
 */

#define OSMUX_FT_SIGNAL		0
#define OSMUX_FT_VOICE_AMR	1

struct osmux_hdr {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ft:4,
		amr_cmr:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t amr_cmr:4,
		ft:4;
#endif
	uint8_t circuit_id;
	uint8_t seq;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t amr_f:1,
		amr_ft:4,
		amr_q:1,
		rtp_marker:1,
		pad:1;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t pad:1,
		rtp_marker:1,
		amr_q:1,
		amr_ft:4,
		amr_f:1;
#endif
} __attribute__((packed));

/* one to handle all existing RTP flows */
struct osmux_in_handle {
	uint8_t osmux_seq;
	void (*deliver)(struct msgb *msg);
};

/* one per OSmux circuit_id, ie. one per RTP flow. */
struct osmux_out_handle {
	uint16_t rtp_seq;
	uint32_t rtp_timestamp;
};

static inline uint8_t *osmux_get_payload(struct osmux_hdr *osmuxh)
{
	return (uint8_t *)osmuxh + sizeof(struct osmux_hdr);
}

void osmux_xfrm_input_init(struct osmux_in_handle *h);
int osmux_xfrm_input(struct msgb *msg);
void osmux_xfrm_input_deliver(struct osmux_in_handle *h);

struct msgb *osmux_xfrm_output(struct osmux_hdr *osmuxh, struct osmux_out_handle *h);
struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg);

void osmux_tx_sched(struct msgb *msg, struct timeval *when, void (*tx_cb)(struct msgb *msg, void *data), void *data);

#endif
