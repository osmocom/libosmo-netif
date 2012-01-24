#ifndef _OSMO_RTP_H_
#define _OSMO_RTP_H_

/* XXX: RFC specifies that MTU should used, add generic function to obtain
	existing MTU. */
#define RTP_MSGB_SIZE  1500

struct osmo_rtp_handle *osmo_rtp_handle_create(void *ctx);
void osmo_rtp_handle_free(struct osmo_rtp_handle *h);

int osmo_rtp_handle_tx_set_sequence(struct osmo_rtp_handle *h, uint16_t seq);
int osmo_rtp_handle_tx_set_ssrc(struct osmo_rtp_handle *h, uint32_t ssrc);
int osmo_rtp_handle_tx_set_timestamp(struct osmo_rtp_handle *h, uint32_t timestamp);

int osmo_rtp_parse(struct osmo_rtp_handle *h, struct msgb *msg);
struct msgb *osmo_rtp_build(struct osmo_rtp_handle *h, uint8_t payload_type, uint32_t payload_len, const void *data, uint32_t duration);

/* supported RTP payload types. */
#define RTP_PT_GSM_FULL			3
#define RTP_PT_GSM_FULL_PAYLOAD_LEN	33
#define RTP_PT_GSM_FULL_DURATION	160	/* in samples. */

#define RTP_PT_GSM_EFR			97
#define RTP_PT_GSM_EFR_PAYLOAD_LEN	31
#define RTP_PT_GSM_EFR_DURATION		160	/* in samples. */

#endif
