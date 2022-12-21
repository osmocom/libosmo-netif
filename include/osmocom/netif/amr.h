#ifndef _OSMO_AMR_H_
#define _OSMO_AMR_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/endian.h>

/* As defined by RFC3267: Adaptive Multi-Rate (AMR) */

/*
 *  +----------------+-------------------+----------------
 *  | payload header | table of contents | speech data ...
 *  +----------------+-------------------+----------------
 */

/*
 * 4.3. Bandwidth-Efficient Mode:
 *
 * Summary from 4.3.4: Same as Octet aligned (see below) but without padding after header and ToC:
 *  0               1
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  CMR  |F|  FT   |Q|X X X X X X|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * X means AMR payload (padding in case of FT=NO_DATA).
 */
struct amr_hdr_bwe {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t ft_hi:3, /* coding mode highest part */
		f:1,
		cmr:4;	/* Codec Mode Request */
	uint8_t data_start:6,
		q:1,	/* OK (not damaged) at origin? */
		ft_lo:1;	/* coding mode lowest bit */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t cmr:4, f:1, ft_hi:3;
	uint8_t ft_lo:1, q:1, data_start:6;
#endif
	uint8_t data[0];
} __attribute__((packed));

/*
 * 4.4. Octet-aligned Mode:
 *
 * 4.4.1. The Payload Header:
 *
 *   0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |  CMR  |X X X X|
 *  +-+-+-+-+-+-+-+-+
 *
 * According to: 3GPP TS 26.201 "AMR Wideband speech codec; Frame Structure",
 * version 5.0.0 (2001-03), 3rd Generation Partnership Project (3GPP):
 *
 * Possible Frame type / CMR values:
 *
 * 0-8 for AMR-WB (from 6.60 kbit/s to 23.85 kbit/s)
 * 9 (SID) confort noise.
 * 10-13 future use.
 * 14 means lost speech frame (only available for AMR-WB)
 * 15 means no data
 *
 * 4.4.2. The table of contents:
 *
 *   0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |F|  FT   |Q|X X|
 *  +-+-+-+-+-+-+-+-+
 *
 * X means padding.
 */

struct amr_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	/* Payload Header */
	uint8_t pad1:4,
		cmr:4;	/* Codec Mode Request */
	/* Table of Contents */
	uint8_t pad2:2,
		q:1,	/* OK (not damaged) at origin? */
		ft:4,	/* coding mode */
		f:1;	/* followed by another speech frame? */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t cmr:4, pad1:4;
	uint8_t f:1, ft:4, q:1, pad2:2;
#endif
	uint8_t data[0];
} __attribute__((packed));

static inline void *osmo_amr_get_payload(struct amr_hdr *amrh)
{
	return (uint8_t *)amrh + sizeof(struct amr_hdr);
}

/* AMR voice frame type identifiers
 * See also 3GPP TS 26.101, Table 1a: Interpretation of Frame Type, Mode
 * Indication and Mode Request fields */
#define AMR_FT_0		0	/* 4.75 */
#define AMR_FT_1		1	/* 5.15 */
#define AMR_FT_2		2	/* 5.90 */
#define AMR_FT_3		3	/* 6.70 */
#define AMR_FT_4		4	/* 7.40 */
#define AMR_FT_5		5	/* 7.95 */
#define AMR_FT_6		6	/* 10.2 */
#define AMR_FT_7		7	/* 12.2 */
#define AMR_FT_SID		8	/* AMR SID */
#define AMR_FT_GSM_EFR_SID	9	/* GSM-EFR SID */
#define AMR_FT_TDMA_EFR_SID	10	/* TDMA-EFR SID */
#define AMR_FT_PDC_EFR_SID	11	/* PDC-EFR SID */
/* version 16.0.0 Release 16: 12-14 for future use */
#define AMR_FT_NO_DATA		15	/* NO_DATA */
#define AMR_FT_MAX		16	/* INTERNAL, NO NOT USE OUTSIDE libosmo-netif */

/* AMR voice frame length (in bits).
 * See also RFC 3267, chapter 3.6.
 *
 * NOTE: These constants refer to the length of one AMR speech frame-block,
 * not counting CMR, TOC. */
#define AMR_FT_0_LEN_BITS		95	/* 4.75 */
#define AMR_FT_1_LEN_BITS		103	/* 5.15 */
#define AMR_FT_2_LEN_BITS		118	/* 5.90 */
#define AMR_FT_3_LEN_BITS		134	/* 6.70 */
#define AMR_FT_4_LEN_BITS		148	/* 7.40 */
#define AMR_FT_5_LEN_BITS		159	/* 7.95 */
#define AMR_FT_6_LEN_BITS		204	/* 10.2 */
#define AMR_FT_7_LEN_BITS		244	/* 12.2 */
#define AMR_FT_SID_LEN_BITS		39	/* SID */
#define AMR_FT_GSM_EFR_SID_LEN_BITS	43	/* GSM-EFR SID */
#define AMR_FT_TDMA_EFR_SID_LEN_BITS	38	/* TDMA-EFR SID */
#define AMR_FT_PDC_EFR_SID_LEN_BITS	37	/* PDC-EFR SID */
/* version 16.0.0 Release 16: 12-14 for future use */
#define AMR_FT_NO_DATA_LEN_BITS		0	/* NO_DATA */

/* AMR voice frame length (in bytes, rounded).
 *
 * NOTE: These constants refer to the length of one AMR speech frame-block,
 * not counting CMR, TOC. */
#define AMR_FT_0_LEN		((AMR_FT_0_LEN_BITS+7)/8)		/* 4.75 */
#define AMR_FT_1_LEN		((AMR_FT_1_LEN_BITS+7)/8)		/* 5.15 */
#define AMR_FT_2_LEN		((AMR_FT_2_LEN_BITS+7)/8)		/* 5.90 */
#define AMR_FT_3_LEN		((AMR_FT_3_LEN_BITS+7)/8)		/* 6.70 */
#define AMR_FT_4_LEN		((AMR_FT_4_LEN_BITS+7)/8)		/* 7.40 */
#define AMR_FT_5_LEN		((AMR_FT_5_LEN_BITS+7)/8)		/* 7.95 */
#define AMR_FT_6_LEN		((AMR_FT_6_LEN_BITS+7)/8)		/* 10.2 */
#define AMR_FT_7_LEN		((AMR_FT_7_LEN_BITS+7)/8)		/* 12.2 */
#define AMR_FT_SID_LEN		((AMR_FT_SID_LEN_BITS+7)/8)		/* SID */
#define AMR_FT_GSM_EFR_SID_LEN	((AMR_FT_GSM_EFR_SID_LEN_BITS+7)/8)	/* GSM-EFR SID */
#define AMR_FT_TDMA_EFR_SID_LEN	((AMR_FT_TDMA_EFR_SID_LEN_BITS+7)/8)	/* TDMA-EFR SID */
#define AMR_FT_PDC_EFR_SID_LEN	((AMR_FT_PDC_EFR_SID_LEN_BITS+7)/8)	/* PDC-EFR SID */
/* version 16.0.0 Release 16: 12-14 for future use */
#define AMR_FT_NO_DATA_LEN	((AMR_FT_NO_DATA_LEN_BITS+7)/8)		/* NO_DATA */

int osmo_amr_ft_valid(uint8_t amr_ft);
size_t osmo_amr_bytes(uint8_t amr_cmr);
size_t osmo_amr_bits(uint8_t amr_ft);

bool osmo_amr_is_oa(uint8_t *payload, unsigned int payload_len);
int osmo_amr_oa_to_bwe(uint8_t *payload, unsigned int payload_len);
int osmo_amr_bwe_to_oa(uint8_t *payload, unsigned int payload_len,
		       unsigned int payload_maxlen);
int osmo_amr_bwe_to_iuup(uint8_t *payload, unsigned int payload_len);
int osmo_amr_iuup_to_bwe(uint8_t *payload, unsigned int payload_len,
			 unsigned int payload_maxlen);
int osmo_amr_bytes_to_ft(size_t bytes);

#endif
