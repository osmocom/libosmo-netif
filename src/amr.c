/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/netif/amr.h>

/* According to TS 26.101 Table A.1b:
 *
 * Frame type    AMR code    bits  bytes
 *      0          4.75       95    12
 *      1          5.15      103    13
 *      2          5.90      118    15
 *      3          6.70      134    17
 *      4          7.40      148    19
 *      5          7.95      159    20
 *      6         10.20      204    26
 *      7         12.20      244    31
 *      8       AMR SID       39     5
 *      9   GSM-EFR SID       43     5
 *      10 TDMA-EFR SID       38     5
 *      11  PDC-EFR SID       37     5
 *      12     NOT USED
 *      13     NOT USED
 *      14     NOT USED
 *      15      NO DATA       0      0
 */

static int amr_ft_to_bits[AMR_FT_MAX] = {
	[AMR_FT_0]		= AMR_FT_0_LEN_BITS,
	[AMR_FT_1]		= AMR_FT_1_LEN_BITS,
	[AMR_FT_2]		= AMR_FT_2_LEN_BITS,
	[AMR_FT_3]		= AMR_FT_3_LEN_BITS,
	[AMR_FT_4]		= AMR_FT_4_LEN_BITS,
	[AMR_FT_5]		= AMR_FT_5_LEN_BITS,
	[AMR_FT_6]		= AMR_FT_6_LEN_BITS,
	[AMR_FT_7]		= AMR_FT_7_LEN_BITS,
	[AMR_FT_SID]		= AMR_FT_SID_LEN_BITS,
	[AMR_FT_GSM_EFR_SID]	= AMR_FT_GSM_EFR_SID_LEN_BITS,
	[AMR_FT_TDMA_EFR_SID]	= AMR_FT_TDMA_EFR_SID_LEN_BITS,
	[AMR_FT_PDC_EFR_SID]	= AMR_FT_PDC_EFR_SID_LEN_BITS,
	[12] = 0, /* for future use */
	[13] = 0, /* for future use */
	[14] = 0, /* for future use */
	[AMR_FT_NO_DATA]	= AMR_FT_NO_DATA_LEN_BITS,
};

static size_t amr_ft_to_bytes[AMR_FT_MAX] = {
	[AMR_FT_0]	= AMR_FT_0_LEN,
	[AMR_FT_1]	= AMR_FT_1_LEN,
	[AMR_FT_2]	= AMR_FT_2_LEN,
	[AMR_FT_3]	= AMR_FT_3_LEN,
	[AMR_FT_4]	= AMR_FT_4_LEN,
	[AMR_FT_5]	= AMR_FT_5_LEN,
	[AMR_FT_6]	= AMR_FT_6_LEN,
	[AMR_FT_7]	= AMR_FT_7_LEN,
	[AMR_FT_SID]	= AMR_FT_SID_LEN,
	[AMR_FT_GSM_EFR_SID]	= AMR_FT_GSM_EFR_SID_LEN,
	[AMR_FT_TDMA_EFR_SID]	= AMR_FT_TDMA_EFR_SID_LEN,
	[AMR_FT_PDC_EFR_SID]	= AMR_FT_PDC_EFR_SID_LEN,
	[12] = 0, /* for future use */
	[13] = 0, /* for future use */
	[14] = 0, /* for future use */
	[AMR_FT_NO_DATA]	= AMR_FT_NO_DATA_LEN,
};

size_t osmo_amr_bits(uint8_t amr_ft)
{
	OSMO_ASSERT(amr_ft < AMR_FT_MAX);
	return amr_ft_to_bits[amr_ft];
}

size_t osmo_amr_bytes(uint8_t amr_ft)
{
	OSMO_ASSERT(amr_ft < AMR_FT_MAX);
	return amr_ft_to_bytes[amr_ft];
}

int osmo_amr_bytes_to_ft(size_t bytes)
{
	int ft;

	for (ft = 0; ft < AMR_FT_PDC_EFR_SID; ft++) {
		if (amr_ft_to_bytes[ft] == bytes)
			return ft;
	}
	/* 12-14 not used, jump to 15 (AMR_FT_NO_DATA): */
	if (amr_ft_to_bytes[AMR_FT_NO_DATA] == bytes)
		return AMR_FT_NO_DATA;

	return -1;
}

int osmo_amr_ft_valid(uint8_t amr_ft)
{
	return amr_ft <= AMR_FT_PDC_EFR_SID || amr_ft == AMR_FT_NO_DATA;
}

/*! Check if an AMR frame is octet aligned by looking at the padding bits.
 *  \param[inout] payload user provided memory containing the AMR payload.
 *  \param[in] payload_len overall length of the AMR payload.
 *  \returns true when the payload is octet aligned. */
bool osmo_amr_is_oa(const uint8_t *payload, unsigned int payload_len)
{
	/* NOTE: The distinction between octet-aligned and bandwith-efficient
	 * mode normally relys on out of band methods that explicitly select
	 * one of the two modes. (See also RFC 3267, chapter 3.8). However the
	 * A interface in GSM does not provide ways to communicate which mode
	 * is exactly used. The following functions uses some heuristics to
	 * check if an AMR payload is octet aligned or not. */

	struct amr_hdr *oa_hdr = (struct amr_hdr *)payload;
	unsigned int frame_len;

	/* Broken payload? */
	if (!payload || payload_len < sizeof(struct amr_hdr))
		return false;

	/* In octet aligned mode, padding bits are specified to be
	 * set to zero. (However, there is a remaining risk that the FT0 or FT1
	 * is selected and the first two bits of the frame are zero as well,
	 * in this case a bandwith-efficient mode payload would look like an
	 * octet-aligned payload, thats why additional checks are required.) */
	if (oa_hdr->pad1 != 0)
		return false;
	if (oa_hdr->pad2 != 0)
		return false;

	/* This implementation is limited to single-frame payloads only and
	 * since multi-frame payloads are not common in GSM anyway, we may
	 * include the final bit of the first header into this check. */
	if (oa_hdr->f != 0)
		return false;

	/* Match the length of the received payload against the expected frame
	 * length that is defined by the frame type. */
	if (!osmo_amr_ft_valid(oa_hdr->ft))
		return false;
	frame_len = osmo_amr_bytes(oa_hdr->ft);
	if (frame_len != payload_len - sizeof(struct amr_hdr))
		return false;

	return true;
}

/*! Convert an AMR frame from octet-aligned mode to bandwith-efficient mode.
 *  \param[inout] payload user provided memory containing the AMR payload.
 *  \param[in] payload_len overall length of the AMR payload.
 *  \returns resulting payload length, -1 on error. */
int osmo_amr_oa_to_bwe(uint8_t *payload, unsigned int payload_len)
{
	struct amr_hdr *oa_hdr = (struct amr_hdr *)payload;
	unsigned int ft = oa_hdr->ft;
	unsigned int frame_len = payload_len - sizeof(struct amr_hdr);
	unsigned int i;
	int bwe_payload_len;

	/* This implementation is not capable to handle multi-frame
	 * packets, so we need to make sure that the frame we operate on
	 * contains only one payload. */
	if (oa_hdr->f != 0)
		return -1;

	/* Check for valid FT (AMR mode) value */
	if (!osmo_amr_ft_valid(oa_hdr->ft))
		return -1;

	/* Move TOC close to CMR */
	payload[0] = (payload[0] & 0xf0) | ((payload[1] >> 4) & 0x0f);
	payload[1] = (payload[1] << 4) & 0xf0;

	for (i = 0; i < frame_len; i++) {
		payload[i + 1] |= payload[i + 2] >> 2;
		payload[i + 2] = payload[i + 2] << 6;
	}

	/* Calculate new payload length */
	bwe_payload_len = OSMO_BYTES_FOR_BITS(AMR_HDR_BWE_LEN_BITS + osmo_amr_bits(ft));

	return bwe_payload_len;
}

/*! Convert an AMR frame from bandwith-efficient mode to octet-aligned mode.
 *  \param[inout] payload user provided memory containing the AMR payload.
 *  \param[in] payload_len overall length of the AMR payload.
 *  \param[in] payload_maxlen maximum length of the user provided memory.
 *  \returns resulting payload length, -1 on error. */
int osmo_amr_bwe_to_oa(uint8_t *payload, unsigned int payload_len,
		       unsigned int payload_maxlen)
{
	uint8_t buf[256];
	/* The header is only valid after shifting first two bytes to OA mode */
	struct amr_hdr_bwe *bwe_hdr = (struct amr_hdr_bwe *)payload;
	struct amr_hdr *oa_hdr;
	unsigned int i;
	unsigned int oa_payload_len;
	uint8_t ft;

	if (payload_len < sizeof(struct amr_hdr_bwe))
		return -1;

	if (payload_len + 1 > payload_maxlen)
		return -1;

	if (payload_len + 1 > sizeof(buf))
		return -1;

	ft = (bwe_hdr->ft_hi << 1) | bwe_hdr->ft_lo;
	if (!osmo_amr_ft_valid(ft))
		return -1;
	if (OSMO_BYTES_FOR_BITS(AMR_HDR_BWE_LEN_BITS + osmo_amr_bits(ft)) > payload_len)
		return -1;

	memset(buf, 0, sizeof(buf));
	oa_hdr = (struct amr_hdr *)buf;
	oa_hdr->cmr = bwe_hdr->cmr;
	oa_hdr->f = bwe_hdr->f;
	oa_hdr->ft = ft;
	oa_hdr->q = bwe_hdr->q;

	/* Calculate new payload length */
	oa_payload_len = 2 + osmo_amr_bytes(ft);

	for (i = 2; i < oa_payload_len - 1; i++) {
		buf[i] = payload[i - 1] << 2;
		buf[i] |= payload[i] >> 6;
	}
	buf[i] = payload[i - 1] << 2;

	memcpy(payload, buf, oa_payload_len);
	return oa_payload_len;
}

/*! Convert an AMR frame from bandwith-efficient mode to IuuP/IuFP payload.
 *  The IuuP/IuPF payload only contains the class a, b, c bits. No header.
 *  \param[inout] payload user provided memory containing the AMR payload.
 *  \param[in] payload_len overall length of the AMR payload.
 *  \param[in] payload_maxlen maximum length of the user provided memory.
 *  \returns resulting payload length, negative on error. */
int osmo_amr_bwe_to_iuup(uint8_t *payload, unsigned int payload_len)
{
	/* The header is only valid after shifting first two bytes to OA mode */
	unsigned int i, required_len_bits;
	unsigned int amr_speech_len_bytes, amr_speech_len_bits;
	uint8_t ft;

	if (payload_len < 2)
		return -1;

	/* Calculate new payload length */
	ft = ((payload[0] & 0x07) << 1) | ((payload[1] & 0x80) >> 7);
	if (!osmo_amr_ft_valid(ft))
		return -1;

	amr_speech_len_bits = osmo_amr_bits(ft);
	amr_speech_len_bytes = osmo_amr_bytes(ft);

	/* shift of AMR_HDR_BWE_LEN_BITS (10) bits, aka remove BWE Hdr + ToC: */
	required_len_bits = AMR_HDR_BWE_LEN_BITS + amr_speech_len_bits;
	if (payload_len < OSMO_BYTES_FOR_BITS(required_len_bits))
		return -1;

	for (i = 0; i < amr_speech_len_bytes; i++) {
		/* we have to shift the payload by 10 bits to get only the Class A, B, C bits */
		payload[i] = (payload[i + 1] << 2) | ((payload[i + 2]) >> 6);
	}

	return amr_speech_len_bytes;
}

/*! Convert an AMR frame from IuuP/IuFP payload to bandwith-efficient mode.
 *  The IuuP/IuPF payload only contains the class a, b, c bits. No header.
 *  The resulting buffer has space at the start prepared to be filled by CMR, TOC.
 *  \param[inout] payload user provided memory containing the AMR payload.
 *  \param[in] payload_len overall length of the AMR payload.
 *  \param[in] payload_maxlen maximum length of the user provided memory (payload_len + 2 required).
 *  \returns resulting payload length, negative on error. */
int osmo_amr_iuup_to_bwe(uint8_t *payload, unsigned int payload_len,
			 unsigned int payload_maxlen)
{
	/* shift all bits by AMR_HDR_BWE_LEN_BITS (10) */
	unsigned int i, required_len_bits, required_len_bytes;

	int ft = osmo_amr_bytes_to_ft(payload_len);
	if (ft < 0)
		return ft;

	required_len_bits = osmo_amr_bits(ft) + 10;
	required_len_bytes = OSMO_BYTES_FOR_BITS(required_len_bits);
	if (payload_maxlen < required_len_bytes)
		return -1;

	i = payload_len + 1;
	payload[i] = (payload[i - 2] << 6);
	for (i = payload_len; i >= 2; i--) {
		/* we have to shift the payload by AMR_HDR_BWE_LEN_BITS (10) bits to prepend BWE Hdr + ToC */
		payload[i] = (payload[i - 1] >> 2) | (payload[i - 2] << 6);
	}
	payload[i] = (payload[i - 1] >> 2);
	payload[0] = 0;
	return required_len_bytes;
}
