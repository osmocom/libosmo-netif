/*
 * (C) 2012-2017 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 * (C) 2015-2022 by sysmocom - s.f.m.c. GmbH
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include <arpa/inet.h>

/*! \addtogroup osmux Osmocom Multiplex Protocol
 *  @{
 *
 *  This code implements a variety of utility functions related to the
 *  OSMUX user-plane multiplexing protocol, an efficient alternative to
 *  plain UDP/RTP streams for voice transport in back-haul of cellular
 *  networks.
 *
 *  For information about the OSMUX protocol design, please see the
 *  OSMUX reference manual at
 *  http://ftp.osmocom.org/docs/latest/osmux-reference.pdf
 */

/*! \file osmux.c
 *  \brief Osmocom multiplex protocol helpers
 */

static uint32_t osmux_get_payload_len(struct osmux_hdr *osmuxh)
{
	return osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1);
}

#define SNPRINTF_BUFFER_SIZE(ret, remain, offset)	\
	if (ret < 0)					\
		ret = 0;				\
	offset += ret;					\
	if (ret > remain)				\
		ret = remain;				\
	remain -= ret;

static int osmux_snprintf_header(char *buf, size_t size, struct osmux_hdr *osmuxh)
{
	unsigned int remain = size, offset = 0;
	int ret;

	ret = snprintf(buf, remain, "OSMUX seq=%03u ccid=%03u "
				 "ft=%01u rtp_m=%01u ctr=%01u "
				 "amr_f=%01u amr_q=%01u "
				 "amr_ft=%02u amr_cmr=%02u",
			osmuxh->seq, osmuxh->circuit_id,
			osmuxh->ft, osmuxh->rtp_m, osmuxh->ctr,
			osmuxh->amr_f, osmuxh->amr_q,
			osmuxh->amr_ft, osmuxh->amr_cmr);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int osmux_snprintf_payload(char *buf, size_t size,
				  const uint8_t *payload, int payload_len)
{
	unsigned int remain = size, offset = 0;
	int ret, i;

	ret = snprintf(buf + offset, remain, "[ ");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	for (i=0; i<payload_len; i++) {
		ret = snprintf(buf + offset, remain, "%02x ", payload[i]);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	ret = snprintf(buf + offset, remain, "]");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

/*! Print osmux header fields and payload from msg into buffer buf.
 *  \param[out] buf buffer to store the output into
 *  \param[in] len length of buf in bytes
 *  \param[in] msgb message buffer containing one or more osmux frames
 *  \returns the number of characters printed (excluding the null byte used to end output to strings).
 *
 * If the output was truncated due to this limit, then the return value is the number of characters
 * (excluding the terminating null byte) which would have been written to the final string if enough
 * space had been available.
 */
int osmux_snprintf(char *buf, size_t size, struct msgb *msg)
{
	unsigned int remain = size;
	unsigned int msg_off = 0;
	struct osmux_hdr *osmuxh;
	unsigned int offset = 0;
	int msg_len = msg->len;
	uint32_t payload_len;
	int ret;

	if (size)
		buf[0] = '\0';

	while (msg_len > 0) {
		if (msg_len < sizeof(struct osmux_hdr)) {
			LOGP(DLMUX, LOGL_ERROR,
			     "No room for OSMUX header: only %d bytes\n",
			     msg_len);
			return -1;
		}
		osmuxh = (struct osmux_hdr *)((uint8_t *)msg->data + msg_off);
		if (msg_off) {
			ret = snprintf(buf + offset, remain, ", ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
		ret = osmux_snprintf_header(buf + offset, remain, osmuxh);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		msg_off += sizeof(struct osmux_hdr);
		msg_len -= sizeof(struct osmux_hdr);

		switch (osmuxh->ft) {
		case OSMUX_FT_SIGNAL:
			ret = snprintf(buf + offset, remain, "[signal]");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			return -1;
		case OSMUX_FT_DUMMY:
		case OSMUX_FT_VOICE_AMR:
			if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
				LOGP(DLMUX, LOGL_ERROR, "Bad AMR FT %d, skipping\n",
				     osmuxh->amr_ft);
				return -1;
			}

			payload_len = osmux_get_payload_len(osmuxh);

			if (msg_len < payload_len) {
				LOGP(DLMUX, LOGL_ERROR,
				     "No room for OSMUX payload: only %d bytes\n",
				     msg_len);
				return -1;
			}

			if (osmuxh->ft == OSMUX_FT_VOICE_AMR) {
				ret = snprintf(buf + offset, remain, " ");
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
				ret = osmux_snprintf_payload(buf + offset, remain,
							     osmux_get_payload(osmuxh),
							     payload_len);
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			}

			msg_off += payload_len;
			msg_len -= payload_len;
			break;
		default:
			LOGP(DLMUX, LOGL_ERROR, "Unknown OSMUX ft value %d\n",
			     osmuxh->ft);
			return -1;
		}
	}
	return offset;
}

/*! @} */
