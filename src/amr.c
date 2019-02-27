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
#include <osmocom/netif/amr.h>

/* According to TS 26.101:
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
 */

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
};

size_t osmo_amr_bytes(uint8_t amr_ft)
{
	return amr_ft_to_bytes[amr_ft];
}

int osmo_amr_ft_valid(uint8_t amr_ft)
{
	/*
	 * Extracted from RFC3267:
	 *
	 * "... with a FT value in the range 9-14 for AMR ... the whole packet
	 *  SHOULD be discarded."
	 *
	 * "... packets containing only NO_DATA frames (FT=15) SHOULD NOT be
	 *  transmitted."
	 *
	 * So, let's discard frames with a AMR FT >= 9.
	 */
	if (amr_ft >= AMR_FT_MAX)
		return 0;

	return 1;
}
