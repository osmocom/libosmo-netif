/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
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

static size_t amr_cmr_to_bytes[AMR_CMR_MAX] = {
	[AMR_CMR_0]	= 12,
	[AMR_CMR_1]	= 13,
	[AMR_CMR_2]	= 15,
	[AMR_CMR_3]	= 17,
	[AMR_CMR_4]	= 19,
	[AMR_CMR_5]	= 20,
	[AMR_CMR_6]	= 26,
	[AMR_CMR_7]	= 31,
};

size_t osmo_amr_bytes(uint8_t amr_cmr)
{
	return amr_cmr_to_bytes[amr_cmr];
}
