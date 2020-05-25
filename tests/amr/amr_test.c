/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/amr.h>

/* Some octet aligned single-payload AMR frames on different rates */
char *oa_amr_samples[] = {
	"703c22f979890338540179209572624a0f8535871c2f7039cbf926b7e4425b6ef0",
	"703c2e671f3b1b0810412d5adae61e2b2a319885c6ced4e909b4eeaa2ea0f0cd80",
	"703cf8fc77356c948141686cda34d35220db719e36a359d86b64420dc64b563850",
	"60344e300c0e6251342c2ae51fd8a698a945488d16c98922726f3e50",
	"60341fc722c7880328a9c280030bc9755c3ef519f80000295323e000",
	"60342c338655c00008efba03592419adf62478a79278b3e2d68ab0f0",
	"502c98ab841e491ff7a1a555016a32a3c7f913210630",
	"502cc5459a0d200e7097c4dfe86ec8d27f1756d776f0",
	"502c42b332081813d7e916e7aa5e80d7fde812b8c080",
	"40240343e959c79bacd20c77501054880a718db200",
	"4024172c53401e39115ceecd12606df5689bdd0ca0",
	"4024f871cf48801ec427f0fc3f7318898622062200",
	"20141fd4c02667c742b164aef659ffe708",
	"2014197e10ead7b250bccbbf3b81887c64",
	"2014e959f35fdfe5e9667ffbc088818088",
	"100c4e9ba850e30d5d53d04de41e7c",
	"100c6c18e7b7fff53aeb055e7d1c54",
	"100c1fb967f7f1fdf547bf2e61c060",
	"0004f89d67f1160935bde1996840",
	"0004633cc7f0630439ffe0000000",
	"0004eb81fc0758973b9edc782550",
	"a078ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00fc",	/* sample with invalid FT */
	"END",
};

/* Some bandwith efficient single-payload AMR frames */
char *bwe_amr_samples[] = {
	"f4495c7cda8f80",
	"f44aaa6c969780",
	"f3d09c20e32da600c025a72e0a9b360386e40f87e19282094adc1a11e397d1d4",
	"f3d39a49a09e7a802852e297e8c9246aadf5a45928bfc27177fed8404d97d3b8",
	"f3c2155b65131c68682079fab4810911200003b360ae0446000025f11e539dd0",
	"f3c381bc7061c9f8507f6029de6115c16e5fa470c243b21b6e35dbb48bd84c00",
	"a7bfc03fc03fc03fc03fc03fc03fc03fc03fc03fc03fc03fc03fc03fc03fc03f",	/* sample with invalid FT */
	"END",
};

void dump_bits(uint8_t *buf, int len)
{
	unsigned int i;
	if (len <= 0) {
		printf("(no data)");
		return;
	}
	for (i = 0; i < (len * 8); i++)
		printf("%u", (buf[i / 8] >> (7 - (i % 8))) & 1);
	return;
}

void osmo_amr_oa_to_bwe_test(void)
{
	uint8_t buf[256];
	unsigned int i = 0;
	int len;
	int rc;

	printf("\n\n");
	printf("Testing conversion from octet-aligned to bw-efficient:\n");

	while (1) {
		if (strcmp(oa_amr_samples[i], "END") == 0)
			return;
		printf("\n");
		printf("Sample No.: %i\n", i);

		len = osmo_hexparse(oa_amr_samples[i], buf, sizeof(buf));
		OSMO_ASSERT(len > 0);

		printf("   octet aligned: %s\n", osmo_hexdump_nospc(buf, len));
		printf("                  ");
		dump_bits(buf, len);
		printf("\n");
		rc = osmo_amr_oa_to_bwe(buf, len);
		printf("   bw-efficient:  %s\n", osmo_hexdump_nospc(buf, rc));
		printf("                  ");
		dump_bits(buf, rc);
		printf("\n");
		printf("   rc: %i\n", rc);
		i++;
	}
}

void osmo_amr_bwe_to_oa_test(void)
{
	uint8_t buf[256];
	unsigned int i = 0;
	int len;
	int rc;

	printf("\n\n");
	printf("Testing conversion from bw-efficient to octet-aligned:\n");

	while (1) {
		if (strcmp(bwe_amr_samples[i], "END") == 0)
			return;
		printf("\n");
		printf("Sample No.: %i\n", i);

		len = osmo_hexparse(bwe_amr_samples[i], buf, sizeof(buf));
		OSMO_ASSERT(len > 0);

		printf("   bw-efficient:  %s\n", osmo_hexdump_nospc(buf, len));
		printf("                  ");
		dump_bits(buf, len);
		printf("\n");
		rc = osmo_amr_bwe_to_oa(buf, len, sizeof(buf));
		printf("   octet aligned: %s\n", osmo_hexdump_nospc(buf, rc));
		printf("                  ");
		dump_bits(buf, rc);
		printf("\n");
		printf("   rc: %i\n", rc);

		i++;
	}
}

void osmo_amr_oa_to_bwe_and_inverse_test(void)
{
	uint8_t buf[256];
	uint8_t buf_chk[256];
	struct amr_hdr *oa_hd = (struct amr_hdr *)buf;
	unsigned int ft;

	unsigned int i = 0;
	int len;
	int rc;

	printf("\n\n");
	printf
	    ("Testing conversion from octet-aligned to bw-efficient and inverse:\n");

	while (1) {
		if (strcmp(oa_amr_samples[i], "END") == 0)
			return;
		printf("Sample No.: %i...", i);

		len = osmo_hexparse(oa_amr_samples[i], buf, sizeof(buf));
		OSMO_ASSERT(len > 0);
		i++;

		ft = oa_hd->ft;
		if (!osmo_amr_ft_valid(ft)) {
			printf(" skipping a sample with a wrong FT\n");
			continue;
		}
		OSMO_ASSERT(osmo_amr_bytes(ft) + 2 == len);
		printf(" AMR mode: %d, OA: %d bytes,", ft, len);
		memcpy(buf_chk, buf, sizeof(buf));

		rc = osmo_amr_oa_to_bwe(buf, len);
		OSMO_ASSERT(rc > 0);
		printf(" BE: %d bytes,", rc);
		rc = osmo_amr_bwe_to_oa(buf, rc, sizeof(buf));
		printf(" OA: %d bytes\n", rc);
		OSMO_ASSERT(len == rc);
		OSMO_ASSERT(memcmp(buf, buf_chk, len) == 0);
	}
}

void osmo_amr_is_oa_test(void)
{
	uint8_t buf[256];
	unsigned int i;
	int len;
	bool is_oc;

	printf("\n\n");
	printf("Testing detection of octet-aligned mode payloads:\n");

	i = 0;
	while (1) {
		if (strcmp(oa_amr_samples[i], "END") == 0)
			break;
		printf("Sample No.: %i ==>", i);
		len = strlen(oa_amr_samples[i]);

		len = osmo_hexparse(oa_amr_samples[i], buf, sizeof(buf));
		OSMO_ASSERT(len > 0);

		is_oc = osmo_amr_is_oa(buf, len);
		if (is_oc)
			printf("octet aligned\n");
		else
			printf("bandwith efficient\n");

		i++;
	}

	i = 0;
	while (1) {
		if (strcmp(bwe_amr_samples[i], "END") == 0)
			break;
		printf("Sample No.: %i ==>", i);
		len = strlen(oa_amr_samples[i]);

		len = osmo_hexparse(bwe_amr_samples[i], buf, sizeof(buf));
		OSMO_ASSERT(len > 0);

		is_oc = osmo_amr_is_oa(buf, len);
		if (is_oc)
			printf("octet aligned\n");
		else
			printf("bandwith efficient\n");

		i++;
	}
}

int main(int argc, char **argv)
{
	osmo_amr_oa_to_bwe_test();
	osmo_amr_bwe_to_oa_test();
	osmo_amr_oa_to_bwe_and_inverse_test();
	osmo_amr_is_oa_test();

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
