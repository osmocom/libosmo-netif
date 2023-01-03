/*! \file osmo-amr-inspect.c
 * Utility program to inspect AMR payloads */
/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau espin Pedrol <pespin@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/codec/codec.h>
#include <osmocom/netif/amr.h>

enum force_amr_input_fmt {
	FORCE_AMR_INPUT_FMT_AUTO = 0,
	FORCE_AMR_INPUT_FMT_OA,
	FORCE_AMR_INPUT_FMT_BWE,
	FORCE_AMR_INPUT_FMT_ALL,
};

static enum force_amr_input_fmt force_fmt = FORCE_AMR_INPUT_FMT_AUTO;
static bool use_color = false;

static void help(const char *progname)
{
	printf("Usage: %s [-h] [-i filename] [-F (auto|oa|bwe|all)] [-C]\n",
		progname);
}

#define println_color(color, fmt, args ...) \
	do { \
		if (use_color) \
			printf(color fmt OSMO_LOGCOLOR_END "\n", ## args); \
		else \
			printf(fmt "\n", ## args); \
	} while (0)

#define println_red(fmt, args ...) \
	println_color(OSMO_LOGCOLOR_RED, fmt OSMO_LOGCOLOR_END, ## args)

#define println_orange(fmt, args ...) \
	println_color(OSMO_LOGCOLOR_YELLOW, fmt OSMO_LOGCOLOR_END, ## args)

static void inspect_amr_oa(const uint8_t *buf, size_t buf_len)
{
	const struct amr_hdr *hdr = (const struct amr_hdr *)buf;
	size_t payload_len = buf_len - sizeof(*hdr);
	const uint8_t *payload = hdr->data;
	size_t ft_bytes, ft_bits;
	printf(" octet-aligned\n");
	printf("  CMR: %u\n", hdr->cmr);
	printf("  F: %u\n", hdr->f);
	printf("  FT: %u (%s)\n", hdr->ft, osmo_amr_type_name(hdr->ft));
	printf("  Q: %u\n", hdr->q);
	printf("  Payload (%lu bytes): %s\n",
	       buf_len - sizeof(*hdr), osmo_hexdump_nospc(payload, payload_len));

	if (hdr->f)
		println_orange("  WARN: F=%u not supported!", hdr->f);
	if (!osmo_amr_ft_valid(hdr->cmr))
		println_red("  ERROR: CMR=%u not valid!", hdr->cmr);
	if (!osmo_amr_ft_valid(hdr->ft))
		println_red("  ERROR: FT=%u not valid!", hdr->ft);
	if (hdr->pad1 != 0)
		println_orange("  WARN: PAD1=0x%x not zero!", hdr->pad1);
	if (hdr->pad2 != 0)
		println_orange("  WARN: PAD2=0x%x not zero!", hdr->pad2);
	ft_bytes = osmo_amr_bytes(hdr->ft);
	if (payload_len != ft_bytes) {
		println_red("  ERROR: Wrong payload byte-length %lu != exp %lu!", payload_len, ft_bytes);
	} else {
		ft_bits = osmo_amr_bits(hdr->ft);
		if (ft_bits/8 == ft_bytes) {
			printf("  Payload has no padding (%lu bits)\n", ft_bits);
		} else {
			uint8_t last_byte = payload[payload_len - 1];
			uint8_t padding = last_byte & (0xff >> (ft_bits & 3));
			if (padding)
				println_orange("  WARN: Payload last byte = 0x%02x has PAD=0x%02x not zero!", last_byte, padding);
		}
	}
}

static void inspect_amr_bwe(const uint8_t *buf, size_t buf_len)
{
	const struct amr_hdr_bwe *hdr = (const struct amr_hdr_bwe *)buf;
	size_t payload_len_bits = 6 + (buf_len - sizeof(*hdr))*8;
	size_t ft_bits;
	int rc;
	uint8_t buf_oa[buf_len + 1];
	uint8_t ft = (hdr->ft_hi << 1) | hdr->ft_lo;

	printf(" bandwith-efficient\n");
	printf("  CMR: %u\n", hdr->cmr);
	printf("  F: %u\n", hdr->f);
	printf("  FT: %u (%s)\n", ft, osmo_amr_type_name(ft));
	printf("  Q: %u\n", hdr->q);
	printf("  Payload first 6 bits: 0x%02x\n", hdr->data_start);
	printf("  Payload continuation (%lu bytes): %s\n", buf_len - sizeof(*hdr),
	       osmo_hexdump_nospc(buf + sizeof(*hdr), buf_len - sizeof(*hdr)));

	if (hdr->f)
		println_orange("  WARN: F=%u not supported!", hdr->f);
	if (!osmo_amr_ft_valid(hdr->cmr))
		println_red("  ERROR: CMR=%u not valid!", hdr->cmr);
	if (!osmo_amr_ft_valid(ft)) {
		println_red("  ERROR: FT=%u not valid!", ft);
		return;
	}
	ft_bits = osmo_amr_bits(ft);
	if (ft_bits != payload_len_bits) {
		println_red("  ERROR: Wrong payload bits-length %lu != exp %lu! (FT=%u)\n", payload_len_bits, ft_bits, ft);
		return;
	}

	if (!((AMR_HDR_BWE_LEN_BITS + ft_bits) & 0x03)) {
		printf("  Payload has no padding (%lu bits with offset 10)\n", ft_bits);
	} else {
		uint8_t last_byte = buf[buf_len - 1];
		uint8_t padding = last_byte & (0xff >> ((AMR_HDR_BWE_LEN_BITS + ft_bits) & 0x03));
		if (padding)
			println_orange("  WARN: Payload last byte = 0x%02x has PAD=0x%02x not zero!", last_byte, padding);
	}

	memcpy(buf_oa, buf, buf_len);
	rc = osmo_amr_bwe_to_oa(buf_oa, buf_len, sizeof(buf_oa));
	if (rc < 0) {
		println_red("  ERROR: Unable to convert to octet-aligned!");
		return;
	}
	printf("  Payload (octet-aligned %d bytes): %s", rc,
	       osmo_hexdump_nospc(buf_oa + sizeof(struct amr_hdr), rc));
}

static void inspect_amr(unsigned int i, const uint8_t *buf, size_t buf_len)
{
	bool is_oa;
	printf("[%u] Buffer (%lu bytes): %s\n", i, buf_len, osmo_hexdump_nospc(buf, buf_len));
	is_oa = osmo_amr_is_oa(buf, buf_len);
	switch (force_fmt) {
	case FORCE_AMR_INPUT_FMT_AUTO:
		if (is_oa)
			inspect_amr_oa(buf, buf_len);
		else
			inspect_amr_bwe(buf, buf_len);
		break;
	case FORCE_AMR_INPUT_FMT_OA:
		if (!is_oa)
			println_orange(" WARN: detected as 'bwe' but forced as 'oa'");
		inspect_amr_oa(buf, buf_len);
		break;
	case FORCE_AMR_INPUT_FMT_BWE:
		if (is_oa)
			println_orange(" WARN: detected as 'oa' but forced as 'bwe'");
		inspect_amr_bwe(buf, buf_len);
		break;
	case FORCE_AMR_INPUT_FMT_ALL:
		if (!is_oa)
			println_orange(" WARN: detected as 'bwe' but forced as 'oa'");
		inspect_amr_oa(buf, buf_len);
		if (is_oa)
			println_orange(" WARN: detected as 'oa' but forced as 'bwe'");
		inspect_amr_bwe(buf, buf_len);
		break;
	default:
		OSMO_ASSERT(0);
	}
	printf("\n");
}

static int read_file(const char *filename)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	uint8_t buf[4096];
	int rc = 0;
	unsigned int i = 0;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed opening %s: %s\n", filename, strerror(errno));
		return -errno;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		if (len & 1) {
			fprintf(stderr, "Failed parsing (wrong even length): %s\n", line);
			rc = -1;
			goto free_ret;
		}
		if (len > sizeof(buf)*2) {
			fprintf(stderr, "Failed parsing (too big): %s\n", line);
			rc = -1;
			goto free_ret;
		}
		rc = osmo_hexparse(line, buf, sizeof(buf));
		if (rc < 0) {
			fprintf(stderr, "Failed parsing (hexparse error): %s\n", line);
			rc = -1;
			goto free_ret;
		}
		if (rc < 2) {
			fprintf(stderr, "Too short to be an AMR buffer (%u bytes): %s\n", rc, line);
			rc = -1;
			goto free_ret;
		}
		inspect_amr(i, buf, rc);
		i++;
	}

free_ret:
	fclose(fp);
	if (line)
		free(line);
	return rc;
}

static int read_stdin(void)
{
	ssize_t rc;
	size_t hex_buflen;
	char hex_buf[4096];
	uint8_t buf[2048];
	rc = read(0, hex_buf, sizeof(hex_buf) - 1);
	if (rc < 0) {
		fprintf(stderr, "Failed reading stdin: %s\n", strerror(errno));
		return -EIO;
	}
	hex_buflen = rc;
	hex_buf[hex_buflen] = '\0';

	if (hex_buflen == sizeof(hex_buf) - 1) {
		fprintf(stderr, "Failed parsing (input too long > %lu): %s\n", hex_buflen, hex_buf);
		return -ENOMEM;
	}

	rc = osmo_hexparse(hex_buf, buf, sizeof(buf));
	if (rc < 0) {
		fprintf(stderr, "Failed parsing (hexparse error): %s\n", hex_buf);
		return -1;
	}
	if (rc < 2) {
		fprintf(stderr, "Too short to be an AMR buffer (%ld bytes): %s\n", rc, hex_buf);
		return -1;
	}

	inspect_amr(0, buf, rc);
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	char *filename = NULL;
	int rc;

	while ((opt = getopt(argc, argv, "i:F:Ch")) != -1) {
		switch (opt) {
		case 'i':
			filename = optarg;
			break;
		case 'F':
			if (strcasecmp(optarg, "auto") == 0) {
				force_fmt = FORCE_AMR_INPUT_FMT_AUTO;
			} else if (strcasecmp(optarg, "oa") == 0) {
				force_fmt = FORCE_AMR_INPUT_FMT_OA;
			} else if (strcasecmp(optarg, "bwe") == 0) {
				force_fmt = FORCE_AMR_INPUT_FMT_BWE;
			} else if (strcasecmp(optarg, "all") == 0) {
				force_fmt = FORCE_AMR_INPUT_FMT_ALL;
			} else {
				help(argv[0]);
				exit(1);
			}
			break;
		case 'h':
			help(argv[0]);
			exit(0);
			break;
		case 'C':
			use_color = true;
			break;
		default:
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments in command line\n");
		exit(2);
	}

	if (filename) {
		rc = read_file(filename);
		exit(-rc);
	} else {
		rc = read_stdin();
		exit(-rc);
	}

	exit(0);
}
