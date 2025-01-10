/*
 * Themyscira Wireless RTP endpoint implementation: basic functions,
 * everything that isn't factored out into other modules.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>
#include <osmocom/netif/twjit.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/rtcp_defs.h>

/* We need to know maximum expected sizes of RTP and RTCP Rx packets
 * for osmo_io msgb allocation.  For RTP, the largest packet size in
 * 3GPP and IP-PSTN applications is 176 bytes: 12 bytes of RTP header
 * plus 160 bytes of payload for 20 ms of uncompressed G.711 audio
 * or CSData.  Of course there may be other applications that use
 * larger RTP packets, in which case we may have to add an API function
 * that overrides our default msgb alloc size setting - but let's
 * cross that bridge if and when we actually have such users.
 *
 * In case of RTCP, we fully process all received packets inside
 * the present library, hence we can set osmo_io msgb alloc size
 * based on what our RTCP Rx code can parse and make use of.  Any
 * additional RTCP Rx data, such as very long SDES strings, will
 * simply be truncated at osmo_io level - but the subsequent parsing
 * code will never get to those bits anyway.
 */

#define	MAX_RTP_RX_PACKET	(sizeof(struct rtp_hdr) + 160)
#define	MAX_RTCP_RX_PACKET	(sizeof(struct rtcp_sr_rr_hdr) + \
					sizeof(struct rtcp_sr_block) + \
					sizeof(struct rtcp_rr_block) * 31)

struct osmo_twrtp *
osmo_twrtp_create(void *ctx, uint16_t clock_khz, uint16_t quantum_ms,
		  bool random_ts_seq,
		  const struct osmo_twjit_config *twjit_config)
{
	struct osmo_twrtp *endp;

	endp = talloc_zero(ctx, struct osmo_twrtp);
	if (!endp)
		return NULL;

	endp->iofd_rtp = osmo_iofd_setup(endp, -1, NULL,
					 OSMO_IO_FD_MODE_RECVFROM_SENDTO,
					 &_osmo_twrtp_iops_rtp, endp);
	if (!endp->iofd_rtp) {
		talloc_free(endp);
		return NULL;
	}
	osmo_iofd_set_alloc_info(endp->iofd_rtp, MAX_RTP_RX_PACKET, 0);

	endp->iofd_rtcp = osmo_iofd_setup(endp, -1, NULL,
					  OSMO_IO_FD_MODE_RECVFROM_SENDTO,
					  &_osmo_twrtp_iops_rtcp, endp);
	if (!endp->iofd_rtcp) {
		osmo_iofd_free(endp->iofd_rtp);
		talloc_free(endp);
		return NULL;
	}
	osmo_iofd_set_alloc_info(endp->iofd_rtcp, MAX_RTCP_RX_PACKET, 0);

	if (twjit_config) {
		endp->twjit = osmo_twjit_create(endp, clock_khz, quantum_ms,
						twjit_config);
		if (!endp->twjit) {
			osmo_iofd_free(endp->iofd_rtp);
			osmo_iofd_free(endp->iofd_rtcp);
			talloc_free(endp);
			return NULL;
		}
	}

	endp->ts_quantum = (uint32_t) quantum_ms * clock_khz;
	endp->ts_units_per_sec = (uint32_t) clock_khz * 1000;
	endp->ns_to_ts_units = 1000000 / clock_khz;

	endp->tx.ssrc = random();
	if (random_ts_seq) {
		endp->tx.ts_addend = random();
		endp->tx.seq = random();
	}

	return endp;
}

void osmo_twrtp_destroy(struct osmo_twrtp *endp)
{
	osmo_iofd_free(endp->iofd_rtp);
	osmo_iofd_free(endp->iofd_rtcp);
	if (endp->twjit)
		osmo_twjit_destroy(endp->twjit);
	talloc_free(endp);
}

/* This function equips a newly created twrtp endpoint with file descriptors
 * for RTP and RTCP sockets.  Most applications will use higher-level
 * osmo_twrtp_bind_local_ipv4() and osmo_twrtp_bind_local_ipv6() functions
 * that create and bind the right type of sockets, then call the present
 * function - however, some applications may call this function directly.
 * In Themyscira Wireless CN environment, there is a separate daemon process
 * that manages the pool of local UDP ports for RTP+RTCP pairs, and that
 * daemon passes allocated sockets to its clients via UNIX domain socket
 * file descriptor passing mechanism - hence twrtp layer must have a public
 * API that takes in already-bound file descriptor pairs.
 *
 * This function always "consumes" the two file descriptors that are passed
 * to it.  If the operation succeeds, each of these fds becomes wrapped in
 * an osmo_io_fd subordinate to struct osmo_twrtp, and both will eventually
 * be closed upon osmo_twrtp_destroy().  OTOH, if the present function fails,
 * it closes both fds before returning its error indication.  The latter
 * behavior may seem wrong, but it is more convenient for all current users,
 * and consistent with the original twrtp-proto version.  If we get a user
 * application that prefers the other alternative (keeping the fds intact
 * on EBUSY or if osmo_iofd_register() operations fail), we can create
 * another variant of this API with that alternative behavior.
 */
int osmo_twrtp_supply_fds(struct osmo_twrtp *endp, int rtp_fd, int rtcp_fd)
{
	int rc;

	if (endp->register_done) {
		close(rtp_fd);
		close(rtcp_fd);
		return -EBUSY;
	}

	rc = osmo_iofd_register(endp->iofd_rtp, rtp_fd);
	if (rc < 0) {
		close(rtp_fd);
		close(rtcp_fd);
		return rc;
	}

	rc = osmo_iofd_register(endp->iofd_rtcp, rtcp_fd);
	if (rc < 0) {
		osmo_iofd_close(endp->iofd_rtp);
		close(rtcp_fd);
		return rc;
	}

	endp->register_done = true;
	return 0;
}
