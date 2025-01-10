/*
 * Themyscira Wireless RTP endpoint implementation: creating and binding
 * local UDP sockets for RTP and RTCP.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/netif/twrtp.h>

int osmo_twrtp_bind_local_ipv4(struct osmo_twrtp *endp,
				const struct in_addr *ip, uint16_t port)
{
	int rtp_fd, rtcp_fd;
	struct sockaddr_in sin;
	int rc;

	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr, ip, sizeof(struct in_addr));

	/* do RTP socket first */
	rc = socket(AF_INET, SOCK_DGRAM, 0);
	if (rc < 0)
		return -errno;
	rtp_fd = rc;
	sin.sin_port = htons(port);
	rc = bind(rtp_fd, (struct sockaddr *) &sin, sizeof(sin));
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		return rc;
	}

	/* now do RTCP */
	rc = socket(AF_INET, SOCK_DGRAM, 0);
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		return rc;
	}
	rtcp_fd = rc;
	sin.sin_port = htons(port + 1);
	rc = bind(rtcp_fd, (struct sockaddr *) &sin, sizeof(sin));
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		close(rtcp_fd);
		return rc;
	}

	return osmo_twrtp_supply_fds(endp, rtp_fd, rtcp_fd);
}

int osmo_twrtp_bind_local_ipv6(struct osmo_twrtp *endp,
				const struct in6_addr *ip6, uint16_t port)
{
	int rtp_fd, rtcp_fd;
	struct sockaddr_in6 sin6;
	int rc;

	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, ip6, sizeof(struct in6_addr));

	/* do RTP socket first */
	rc = socket(AF_INET6, SOCK_DGRAM, 0);
	if (rc < 0)
		return -errno;
	rtp_fd = rc;
	sin6.sin6_port = htons(port);
	rc = bind(rtp_fd, (struct sockaddr *) &sin6, sizeof(sin6));
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		return rc;
	}

	/* now do RTCP */
	rc = socket(AF_INET6, SOCK_DGRAM, 0);
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		return rc;
	}
	rtcp_fd = rc;
	sin6.sin6_port = htons(port + 1);
	rc = bind(rtcp_fd, (struct sockaddr *) &sin6, sizeof(sin6));
	if (rc < 0) {
		rc = -errno;
		close(rtp_fd);
		close(rtcp_fd);
		return rc;
	}

	return osmo_twrtp_supply_fds(endp, rtp_fd, rtcp_fd);
}

int osmo_twrtp_bind_local_sin(struct osmo_twrtp *endp,
				const struct sockaddr_in *sin)
{
	return osmo_twrtp_bind_local_ipv4(endp, &sin->sin_addr,
					  ntohs(sin->sin_port));
}

int osmo_twrtp_bind_local_sin6(struct osmo_twrtp *endp,
				const struct sockaddr_in6 *sin6)
{
	return osmo_twrtp_bind_local_ipv6(endp, &sin6->sin6_addr,
					  ntohs(sin6->sin6_port));
}
