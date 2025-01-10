/*
 * Themyscira Wireless RTP endpoint implementation: different ways
 * of setting the address of the remote RTP peer.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <osmocom/netif/twrtp.h>
#include <osmocom/netif/twrtp_private.h>

void osmo_twrtp_set_remote_ipv4(struct osmo_twrtp *endp,
				const struct in_addr *ip, uint16_t port)
{
	endp->rtp_remote.u.sin.sin_family = AF_INET;
	memcpy(&endp->rtp_remote.u.sin.sin_addr, ip, sizeof(struct in_addr));
	endp->rtp_remote.u.sin.sin_port = htons(port);

	endp->rtcp_remote.u.sin.sin_family = AF_INET;
	memcpy(&endp->rtcp_remote.u.sin.sin_addr, ip, sizeof(struct in_addr));
	endp->rtcp_remote.u.sin.sin_port = htons(port + 1);

	endp->remote_set = true;
}

void osmo_twrtp_set_remote_ipv6(struct osmo_twrtp *endp,
				const struct in6_addr *ip6, uint16_t port)
{
	endp->rtp_remote.u.sin6.sin6_family = AF_INET6;
	memcpy(&endp->rtp_remote.u.sin6.sin6_addr, ip6,
		sizeof(struct in6_addr));
	endp->rtp_remote.u.sin6.sin6_port = htons(port);

	endp->rtcp_remote.u.sin6.sin6_family = AF_INET6;
	memcpy(&endp->rtcp_remote.u.sin6.sin6_addr, ip6,
		sizeof(struct in6_addr));
	endp->rtcp_remote.u.sin6.sin6_port = htons(port + 1);

	endp->remote_set = true;
}

void osmo_twrtp_set_remote_sin(struct osmo_twrtp *endp,
				const struct sockaddr_in *sin)
{
	osmo_twrtp_set_remote_ipv4(endp, &sin->sin_addr, ntohs(sin->sin_port));
}

void osmo_twrtp_set_remote_sin6(struct osmo_twrtp *endp,
				const struct sockaddr_in6 *sin6)
{
	osmo_twrtp_set_remote_ipv6(endp, &sin6->sin6_addr,
				   ntohs(sin6->sin6_port));
}
