/* (C) 2011 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2015-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/panic.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/stream_private.h>

#include "config.h"

#include <osmocom/netif/sctp.h>


/*! \addtogroup stream
 *  @{
 */

/*! \file stream.c
 *  \brief Osmocom stream socket helpers
 */

#ifdef HAVE_LIBSCTP

/* is any of the bytes from offset .. u8_size in 'u8' non-zero? return offset or -1 if all zero */
static int byte_nonzero(const uint8_t *u8, unsigned int offset, unsigned int u8_size)
{
	int j;

	for (j = offset; j < u8_size; j++) {
		if (u8[j] != 0)
			return j;
	}

	return -1;
}

static unsigned int sctp_sockopt_event_subscribe_size = 0;

static int determine_sctp_sockopt_event_subscribe_size(void)
{
	uint8_t buf[256];
	socklen_t buf_len = sizeof(buf);
	int sd, rc;

	/* only do this once */
	if (sctp_sockopt_event_subscribe_size > 0)
		return 0;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (sd < 0)
		return sd;

	rc = getsockopt(sd, IPPROTO_SCTP, SCTP_EVENTS, buf, &buf_len);
	close(sd);
	if (rc < 0)
		return rc;

	sctp_sockopt_event_subscribe_size = (unsigned int)buf_len;

	LOGP(DLINP, LOGL_INFO, "sizes of 'struct sctp_event_subscribe': compile-time %zu, kernel: %u\n",
		sizeof(struct sctp_event_subscribe), sctp_sockopt_event_subscribe_size);
	return 0;
}

/* Attempt to work around Linux kernel ABI breakage
 *
 * The Linux kernel ABI for the SCTP_EVENTS socket option has been broken repeatedly.
 *  - until commit 35ea82d611da59f8bea44a37996b3b11bb1d3fd7 ( kernel < 4.11), the size is 10 bytes
 *  - in 4.11 it is 11 bytes
 *  - in 4.12 .. 5.4 it is 13 bytes
 *  - in kernels >= 5.5 it is 14 bytes
 *
 * This wouldn't be a problem if the kernel didn't have a "stupid" assumption that the structure
 * size passed by userspace will match 1:1 the length of the structure at kernel compile time. In
 * an ideal world, it would just use the known first bytes and assume the remainder is all zero.
 * But as it doesn't do that, let's try to work around this */
static int sctp_setsockopt_events_linux_workaround(int fd, const struct sctp_event_subscribe *event)
{

	const unsigned int compiletime_size = sizeof(*event);
	int rc;

	if (determine_sctp_sockopt_event_subscribe_size() < 0) {
		LOGP(DLINP, LOGL_ERROR, "Cannot determine SCTP_EVENTS socket option size\n");
		return -1;
	}

	if (compiletime_size == sctp_sockopt_event_subscribe_size) {
		/* no kernel workaround needed */
		return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, event, compiletime_size);
	} else if (compiletime_size < sctp_sockopt_event_subscribe_size) {
		/* we are using an older userspace with a more modern kernel and hence need
		 * to pad the data */
		uint8_t buf[sctp_sockopt_event_subscribe_size];

		memcpy(buf, event, compiletime_size);
		memset(buf + sizeof(*event), 0, sctp_sockopt_event_subscribe_size - compiletime_size);
		return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, buf, sctp_sockopt_event_subscribe_size);
	} else /* if (compiletime_size > sctp_sockopt_event_subscribe_size) */ {
		/* we are using a newer userspace with an older kernel and hence need to truncate
		 * the data - but only if the caller didn't try to enable any of the events of the
		 * truncated portion */
		rc = byte_nonzero((const uint8_t *)event, sctp_sockopt_event_subscribe_size,
				  compiletime_size);
		if (rc >= 0) {
			LOGP(DLINP, LOGL_ERROR, "Kernel only supports sctp_event_subscribe of %u bytes, "
				"but caller tried to enable more modern event at offset %u\n",
				sctp_sockopt_event_subscribe_size, rc);
			return -1;
		}

		return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, event, sctp_sockopt_event_subscribe_size);
	}
}
#endif // HAVE_LIBSCTP

int stream_sctp_sock_activate_events(int fd)
{
#ifdef HAVE_LIBSCTP
	struct sctp_event_subscribe event;
	int rc;

	/* subscribe for all relevant events */
	memset((uint8_t *)&event, 0, sizeof(event));
	event.sctp_data_io_event = 1;
	event.sctp_association_event = 1;
	event.sctp_address_event = 1;
	event.sctp_send_failure_event = 1;
	event.sctp_peer_error_event = 1;
	event.sctp_shutdown_event = 1;
	/* IMPORTANT: Do NOT enable sender_dry_event here, see
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1442784 */

	rc = sctp_setsockopt_events_linux_workaround(fd, &event);
	if (rc < 0)
		LOGP(DLINP, LOGL_ERROR, "couldn't activate SCTP events on FD %u\n", fd);
	return rc;
#else
	return -1;
#endif
}

int stream_setsockopt_nodelay(int fd, int proto, int on)
{
	int rc;

	switch (proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		rc = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &on, sizeof(on));
		break;
#endif
	case IPPROTO_TCP:
		rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
		break;
	default:
		rc = -1;
		LOGP(DLINP, LOGL_ERROR, "Unknown protocol %u, cannot set NODELAY\n",
		     proto);
		break;
	}
	return rc;
}

#ifdef HAVE_LIBSCTP
static int stream_sctp_recvmsg_trailer(const char *log_pfx, struct msgb *msg, int ret, const struct sctp_sndrcvinfo *sinfo, int flags)
{
	msgb_sctp_msg_flags(msg) = 0;
	if (OSMO_LIKELY(sinfo)) {
		msgb_sctp_ppid(msg) = ntohl(sinfo->sinfo_ppid);
		msgb_sctp_stream(msg) = sinfo->sinfo_stream;
	}

	if (flags & MSG_NOTIFICATION) {
		char buf[512];
		struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
		int logl = LOGL_INFO;
		union sctp_notification *notif = (union sctp_notification *) msg->data;

		OSMO_STRBUF_PRINTF(sb, "%s NOTIFICATION %s flags=0x%x", log_pfx,
				   osmo_sctp_sn_type_str(notif->sn_header.sn_type), notif->sn_header.sn_flags);
		msgb_put(msg, sizeof(union sctp_notification));
		msgb_sctp_msg_flags(msg) = OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION;
		ret = -EAGAIN;

		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			OSMO_STRBUF_PRINTF(sb, " %s", osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_UP:
				break;
			case SCTP_COMM_LOST:
				OSMO_STRBUF_PRINTF(sb, " (err: %s)",
						   osmo_sctp_sn_error_str(notif->sn_assoc_change.sac_error));
				/* Handle this like a regular disconnect */
				ret = 0;
				break;
			case SCTP_RESTART:
			case SCTP_SHUTDOWN_COMP:
				logl = LOGL_NOTICE;
				break;
			case SCTP_CANT_STR_ASSOC:
				break;
			}
			break;
		case SCTP_SEND_FAILED:
			logl = LOGL_ERROR;
			break;
		case SCTP_PEER_ADDR_CHANGE:
			{
			char addr_str[INET6_ADDRSTRLEN + 10];
			struct sockaddr_storage sa = notif->sn_paddr_change.spc_aaddr;
			osmo_sockaddr_to_str_buf(addr_str, sizeof(addr_str),
						 (const struct osmo_sockaddr *)&sa);
			OSMO_STRBUF_PRINTF(sb, " %s %s err=%s",
					   osmo_sctp_paddr_chg_str(notif->sn_paddr_change.spc_state), addr_str,
					   (notif->sn_paddr_change.spc_state == SCTP_ADDR_UNREACHABLE) ?
						osmo_sctp_sn_error_str(notif->sn_paddr_change.spc_error) : "None");
			}
			break;
		case SCTP_SHUTDOWN_EVENT:
			logl = LOGL_NOTICE;
			/* RFC6458 3.1.4: Any attempt to send more data will cause sendmsg()
			 * to return with an ESHUTDOWN error. */
			break;
		case SCTP_REMOTE_ERROR:
			logl = LOGL_NOTICE;
			OSMO_STRBUF_PRINTF(sb, " %s", osmo_sctp_op_error_str(ntohs(notif->sn_remote_error.sre_error)));
			break;
		}
		LOGP(DLINP, logl, "%s\n", buf);
		return ret;
	}

	if (OSMO_UNLIKELY(ret > 0 && !sinfo))
		LOGP(DLINP, LOGL_ERROR, "%s sctp_recvmsg without SNDRCV cmsg?!?\n", log_pfx);

	return ret;
}

/*! wrapper for regular synchronous sctp_recvmsg(3) */
int stream_sctp_recvmsg_wrapper(int fd, struct msgb *msg, const char *log_pfx)
{
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int ret;

	ret = sctp_recvmsg(fd, msg->tail, msgb_tailroom(msg), NULL, NULL, &sinfo, &flags);
	return stream_sctp_recvmsg_trailer(log_pfx, msg, ret, &sinfo, flags);
}

/*! wrapper for osmo_io asynchronous recvmsg response */
int stream_iofd_sctp_recvmsg_trailer(struct osmo_io_fd *iofd, struct msgb *msg, int ret, const struct msghdr *msgh)
{
	const struct sctp_sndrcvinfo *sinfo = NULL;
	struct cmsghdr *cmsg = NULL;

	for (cmsg = CMSG_FIRSTHDR((struct msghdr *) msgh); cmsg != NULL;
		cmsg = CMSG_NXTHDR((struct msghdr *) msgh, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_SCTP && cmsg->cmsg_type == SCTP_SNDRCV) {
			sinfo = (const struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
			break;
		}
	}

	return stream_sctp_recvmsg_trailer(osmo_iofd_get_name(iofd), msg, ret, sinfo, msgh->msg_flags);
}

/*! Send a message through a connected SCTP socket, similar to sctp_sendmsg().
 *
 *  Appends the message to the internal transmit queue.
 *  If the function returns success (0), it will take ownership of the msgb and
 *  internally call msgb_free() after the write request completes.
 *  In case of an error the msgb needs to be freed by the caller.
 *
 *  \param[in] iofd file descriptor to write to
 *  \param[in] msg message buffer to send; uses msgb_sctp_ppid/msg_sctp_stream
 *  \param[in] sendmsg_flags Flags to pass to the send call
 *  \returns 0 in case of success; a negative value in case of error
 */
int stream_iofd_sctp_send_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendmsg_flags)
{
	struct msghdr outmsg = {};
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct sctp_sndrcvinfo *sinfo;
	struct cmsghdr *cmsg;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_ppid =  htonl(msgb_sctp_ppid(msg));
	sinfo->sinfo_stream = msgb_sctp_stream(msg);

	return osmo_iofd_sendmsg_msgb(iofd, msg, sendmsg_flags, &outmsg);
}
#endif


/*! @} */
