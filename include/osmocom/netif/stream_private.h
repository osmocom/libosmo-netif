#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/socket.h>

#include "config.h"

#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
	#define OSMO_STREAM_MAX_ADDRS OSMO_SOCK_MAX_ADDRS
	/*
	* Platforms that don't have MSG_NOSIGNAL (which disables SIGPIPE)
	* usually have SO_NOSIGPIPE (set via setsockopt).
	*/
	#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
	#endif
#else
	#define OSMO_STREAM_MAX_ADDRS 1
#endif

/*! \addtogroup stream
 *  @{
 */

enum osmo_stream_mode {
	OSMO_STREAM_MODE_UNKNOWN,
	OSMO_STREAM_MODE_OSMO_FD,
	OSMO_STREAM_MODE_OSMO_IO,
};

struct osmo_io_fd;
struct msghdr;

int stream_sctp_sock_activate_events(int fd);
int stream_setsockopt_nodelay(int fd, int proto, int on);
int stream_sctp_recvmsg_wrapper(int fd, struct msgb *msg, const char *log_pfx);

int stream_iofd_sctp_send_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendmsg_flags);
int stream_iofd_sctp_recvmsg_trailer(struct osmo_io_fd *iofd, struct msgb *msg, int ret, const struct msghdr *msgh);

/*! @} */
