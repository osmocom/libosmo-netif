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

/*! \cond private */

enum osmo_stream_mode {
	OSMO_STREAM_MODE_UNKNOWN,
	OSMO_STREAM_MODE_OSMO_FD,
	OSMO_STREAM_MODE_OSMO_IO,
};

struct stream_tcp_keepalive_pars {
	bool enable;
	bool time_present;
	bool intvl_present;
	bool probes_present;
	int time_value; /* seconds */
	int intvl_value; /* seconds */
	int probes_value;
};
int stream_setsockopt_tcp_keepalive(int fd, int on);
int stream_setsockopt_tcp_keepidle(int fd, int keepalive_time);
int stream_setsockopt_tcp_keepintvl(int fd, int keepalive_intvl);
int stream_setsockopt_tcp_keepcnt(int fd, int keepalive_probes);
int stream_tcp_keepalive_pars_apply(int fd, const struct stream_tcp_keepalive_pars *tkp);

struct stream_tcp_pars {
	struct stream_tcp_keepalive_pars ka;
	bool user_timeout_present;
	unsigned int user_timeout_value;
};
int stream_setsockopt_tcp_user_timeout(int fd, unsigned int user_timeout);

struct osmo_io_fd;
struct msghdr;

int stream_sctp_sock_activate_events(int fd);
int stream_setsockopt_nodelay(int fd, int proto, int on);
int stream_sctp_recvmsg_wrapper(int fd, struct msgb *msg, const char *log_pfx);

int stream_iofd_sctp_send_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendmsg_flags);
int stream_iofd_sctp_recvmsg_trailer(struct osmo_io_fd *iofd, struct msgb *msg, int ret, const struct msghdr *msgh);

/*! \endcond */
