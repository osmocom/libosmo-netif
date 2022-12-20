/* (C) 2011 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2015-2016 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/stream.h>

#include "config.h"

#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif

#include <osmocom/netif/sctp.h>

#define LOGSCLI(cli, level, fmt, args...) \
	LOGP(DLINP, level, "[%s] %s(): " fmt, get_value_string(stream_cli_state_names, (cli)->state), __func__, ## args)

/*! \addtogroup stream Osmocom Stream Socket
 *  @{
 *
 *  This code is intended to abstract any use of stream-type sockets,
 *  such as TCP and SCTP.  It offers both server and client side
 *  implementations, fully integrated with the libosmocore select loop
 *  abstraction.
 */

/*! \file stream.c
 *  \brief Osmocom stream socket helpers
 */

#ifdef HAVE_LIBSCTP
/*
 * Platforms that don't have MSG_NOSIGNAL (which disables SIGPIPE)
 * usually have SO_NOSIGPIPE (set via setsockopt).
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

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

static int sctp_sock_activate_events(int fd)
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

static int setsockopt_nodelay(int fd, int proto, int on)
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


/*
 * Client side.
 */

enum osmo_stream_cli_state {
	STREAM_CLI_STATE_CLOSED,	 /* No fd associated, no timer active */
	STREAM_CLI_STATE_WAIT_RECONNECT, /* No fd associated, has timer active to try to connect again */
	STREAM_CLI_STATE_CONNECTING,	 /* Fd associated, but connection not yet confirmed by peer or lower layers */
	STREAM_CLI_STATE_CONNECTED,	 /* Fd associated and connection is established */
	STREAM_CLI_STATE_MAX
};

static const struct value_string stream_cli_state_names[] = {
	{ STREAM_CLI_STATE_CLOSED,	 "CLOSED" },
	{ STREAM_CLI_STATE_WAIT_RECONNECT, "WAIT_RECONNECT" },
	{ STREAM_CLI_STATE_CONNECTING,     "CONNECTING" },
	{ STREAM_CLI_STATE_CONNECTED,      "CONNECTED" },
	{ 0, NULL }
};

#define OSMO_STREAM_CLI_F_RECONF	(1 << 0)
#define OSMO_STREAM_CLI_F_NODELAY	(1 << 1)

#ifdef HAVE_LIBSCTP
#define OSMO_STREAM_MAX_ADDRS OSMO_SOCK_MAX_ADDRS
#else
#define OSMO_STREAM_MAX_ADDRS 1
#endif

struct osmo_stream_cli {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum osmo_stream_cli_state	state;
	char				*addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t			 	addrcnt;
	uint16_t			port;
	char				*local_addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t			 	local_addrcnt;
	uint16_t			local_port;
	int				sk_domain;
	int				sk_type;
	uint16_t			proto;
	int (*connect_cb)(struct osmo_stream_cli *srv);
	int (*disconnect_cb)(struct osmo_stream_cli *srv);
	int (*read_cb)(struct osmo_stream_cli *srv);
	int (*write_cb)(struct osmo_stream_cli *srv);
	void				*data;
	int				flags;
	int				reconnect_timeout;
};

void osmo_stream_cli_close(struct osmo_stream_cli *cli);

/*! \brief Re-connect an Osmocom Stream Client
 *  If re-connection is enabled for this client
 *  (which is the case unless negative timeout was explicitly set via osmo_stream_cli_set_reconnect_timeout() call),
 *  we close any existing connection (if any) and schedule a re-connect timer */
void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli)
{
	osmo_stream_cli_close(cli);

	if (cli->reconnect_timeout < 0) {
		LOGSCLI(cli, LOGL_INFO, "not reconnecting, disabled.\n");
		return;
	}

	cli->state = STREAM_CLI_STATE_WAIT_RECONNECT;
	LOGSCLI(cli, LOGL_INFO, "retrying in %d seconds...\n",
		cli->reconnect_timeout);
	osmo_timer_schedule(&cli->timer, cli->reconnect_timeout, 0);
}

/*! \brief Check if Osmocom Stream Client is in connected state
 *  \param[in] cli Osmocom Stream Client
 *  \return true if connected, false otherwise
 */
bool osmo_stream_cli_is_connected(struct osmo_stream_cli *cli)
{
	return cli->state == STREAM_CLI_STATE_CONNECTED;
}

/*! \brief Close an Osmocom Stream Client
 *  \param[in] cli Osmocom Stream Client to be closed
 *  We unregister the socket fd from the osmocom select() loop
 *  abstraction and close the socket */
void osmo_stream_cli_close(struct osmo_stream_cli *cli)
{
	if (cli->ofd.fd == -1)
		return;
	osmo_fd_unregister(&cli->ofd);
	close(cli->ofd.fd);
	cli->ofd.fd = -1;

	if (cli->state == STREAM_CLI_STATE_CONNECTED) {
		LOGSCLI(cli, LOGL_DEBUG, "connection closed\n");
		if (cli->disconnect_cb)
			cli->disconnect_cb(cli);
	}

	cli->state = STREAM_CLI_STATE_CLOSED;
}

static void osmo_stream_cli_read(struct osmo_stream_cli *cli)
{
	LOGSCLI(cli, LOGL_DEBUG, "message received\n");

	if (cli->read_cb)
		cli->read_cb(cli);
}

static int osmo_stream_cli_write(struct osmo_stream_cli *cli)
{
#ifdef HAVE_LIBSCTP
	struct sctp_sndrcvinfo sinfo;
#endif
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	if (llist_empty(&cli->tx_queue)) {
		osmo_fd_write_disable(&cli->ofd);
		return 0;
	}
	lh = cli->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	if (!osmo_stream_cli_is_connected(cli)) {
		LOGSCLI(cli, LOGL_ERROR, "not connected, dropping data!\n");
		return 0;
	}

	LOGSCLI(cli, LOGL_DEBUG, "sending %u bytes of data\n", msgb_length(msg));

	switch (cli->sk_domain) {
	case AF_UNIX:
		ret = send(cli->ofd.fd, msgb_data(msg), msgb_length(msg), 0);
		break;
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		switch (cli->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.sinfo_ppid = htonl(msgb_sctp_ppid(msg));
			sinfo.sinfo_stream = msgb_sctp_stream(msg);
			ret = sctp_send(cli->ofd.fd, msgb_data(msg), msgb_length(msg),
					&sinfo, MSG_NOSIGNAL);
			break;
#endif
		case IPPROTO_TCP:
		default:
			ret = send(cli->ofd.fd, msgb_data(msg), msgb_length(msg), 0);
			break;
		}
		break;
	default:
		ret = -ENOTSUP;
	}
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			osmo_stream_cli_reconnect(cli);
		}
		LOGSCLI(cli, LOGL_ERROR, "error %d to send\n", ret);
	}
	msgb_free(msg);
	return 0;
}

static int _setsockopt_nosigpipe(struct osmo_stream_cli *cli)
{
#ifdef SO_NOSIGPIPE
	int ret;
	int val = 1;
	ret = setsockopt(cli->ofd.fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(val));
	if (ret < 0)
		LOGSCLI(cli, LOGL_DEBUG, "Failed setting SO_NOSIGPIPE: %s\n", strerror(errno));
	return ret;
#else
	return 0;
#endif
}

static int osmo_stream_cli_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_cli *cli = ofd->data;
	int error, ret;
	socklen_t len = sizeof(error);

	switch(cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (ret >= 0 && error > 0) {
			osmo_stream_cli_reconnect(cli);
			return 0;
		}

		/* If messages got enqueued while 'connecting', keep WRITE flag
		   up to dispatch them upon next main loop step */
		if (llist_empty(&cli->tx_queue))
			osmo_fd_write_disable(&cli->ofd);

		LOGSCLI(cli, LOGL_DEBUG, "connection done.\n");
		cli->state = STREAM_CLI_STATE_CONNECTED;
		switch (cli->sk_domain) {
		case AF_UNIX:
			_setsockopt_nosigpipe(cli);
			break;
		case AF_UNSPEC:
		case AF_INET:
		case AF_INET6:
			if (cli->proto == IPPROTO_SCTP) {
				_setsockopt_nosigpipe(cli);
				sctp_sock_activate_events(ofd->fd);
			}
			break;
		default:
			break;
		}
		if (cli->connect_cb)
			cli->connect_cb(cli);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (what & OSMO_FD_READ) {
			LOGSCLI(cli, LOGL_DEBUG, "connected read\n");
			osmo_stream_cli_read(cli);
		}
		if (what & OSMO_FD_WRITE) {
			LOGSCLI(cli, LOGL_DEBUG, "connected write\n");
			osmo_stream_cli_write(cli);
		}
		break;
	default:
		/* Only CONNECTING and CONNECTED states are expected, since they are the only states where FD exists: */
		osmo_panic("osmo_stream_cli_fd_cb called with unexpected state %d\n", cli->state);
	}
	return 0;
}

static void cli_timer_cb(void *data);

/*! \brief Create an Osmocom stream client
 *  \param[in] ctx talloc context from which to allocate memory
 *  This function allocates a new \ref osmo_stream_cli and initializes
 *  it with default values (5s reconnect timer, TCP protocol)
 *  \return allocated stream client, or NULL in case of error
 */
struct osmo_stream_cli *osmo_stream_cli_create(void *ctx)
{
	struct osmo_stream_cli *cli;

	cli = talloc_zero(ctx, struct osmo_stream_cli);
	if (!cli)
		return NULL;

	cli->sk_domain = AF_UNSPEC;
	cli->sk_type = SOCK_STREAM;
	cli->proto = IPPROTO_TCP;
	cli->ofd.fd = -1;
	cli->ofd.priv_nr = 0;	/* XXX */
	cli->ofd.cb = osmo_stream_cli_fd_cb;
	cli->ofd.data = cli;
	cli->state = STREAM_CLI_STATE_CLOSED;
	osmo_timer_setup(&cli->timer, cli_timer_cb, cli);
	cli->reconnect_timeout = 5;	/* default is 5 seconds. */
	INIT_LLIST_HEAD(&cli->tx_queue);

	return cli;
}

/*! \brief Set the remote address to which we connect
 *  \param[in] cli Stream Client to modify
 *  \param[in] addr Remote IP address
 */
void
osmo_stream_cli_set_addr(struct osmo_stream_cli *cli, const char *addr)
{
	osmo_stream_cli_set_addrs(cli, &addr, 1);
}

/*! \brief Set the remote address set to which we connect.
 *  Useful for protocols allowing connecting to more than one address (such as SCTP)
 *  \param[in] cli Stream Client to modify
 *  \param[in] addr Remote IP address set
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_set_addrs(struct osmo_stream_cli *cli, const char **addr, size_t addrcnt)
{
	int i = 0;

	if (addrcnt > OSMO_STREAM_MAX_ADDRS)
		return -EINVAL;

	for (; i < addrcnt; i++)
		osmo_talloc_replace_string(cli, &cli->addr[i], addr[i]);
	for (; i < cli->addrcnt; i++) {
			talloc_free(cli->addr[i]);
			cli->addr[i] = NULL;
	}

	cli->addrcnt = addrcnt;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
	return 0;
}

/*! \brief Set the remote port number to which we connect
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Remote port number
 */
void
osmo_stream_cli_set_port(struct osmo_stream_cli *cli, uint16_t port)
{
	cli->port = port;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/*! \brief Set the local port number for the socket (to be bound to)
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Local port number
 */
void
osmo_stream_cli_set_local_port(struct osmo_stream_cli *cli, uint16_t port)
{
	cli->local_port = port;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/*! \brief Set the local address for the socket (to be bound to)
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Local host name
 */
void
osmo_stream_cli_set_local_addr(struct osmo_stream_cli *cli, const char *addr)
{
	osmo_stream_cli_set_local_addrs(cli, &addr, 1);
}

/*! \brief Set the local address set to which we connect.
 *  Useful for protocols allowing bind to more than one address (such as SCTP)
 *  \param[in] cli Stream Client to modify
 *  \param[in] addr Local IP address set
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_set_local_addrs(struct osmo_stream_cli *cli, const char **addr, size_t addrcnt)
{
	int i = 0;

	if (addrcnt > OSMO_STREAM_MAX_ADDRS)
		return -EINVAL;

	for (; i < addrcnt; i++)
		osmo_talloc_replace_string(cli, &cli->local_addr[i], addr[i]);
	for (; i < cli->local_addrcnt; i++) {
			talloc_free(cli->local_addr[i]);
			cli->local_addr[i] = NULL;
	}

	cli->local_addrcnt = addrcnt;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
	return 0;
}

/*! \brief Set the protocol for the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] proto Protocol (like IPPROTO_TCP (default), IPPROTO_SCTP, ...)
 */
void
osmo_stream_cli_set_proto(struct osmo_stream_cli *cli, uint16_t proto)
{
	cli->proto = proto;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/*! \brief Set the socket type for the stream server link
 *  \param[in] cli Stream Client to modify
 *  \param[in] type Socket Type (like SOCK_STREAM (default), SOCK_SEQPACKET, ...)
 *  \returns zero on success, negative on error.
 */
int osmo_stream_cli_set_type(struct osmo_stream_cli *cli, int type)
{
	switch (type) {
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		break;
	default:
		return -ENOTSUP;
	}
	cli->sk_type = type;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
	return 0;
}

/*! \brief Set the socket type for the stream server link
 *  \param[in] cli Stream Client to modify
 *  \param[in] type Socket Domain (like AF_UNSPEC (default for IP), AF_UNIX, AF_INET, ...)
 *  \returns zero on success, negative on error.
 */
int osmo_stream_cli_set_domain(struct osmo_stream_cli *cli, int domain)
{
	switch (domain) {
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
	case AF_UNIX:
		break;
	default:
		return -ENOTSUP;
	}
	cli->sk_domain = domain;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
	return 0;
}

/*! \brief Set the reconnect time of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] timeout Re-connect timeout in seconds or negative value to disable auto-reconnection */
void
osmo_stream_cli_set_reconnect_timeout(struct osmo_stream_cli *cli, int timeout)
{
	cli->reconnect_timeout = timeout;
}

/*! \brief Set application private data of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_cli_set_data(struct osmo_stream_cli *cli, void *data)
{
	cli->data = data;
}

/*! \brief Get application private data of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \returns Application private data, as set by \ref osmo_stream_cli_set_data() */
void *osmo_stream_cli_get_data(struct osmo_stream_cli *cli)
{
	return cli->data;
}

/*! \brief Get the stream client socket description.
 *  \param[in] cli Stream Client to examine
 *  \returns Socket description or NULL in case of error */
char *osmo_stream_cli_get_sockname(const struct osmo_stream_cli *cli)
{
	static char buf[OSMO_SOCK_NAME_MAXLEN];

	osmo_sock_get_name_buf(buf, OSMO_SOCK_NAME_MAXLEN, cli->ofd.fd);

	return buf;
}

/*! \brief Get Osmocom File Descriptor of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli)
{
	return &cli->ofd;
}

/*! \brief Set the call-back function called on connect of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] connect_cb Call-back function to be called upon connect */
void
osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli,
	int (*connect_cb)(struct osmo_stream_cli *cli))
{
	cli->connect_cb = connect_cb;
}

/*! \brief Set the call-back function called on disconnect of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] disconnect_cb Call-back function to be called upon disconnect */
void osmo_stream_cli_set_disconnect_cb(struct osmo_stream_cli *cli,
				       int (*disconnect_cb)(struct osmo_stream_cli *cli))
{
	cli->disconnect_cb = disconnect_cb;
}

/*! \brief Set the call-back function called to read from the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] read_cb Call-back function to be called when we want to read */
void
osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli,
			    int (*read_cb)(struct osmo_stream_cli *cli))
{
	cli->read_cb = read_cb;
}

/*! \brief Destroy a Osmocom stream client (includes close)
 *  \param[in] cli Stream Client to destroy */
void osmo_stream_cli_destroy(struct osmo_stream_cli *cli)
{
	osmo_stream_cli_close(cli);
	osmo_timer_del(&cli->timer);
	msgb_queue_free(&cli->tx_queue);
	talloc_free(cli);
}

/*! \brief DEPRECATED: use osmo_stream_cli_set_reconnect_timeout() or osmo_stream_cli_reconnect() instead!
 * Open connection of an Osmocom stream client
 *  \param[in] cli Stream Client to connect
 *  \param[in] reconect 1 if we should not automatically reconnect
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && cli->ofd.fd >= 0)
		osmo_stream_cli_close(cli);

	cli->flags &= ~OSMO_STREAM_CLI_F_RECONF;

	switch (cli->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		ret = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, cli->proto,
						(const char **)cli->local_addr, cli->local_addrcnt, cli->local_port,
						(const char **)cli->addr, cli->addrcnt, cli->port,
						OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
		break;
#endif
	default:
		ret = osmo_sock_init2(AF_UNSPEC, SOCK_STREAM, cli->proto,
				      cli->local_addr[0], cli->local_port,
				      cli->addr[0], cli->port,
				      OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	}

	if (ret < 0) {
		if (reconnect)
			osmo_stream_cli_reconnect(cli);
		return ret;
	}
	osmo_fd_setup(&cli->ofd, ret, OSMO_FD_READ | OSMO_FD_WRITE, cli->ofd.cb, cli->ofd.data, cli->ofd.priv_nr);

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = setsockopt_nodelay(cli->ofd.fd, cli->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	if (osmo_fd_register(&cli->ofd) < 0)
		goto error_close_socket;

	cli->state = STREAM_CLI_STATE_CONNECTING;
	return 0;

error_close_socket:
	close(cli->ofd.fd);
	cli->ofd.fd = -1;
	return -EIO;
}

/*! \brief Set the NODELAY socket option to avoid Nagle-like behavior
 *  Setting this to nodelay=true will automatically set the NODELAY
 *  socket option on any socket established via \ref osmo_stream_cli_open
 *  or any re-connect.  You have to set this _before_ opening the
 *  socket.
 *  \param[in] cli Stream client whose sockets are to be configured
 *  \param[in] nodelay whether to set (true) NODELAY before connect()
 */
void osmo_stream_cli_set_nodelay(struct osmo_stream_cli *cli, bool nodelay)
{
	if (nodelay)
		cli->flags |= OSMO_STREAM_CLI_F_NODELAY;
	else
		cli->flags &= ~OSMO_STREAM_CLI_F_NODELAY;
}

/*! \brief Open connection of an Osmocom stream client
 *  By default the client will automatically reconnect after default timeout.
 *  To disable this, use osmo_stream_cli_set_reconnect_timeout() before calling this function.
 *  \param[in] cli Stream Client to connect
 *  \return negative on error, 0 on success */
int osmo_stream_cli_open(struct osmo_stream_cli *cli)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && cli->ofd.fd >= 0)
		osmo_stream_cli_close(cli);

	cli->flags &= ~OSMO_STREAM_CLI_F_RECONF;

	switch (cli->sk_domain) {
	case AF_UNIX:
		ret = osmo_sock_unix_init(cli->sk_type, 0, cli->addr[0], OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
		break;
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		switch (cli->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
			ret = osmo_sock_init2_multiaddr(cli->sk_domain, cli->sk_type, cli->proto,
							(const char **)cli->local_addr, cli->local_addrcnt, cli->local_port,
							(const char **)cli->addr, cli->addrcnt, cli->port,
							OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
			break;
#endif
		default:
			ret = osmo_sock_init2(cli->sk_domain, cli->sk_type, cli->proto,
					      cli->local_addr[0], cli->local_port,
					      cli->addr[0], cli->port,
					      OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
		}
		break;
	default:
		return -ENOTSUP;
	}

	if (ret < 0) {
		osmo_stream_cli_reconnect(cli);
		return ret;
	}
	osmo_fd_setup(&cli->ofd, ret, OSMO_FD_READ | OSMO_FD_WRITE, cli->ofd.cb, cli->ofd.data, cli->ofd.priv_nr);

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = setsockopt_nodelay(cli->ofd.fd, cli->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	if (osmo_fd_register(&cli->ofd) < 0)
		goto error_close_socket;

	cli->state = STREAM_CLI_STATE_CONNECTING;
	return 0;

error_close_socket:
	cli->state = STREAM_CLI_STATE_CLOSED;
	close(cli->ofd.fd);
	cli->ofd.fd = -1;
	return -EIO;
}

static void cli_timer_cb(void *data)
{
	struct osmo_stream_cli *cli = data;

	LOGSCLI(cli, LOGL_DEBUG, "reconnecting.\n");
	osmo_stream_cli_open(cli);
}

/*! \brief Enqueue data to be sent via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg)
{
	OSMO_ASSERT(cli);
	OSMO_ASSERT(msg);
	msgb_enqueue(&cli->tx_queue, msg);
	osmo_fd_write_enable(&cli->ofd);
}

/*! \brief Receive data via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read; <=0 in case of error */
int osmo_stream_cli_recv(struct osmo_stream_cli *cli, struct msgb *msg)
{
	int ret;
	OSMO_ASSERT(cli);
	OSMO_ASSERT(msg);

	ret = recv(cli->ofd.fd, msg->data, msg->data_len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGSCLI(cli, LOGL_ERROR, "lost connection with srv\n");
		}
		osmo_stream_cli_reconnect(cli);
		return ret;
	} else if (ret == 0) {
		LOGSCLI(cli, LOGL_ERROR, "connection closed with srv\n");
		osmo_stream_cli_reconnect(cli);
		return ret;
	}
	msgb_put(msg, ret);
	LOGSCLI(cli, LOGL_DEBUG, "received %d bytes from srv\n", ret);
	return ret;
}

void osmo_stream_cli_clear_tx_queue(struct osmo_stream_cli *cli)
{
	msgb_queue_free(&cli->tx_queue);
	/* If in state 'connecting', keep WRITE flag up to receive
	 * socket connection signal and then transition to STATE_CONNECTED: */
	if (cli->state == STREAM_CLI_STATE_CONNECTED)
		osmo_fd_write_disable(&cli->ofd);
}

/*
 * Server side.
 */

#define OSMO_STREAM_SRV_F_RECONF	(1 << 0)
#define OSMO_STREAM_SRV_F_NODELAY	(1 << 1)

struct osmo_stream_srv_link {
	struct osmo_fd		ofd;
	char			*addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t			addrcnt;
	uint16_t		port;
	int			sk_domain;
	int			sk_type;
	uint16_t		proto;
	int (*accept_cb)(struct osmo_stream_srv_link *srv, int fd);
	void			*data;
	int			flags;
};

static int osmo_stream_srv_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int ret;
	int sock_fd;
	char addrstr[128];
	bool is_ipv6 = false;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	struct osmo_stream_srv_link *link = ofd->data;

	ret = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to accept from origin "
			"peer, reason=`%s'\n", strerror(errno));
		return ret;
	}
	sock_fd = ret;

	is_ipv6 = false;
	switch (((struct sockaddr *)&sa)->sa_family) {
	case AF_UNIX:
		LOGP(DLINP, LOGL_DEBUG, "accept()ed new link on fd %d\n",
		     sock_fd);
		break;
	case AF_INET6:
		is_ipv6 = true;
		/* fall through */
	case AF_INET:
		LOGP(DLINP, LOGL_DEBUG, "accept()ed new link from %s to port %u\n",
			inet_ntop(is_ipv6 ? AF_INET6 : AF_INET,
				  is_ipv6 ? (void *)&(((struct sockaddr_in6 *)&sa)->sin6_addr) :
					    (void *)&(((struct sockaddr_in *)&sa)->sin_addr),
				  addrstr, sizeof(addrstr)),
			link->port);

		if (link->proto == IPPROTO_SCTP) {
			ret = sctp_sock_activate_events(sock_fd);
			if (ret < 0)
				goto error_close_socket;
		}
		break;
	default:
		LOGP(DLINP, LOGL_DEBUG, "accept()ed unexpected address family %d\n",
		     ((struct sockaddr *)&sa)->sa_family);
		goto error_close_socket;
	}

	if (link->flags & OSMO_STREAM_SRV_F_NODELAY) {
		ret = setsockopt_nodelay(sock_fd, link->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	if (!link->accept_cb) {
		ret = -ENOTSUP;
		goto error_close_socket;
	}

	ret = link->accept_cb(link, sock_fd);
	if (ret)
		goto error_close_socket;
	return 0;

error_close_socket:
	close(sock_fd);
	return ret;
}

/*! \brief Create an Osmocom Stream Server Link
 *  A Stream Server Link is the listen()+accept() "parent" to individual
 *  Stream Servers
 *  \param[in] ctx talloc allocation context
 *  \returns Stream Server Link with default values (TCP)
 */
struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx)
{
	struct osmo_stream_srv_link *link;

	link = talloc_zero(ctx, struct osmo_stream_srv_link);
	if (!link)
		return NULL;

	link->sk_domain = AF_UNSPEC;
	link->sk_type = SOCK_STREAM;
	link->proto = IPPROTO_TCP;
	osmo_fd_setup(&link->ofd, -1, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_srv_fd_cb, link, 0);

	return link;
}

/*! \brief Set the NODELAY socket option to avoid Nagle-like behavior
 *  Setting this to nodelay=true will automatically set the NODELAY
 *  socket option on any socket established via this server link, before
 *  calling the accept_cb()
 *  \param[in] link server link whose sockets are to be configured
 *  \param[in] nodelay whether to set (true) NODELAY after accept
 */
void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay)
{
	if (nodelay)
		link->flags |= OSMO_STREAM_SRV_F_NODELAY;
	else
		link->flags &= ~OSMO_STREAM_SRV_F_NODELAY;
}

/*! \brief Set the local address to which we bind
 *  \param[in] link Stream Server Link to modify
 *  \param[in] addr Local IP address
 */
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link,
				      const char *addr)
{
	osmo_stream_srv_link_set_addrs(link, &addr, 1);
}

/*! \brief Set the local address set to which we bind.
 *  Useful for protocols allowing bind on more than one address (such as SCTP)
 *  \param[in] link Stream Server Link to modify
 *  \param[in] addr Local IP address
 *  \return negative on error, 0 on success
 */
int osmo_stream_srv_link_set_addrs(struct osmo_stream_srv_link *link, const char **addr, size_t addrcnt)
{
	int i = 0;

	if (addrcnt > OSMO_STREAM_MAX_ADDRS)
		return -EINVAL;

	for (; i < addrcnt; i++)
		osmo_talloc_replace_string(link, &link->addr[i], addr[i]);
	for (; i < link->addrcnt; i++) {
			talloc_free(link->addr[i]);
			link->addr[i] = NULL;
	}

	link->addrcnt = addrcnt;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
	return 0;
}

/*! \brief Set the local port number to which we bind
 *  \param[in] link Stream Server Link to modify
 *  \param[in] port Local port number
 */
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link,
				      uint16_t port)
{
	link->port = port;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}

/*! \brief Set the protocol for the stream server link
 *  \param[in] link Stream Server Link to modify
 *  \param[in] proto Protocol (like IPPROTO_TCP (default), IPPROTO_SCTP, ...)
 */
void
osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link,
			  uint16_t proto)
{
	link->proto = proto;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}


/*! \brief Set the socket type for the stream server link
 *  \param[in] link Stream Server Link to modify
 *  \param[in] type Socket Type (like SOCK_STREAM (default), SOCK_SEQPACKET, ...)
 *  \returns zero on success, negative on error.
 */
int osmo_stream_srv_link_set_type(struct osmo_stream_srv_link *link, int type)
{
	switch (type) {
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		break;
	default:
		return -ENOTSUP;
	}
	link->sk_type = type;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
	return 0;
}

/*! \brief Set the socket type for the stream server link
 *  \param[in] link Stream Server Link to modify
 *  \param[in] type Socket Domain (like AF_UNSPEC (default for IP), AF_UNIX, AF_INET, ...)
 *  \returns zero on success, negative on error.
 */
int osmo_stream_srv_link_set_domain(struct osmo_stream_srv_link *link, int domain)
{
	switch (domain) {
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
	case AF_UNIX:
		break;
	default:
		return -ENOTSUP;
	}
	link->sk_domain = domain;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
	return 0;
}

/*! \brief Set application private data of the stream server link
 *  \param[in] link Stream Server Link to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link,
				 void *data)
{
	link->data = data;
}

/*! \brief Get application private data of the stream server link
 *  \param[in] link Stream Server Link to modify
 *  \returns Application private data, as set by \ref osmo_stream_cli_set_data() */
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link)
{
	return link->data;
}

/*! \brief Get description of the stream server link e. g. 127.0.0.1:1234
 *  \param[in] link Stream Server Link to examine
 *  \returns Link description or NULL in case of error */
char *osmo_stream_srv_link_get_sockname(const struct osmo_stream_srv_link *link)
{
	static char buf[INET6_ADDRSTRLEN + 6];
	int rc = osmo_sock_get_local_ip(link->ofd.fd, buf, INET6_ADDRSTRLEN);
	if (rc < 0)
		return NULL;

	buf[strnlen(buf, INET6_ADDRSTRLEN + 6)] = ':';

	rc = osmo_sock_get_local_ip_port(link->ofd.fd, buf + strnlen(buf, INET6_ADDRSTRLEN + 6), 6);
	if (rc < 0)
		return NULL;

	return buf;
}

/*! \brief Get Osmocom File Descriptor of the stream server link
 *  \param[in] link Stream Server Link
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link)
{
	return &link->ofd;
}

/*! \brief Set the accept() call-back of the stream server link
 *  \param[in] link Stream Server Link
 *  \param[in] accept_cb Call-back function executed upon accept() */
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link,
	int (*accept_cb)(struct osmo_stream_srv_link *link, int fd))

{
	link->accept_cb = accept_cb;
}

/*! \brief Destroy the stream server link. Closes + Releases Memory.
 *  \param[in] link Stream Server Link */
void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link)
{
	osmo_stream_srv_link_close(link);
	talloc_free(link);
}

/*! \brief Open the stream server link.  This actually initializes the
 *  underlying socket and binds it to the configured ip/port
 *  \param[in] link Stream Server Link to open
 *  \return negative on error, 0 on success */
int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link)
{
	int ret;

	if (link->ofd.fd >= 0) {
		/* No reconfigure needed for existing socket, we are fine */
		if (!(link->flags & OSMO_STREAM_SRV_F_RECONF))
			return 0;
		/* we are reconfiguring this socket, close existing first. */
		osmo_stream_srv_link_close(link);
	}

	link->flags &= ~OSMO_STREAM_SRV_F_RECONF;

	switch (link->sk_domain) {
	case AF_UNIX:
		ret = osmo_sock_unix_init(link->sk_type, 0, link->addr[0], OSMO_SOCK_F_BIND);
		break;
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		switch (link->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
			ret = osmo_sock_init2_multiaddr(link->sk_domain, link->sk_type, link->proto,
							(const char **)link->addr, link->addrcnt, link->port,
							NULL, 0, 0, OSMO_SOCK_F_BIND);
			break;
#endif
		default:
			ret = osmo_sock_init(link->sk_domain, link->sk_type, link->proto,
					     link->addr[0], link->port, OSMO_SOCK_F_BIND);
		}
		break;
	default:
		ret = -ENOTSUP;
	}
	if (ret < 0)
		return ret;

	link->ofd.fd = ret;
	if (osmo_fd_register(&link->ofd) < 0) {
		close(ret);
		link->ofd.fd = -1;
		return -EIO;
	}
	return 0;
}

/*! \brief Close the stream server link and unregister from select loop
 *  Does not destroy the server link, merely closes it!
 *  \param[in] link Stream Server Link to close */
void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link)
{
	if (link->ofd.fd == -1)
		return;
	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
	link->ofd.fd = -1;
}

#define OSMO_STREAM_SRV_F_FLUSH_DESTROY	(1 << 0)

struct osmo_stream_srv {
	struct osmo_stream_srv_link	*srv;
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	int (*closed_cb)(struct osmo_stream_srv *peer);
	int (*cb)(struct osmo_stream_srv *peer);
	void				*data;
	int				flags;
};

static int osmo_stream_srv_read(struct osmo_stream_srv *conn)
{
	int rc = 0;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGP(DLINP, LOGL_DEBUG, "Connection is being flushed and closed; ignoring received message\n");
		return 0;
	}

	if (conn->cb)
		rc = conn->cb(conn);

	return rc;
}

static void osmo_stream_srv_write(struct osmo_stream_srv *conn)
{
#ifdef HAVE_LIBSCTP
	struct sctp_sndrcvinfo sinfo;
#endif
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	if (llist_empty(&conn->tx_queue)) {
		osmo_fd_write_disable(&conn->ofd);
		return;
	}
	lh = conn->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	LOGP(DLINP, LOGL_DEBUG, "sending %u bytes of data\n", msg->len);

	switch (conn->srv->sk_domain) {
	case AF_UNIX:
		ret = send(conn->ofd.fd, msgb_data(msg), msgb_length(msg), 0);
		break;
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		switch (conn->srv->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.sinfo_ppid = htonl(msgb_sctp_ppid(msg));
			sinfo.sinfo_stream = msgb_sctp_stream(msg);
			ret = sctp_send(conn->ofd.fd, msgb_data(msg), msgb_length(msg),
					&sinfo, MSG_NOSIGNAL);
			break;
#endif
		case IPPROTO_TCP:
		default:
			ret = send(conn->ofd.fd, msgb_data(msg), msgb_length(msg), 0);
			break;
		}
		break;
	default:
		ret = -1;
		errno = ENOTSUP;
	}
	if (ret == -1) /* send(): On error -1 is returned, and errno is set appropriately */
		LOGP(DLINP, LOGL_ERROR, "error to send: %s\n", strerror(errno));

	msgb_free(msg);

	if (llist_empty(&conn->tx_queue) && (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY))
		osmo_stream_srv_destroy(conn);
}

static int osmo_stream_srv_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_srv *conn = ofd->data;
	int rc = 0;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write (what=0x%x)\n", what);
	if (what & OSMO_FD_READ)
		rc = osmo_stream_srv_read(conn);
	if (rc != -EBADF && (what & OSMO_FD_WRITE))
		osmo_stream_srv_write(conn);

	return rc;
}

/*! \brief Create a Stream Server inside the specified link
 *  \param[in] ctx talloc allocation context from which to allocate
 *  \param[in] link Stream Server Link to which we belong
 *  \returns Stream Server in case of success; NULL on error */
struct osmo_stream_srv *
osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link,
	int fd,
	int (*cb)(struct osmo_stream_srv *conn),
	int (*closed_cb)(struct osmo_stream_srv *conn), void *data)
{
	struct osmo_stream_srv *conn;

	OSMO_ASSERT(link);

	conn = talloc_zero(ctx, struct osmo_stream_srv);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate new peer in srv, "
			"reason=`%s'\n", strerror(errno));
		return NULL;
	}
	conn->srv = link;
	osmo_fd_setup(&conn->ofd, fd, OSMO_FD_READ, osmo_stream_srv_cb, conn, 0);
	conn->cb = cb;
	conn->closed_cb = closed_cb;
	conn->data = data;
	INIT_LLIST_HEAD(&conn->tx_queue);

	if (osmo_fd_register(&conn->ofd) < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not register FD\n");
		talloc_free(conn);
		return NULL;
	}
	return conn;
}

/*! \brief Prepare to send out all pending messages on the connection's Tx queue
 *  and then automatically destroy the stream with osmo_stream_srv_destroy().
 *  This function disables queuing of new messages on the connection and also
 *  disables reception of new messages on the connection.
 *  \param[in] conn Stream Server to modify */
void osmo_stream_srv_set_flush_and_destroy(struct osmo_stream_srv *conn)
{
	conn->flags |= OSMO_STREAM_SRV_F_FLUSH_DESTROY;
}

/*! \brief Set application private data of the stream server
 *  \param[in] conn Stream Server to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_srv_set_data(struct osmo_stream_srv *conn,
				 void *data)
{
	conn->data = data;
}

/*! \brief Get application private data of the stream server
 *  \param[in] conn Stream Server
 *  \returns Application private data, as set by \ref osmo_stream_srv_set_data() */
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn)
{
	return conn->data;
}

/*! \brief Get Osmocom File Descriptor of the stream server
 *  \param[in] conn Stream Server
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_srv_get_ofd(struct osmo_stream_srv *conn)
{
	return &conn->ofd;
}

/*! \brief Get the master (Link) from a Stream Server
 *  \param[in] conn Stream Server of which we want to know the Link
 *  \returns Link through which the given Stream Server is established */
struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn)
{
	return conn->srv;
}

/*! \brief Destroy given Stream Server
 *  This function closes the Stream Server socket, unregisters from
 *  select loop, invokes the connection's closed_cb() callback to allow API
 *  users to clean up any associated state they have for this connection,
 *  and then de-allocates associated memory.
 *  \param[in] conn Stream Server to be destroyed */
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
	conn->ofd.fd = -1;
	if (conn->closed_cb)
		conn->closed_cb(conn);
	msgb_queue_free(&conn->tx_queue);
	talloc_free(conn);
}

/*! \brief Enqueue data to be sent via an Osmocom stream server
 *  \param[in] conn Stream Server through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg)
{
	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGP(DLINP, LOGL_DEBUG, "Connection is being flushed and closed; ignoring new outgoing message\n");
		return;
	}

	msgb_enqueue(&conn->tx_queue, msg);
	osmo_fd_write_enable(&conn->ofd);
}

#ifdef HAVE_LIBSCTP
static int _sctp_recvmsg_wrapper(int fd, struct msgb *msg)
{
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int ret;

	ret = sctp_recvmsg(fd, msgb_data(msg), msgb_tailroom(msg),
			NULL, NULL, &sinfo, &flags);
	msgb_sctp_msg_flags(msg) = 0;
	msgb_sctp_ppid(msg) = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_stream(msg) = sinfo.sinfo_stream;
	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *)msgb_data(msg);
		LOGP(DLINP, LOGL_DEBUG, "NOTIFICATION %u flags=0x%x\n", notif->sn_header.sn_type, notif->sn_header.sn_flags);
		msgb_put(msg, sizeof(union sctp_notification));
		msgb_sctp_msg_flags(msg) = OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION;
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			LOGP(DLINP, LOGL_DEBUG, "===> ASSOC CHANGE:");
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_UP:
				LOGPC(DLINP, LOGL_DEBUG, " UP\n");
				break;
			case SCTP_COMM_LOST:
				LOGPC(DLINP, LOGL_DEBUG, " LOST\n");
				/* Handle this like a regular disconnect */
				return 0;
			case SCTP_RESTART:
				LOGPC(DLINP, LOGL_DEBUG, " RESTART\n");
				break;
			case SCTP_SHUTDOWN_COMP:
				LOGPC(DLINP, LOGL_DEBUG, " SHUTDOWN COMP\n");
				break;
			case SCTP_CANT_STR_ASSOC:
				LOGPC(DLINP, LOGL_DEBUG, " CANT STR ASSOC\n");
				break;
			}
			break;
		case SCTP_SEND_FAILED:
			LOGP(DLINP, LOGL_DEBUG, "===> SEND FAILED\n");
			break;
		case SCTP_PEER_ADDR_CHANGE:
			{
			char addr_str[INET6_ADDRSTRLEN + 10];
			struct sockaddr_storage sa = notif->sn_paddr_change.spc_aaddr;
			osmo_sockaddr_to_str_buf(addr_str, sizeof(addr_str),
						 (const struct osmo_sockaddr *)&sa);
			LOGP(DLINP, LOGL_DEBUG, "===> PEER ADDR CHANGE: %s %s err=%s\n",
			     addr_str, osmo_sctp_paddr_chg_str(notif->sn_paddr_change.spc_state),
			     (notif->sn_paddr_change.spc_state == SCTP_ADDR_UNREACHABLE) ?
				osmo_sctp_sn_error_str(notif->sn_paddr_change.spc_error) : "None");
			}
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOGP(DLINP, LOGL_DEBUG, "===> SHUTDOWN EVT\n");
			/* Handle this like a regular disconnect */
			return 0;
		}
		return -EAGAIN;
	}
	return ret;
}
#endif

/*! \brief Receive data via Osmocom stream server
 *  \param[in] conn Stream Server from which to receive
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read, negative on error.
 *
 *  If conn is an SCTP connection, additional specific considerations shall be taken:
 *  - msg->cb is always filled with SCTP ppid, and SCTP stream values, see msgb_sctp_*() APIs.
 *  - If an SCTP notification was received when reading from the SCTP socket,
 *    msgb_sctp_msg_flags(msg) will contain bit flag
 *    OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION set, and the msgb will
 *    contain a "union sctp_notification" instead of user data. In this case the
 *    return code will be either 0 (if conn is considered dead after the
 *    notification) or -EAGAIN (if conn is considered still alive after the
 *    notification) resembling the standard recv() API.
 */
int osmo_stream_srv_recv(struct osmo_stream_srv *conn, struct msgb *msg)
{
	int ret;
	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);

	switch (conn->srv->sk_domain) {
	case AF_UNIX:
		ret = recv(conn->ofd.fd, msgb_data(msg), msgb_tailroom(msg), 0);
		break;
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		switch (conn->srv->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
			ret = _sctp_recvmsg_wrapper(conn->ofd.fd, msg);
			break;
#endif
		case IPPROTO_TCP:
		default:
			ret = recv(conn->ofd.fd, msgb_data(msg), msgb_tailroom(msg), 0);
			break;
		}
		break;
	default:
		ret = -ENOTSUP;
	}

	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR,
				"lost connection with client\n");
		}
		return ret;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with client\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from client\n", ret);
	return ret;
}

void osmo_stream_srv_clear_tx_queue(struct osmo_stream_srv *conn)
{
	msgb_queue_free(&conn->tx_queue);
	osmo_fd_write_disable(&conn->ofd);
	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)
		osmo_stream_srv_destroy(conn);
}

/*! @} */
