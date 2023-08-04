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


/*! \addtogroup stream Osmocom Stream Socket (client side)
 *  @{
 *
 *  This code is intended to abstract any use of stream-type sockets,
 *  such as TCP and SCTP.  It offers client side implementation,
 * fully integrated with the libosmocore select loop abstraction.
 */

/*! \file stream_cli.c
 *  \brief Osmocom stream socket helpers (client side)
 */

#define LOGSCLI(cli, level, fmt, args...) \
	LOGP(DLINP, level, "CLICONN(%s,%s){%s} " fmt, \
	     cli->name ? : "", \
	     cli->sockname, \
	     get_value_string(stream_cli_state_names, (cli)->state), \
	     ## args)

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

struct osmo_stream_cli {
	char *name;
	char sockname[OSMO_SOCK_NAME_MAXLEN];
	enum osmo_stream_mode mode;
	union {
		struct osmo_fd			ofd;
		struct osmo_io_fd		*iofd;
	};
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum osmo_stream_cli_state	state;
	char				*addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t				addrcnt;
	uint16_t			port;
	char				*local_addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t				local_addrcnt;
	uint16_t			local_port;
	int				sk_domain;
	int				sk_type;
	uint16_t			proto;
	int (*connect_cb)(struct osmo_stream_cli *cli);
	int (*disconnect_cb)(struct osmo_stream_cli *cli);
	int (*read_cb)(struct osmo_stream_cli *cli);
	int (*iofd_read_cb)(struct osmo_stream_cli *cli, struct msgb *msg);
	int (*write_cb)(struct osmo_stream_cli *cli);
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
		LOGSCLI(cli, LOGL_INFO, "not reconnecting, disabled\n");
		return;
	}

	cli->state = STREAM_CLI_STATE_WAIT_RECONNECT;
	LOGSCLI(cli, LOGL_INFO, "retrying reconnect in %d seconds...\n",
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

static void osmo_stream_cli_close_iofd(struct osmo_stream_cli *cli)
{
	if (!cli->iofd)
		return;

	osmo_iofd_close(cli->iofd);
}

static void osmo_stream_cli_close_ofd(struct osmo_stream_cli *cli)
{
	if (cli->ofd.fd == -1)
		return;
	osmo_fd_unregister(&cli->ofd);
	close(cli->ofd.fd);
	cli->ofd.fd = -1;
}

/*! \brief Close an Osmocom Stream Client
 *  \param[in] cli Osmocom Stream Client to be closed
 *  We unregister the socket fd from the osmocom select() loop
 *  abstraction and close the socket */
void osmo_stream_cli_close(struct osmo_stream_cli *cli)
{
	int old_state = cli->state;

	if (cli->state == STREAM_CLI_STATE_CLOSED)
		return;
	if (cli->state == STREAM_CLI_STATE_WAIT_RECONNECT) {
		osmo_timer_del(&cli->timer);
		cli->state = STREAM_CLI_STATE_CLOSED;
		return;
	}


	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		osmo_stream_cli_close_ofd(cli);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_stream_cli_close_iofd(cli);
		break;
	default:
		OSMO_ASSERT(false);
	}

	cli->state = STREAM_CLI_STATE_CLOSED;

	if (old_state == STREAM_CLI_STATE_CONNECTED) {
		LOGSCLI(cli, LOGL_DEBUG, "connection closed\n");
		if (cli->disconnect_cb)
			cli->disconnect_cb(cli);
	}
}

static inline int osmo_stream_cli_fd(const struct osmo_stream_cli *cli)
{
	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		return cli->ofd.fd;
	case OSMO_STREAM_MODE_OSMO_IO:
		if (cli->iofd)
			return osmo_iofd_get_fd(cli->iofd);
	default:
		break;
	}
	return -EINVAL;
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
	int ret;

	if (llist_empty(&cli->tx_queue)) {
		osmo_fd_write_disable(&cli->ofd);
		return 0;
	}
	msg = llist_first_entry(&cli->tx_queue, struct msgb, list);
	llist_del(&msg->list);

	if (!osmo_stream_cli_is_connected(cli)) {
		LOGSCLI(cli, LOGL_ERROR, "send: not connected, dropping data!\n");
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

	if (ret >= 0 && ret < msgb_length(msg)) {
		LOGSCLI(cli, LOGL_ERROR, "short send: %d < exp %u\n", ret, msgb_length(msg));
		/* Update msgb and re-add it at the start of the queue: */
		msgb_pull(msg, ret);
		llist_add(&msg->list, &cli->tx_queue);
		return 0;
	}

	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN)
			osmo_stream_cli_reconnect(cli);
		LOGSCLI(cli, LOGL_ERROR, "received error %d in response to send\n", errno);
	}

	msgb_free(msg);

	if (llist_empty(&cli->tx_queue))
		osmo_fd_write_disable(&cli->ofd);

	return 0;
}

static int _setsockopt_nosigpipe(struct osmo_stream_cli *cli)
{
#ifdef SO_NOSIGPIPE
	int ret;
	int val = 1;
	ret = setsockopt(osmo_stream_cli_fd(cli), SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(val));
	if (ret < 0)
		LOGSCLI(cli, LOGL_DEBUG, "Failed setting SO_NOSIGPIPE: %s\n", strerror(errno));
	return ret;
#else
	return 0;
#endif
}

static void stream_cli_handle_connecting(struct osmo_stream_cli *cli, int res)
{
	int error, ret = res;
	socklen_t len = sizeof(error);

	int fd = osmo_stream_cli_fd(cli);
	OSMO_ASSERT(fd >= 0);

	if (ret < 0) {
		osmo_stream_cli_reconnect(cli);
		return;
	}
	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret >= 0 && error > 0) {
		osmo_stream_cli_reconnect(cli);
		return;
	}

	/* If messages got enqueued while 'connecting', keep WRITE flag
	   up to dispatch them upon next main loop step */
	if (cli->mode == OSMO_STREAM_MODE_OSMO_FD && llist_empty(&cli->tx_queue))
		osmo_fd_write_disable(&cli->ofd);

	/* Update sockname based on socket info: */
	osmo_sock_get_name_buf(cli->sockname, sizeof(cli->sockname), osmo_stream_cli_fd(cli));

	LOGSCLI(cli, LOGL_INFO, "connection established\n");
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
			stream_sctp_sock_activate_events(fd);
		}
		break;
	default:
		break;
	}
	if (cli->connect_cb)
		cli->connect_cb(cli);
}

static int osmo_stream_cli_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_cli *cli = ofd->data;

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		stream_cli_handle_connecting(cli, 0);
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
		/* Only CONNECTING and CONNECTED states are expected, since they are the only states
		 * where FD exists: */
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
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

	cli->mode = OSMO_STREAM_MODE_UNKNOWN;
	cli->sk_domain = AF_UNSPEC;
	cli->sk_type = SOCK_STREAM;
	cli->proto = IPPROTO_TCP;

	cli->state = STREAM_CLI_STATE_CLOSED;
	osmo_timer_setup(&cli->timer, cli_timer_cb, cli);
	cli->reconnect_timeout = 5;	/* default is 5 seconds. */
	INIT_LLIST_HEAD(&cli->tx_queue);

	return cli;
}

static void stream_cli_iofd_read_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_cli *cli  = osmo_iofd_get_data(iofd);

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		stream_cli_handle_connecting(cli, res);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (res == 0)
			osmo_stream_cli_reconnect(cli);
		else if (cli->iofd_read_cb)
			cli->iofd_read_cb(cli, msg);
		break;
	default:
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
	}
}

static void stream_cli_iofd_write_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_cli *cli = osmo_iofd_get_data(iofd);

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		stream_cli_handle_connecting(cli, res);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (msg && res <= 0) {
			osmo_stream_cli_reconnect(cli);
			LOGSCLI(cli, LOGL_ERROR, "received error %d in response to send\n", res);
		}
		break;
	default:
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
	}
}

static struct osmo_io_ops osmo_stream_cli_ioops = {
	.read_cb = stream_cli_iofd_read_cb,
	.write_cb = stream_cli_iofd_write_cb,

	.segmentation_cb = NULL,
};

/*! \brief Set a name on the cli object (used during logging)
 *  \param[in] cli stream_cli whose name is to be set
 *  \param[in] name the name to be set on cli
 */
void osmo_stream_cli_set_name(struct osmo_stream_cli *cli, const char *name)
{
	osmo_talloc_replace_string(cli, &cli->name, name);
	if (cli->mode == OSMO_STREAM_MODE_OSMO_IO && cli->iofd)
		osmo_iofd_set_name(cli->iofd, name);
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

	osmo_sock_get_name_buf(buf, OSMO_SOCK_NAME_MAXLEN, osmo_stream_cli_fd(cli));

	return buf;
}

/*! \brief Get Osmocom File Descriptor of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli)
{
	OSMO_ASSERT(cli->mode == OSMO_STREAM_MODE_OSMO_FD);
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
 *  This function will configure osmo_stream_cli to use osmo_ofd internally.
 *  \param[in] cli Stream Client to modify
 *  \param[in] read_cb Call-back function to be called when we want to read */
void
osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli,
			    int (*read_cb)(struct osmo_stream_cli *cli))
{
	OSMO_ASSERT(cli->mode != OSMO_STREAM_MODE_OSMO_IO);
	cli->mode = OSMO_STREAM_MODE_OSMO_FD;
	cli->read_cb = read_cb;
}

/*! \brief Set the call-back function called to read from the stream client socket
 *  This function will configure osmo_stream_cli to use osmo_iofd internally.
 *  \param[in] cli Stream Client to modify
 *  \param[in] read_cb Call-back function to be called when data was read from the socket */
void
osmo_stream_cli_set_read_cb2(struct osmo_stream_cli *cli,
			    int (*read_cb)(struct osmo_stream_cli *cli, struct msgb *msg))
{
	OSMO_ASSERT(cli->mode != OSMO_STREAM_MODE_OSMO_FD);
	cli->mode = OSMO_STREAM_MODE_OSMO_IO;
	cli->iofd_read_cb = read_cb;
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
	osmo_fd_setup(&cli->ofd, ret, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_cli_fd_cb, cli, 0);

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = stream_setsockopt_nodelay(cli->ofd.fd, cli->proto, 1);
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
	int ret, fd = -1;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && osmo_stream_cli_fd(cli) >= 0)
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

	fd = ret;

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = stream_setsockopt_nodelay(fd, cli->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		osmo_fd_setup(&cli->ofd, fd, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_cli_fd_cb, cli, 0);
		if (osmo_fd_register(&cli->ofd) < 0)
			goto error_close_socket;
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		if (!cli->iofd)
			cli->iofd = osmo_iofd_setup(cli, fd, cli->name, OSMO_IO_FD_MODE_READ_WRITE, &osmo_stream_cli_ioops, cli);
		if (!cli->iofd)
			goto error_close_socket;

		if (osmo_iofd_register(cli->iofd, fd) < 0)
			goto error_close_socket;
		osmo_iofd_notify_connected(cli->iofd);
		break;
	default:
		OSMO_ASSERT(false);
	}

	cli->state = STREAM_CLI_STATE_CONNECTING;
	return 0;

error_close_socket:
	cli->state = STREAM_CLI_STATE_CLOSED;
	close(fd);
	if (cli->mode == OSMO_STREAM_MODE_OSMO_FD)
		cli->ofd.fd = -1;
	return -EIO;
}

static void cli_timer_cb(void *data)
{
	struct osmo_stream_cli *cli = data;

	LOGSCLI(cli, LOGL_DEBUG, "reconnecting\n");
	osmo_stream_cli_open(cli);
}

/*! \brief Enqueue data to be sent via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg)
{
	OSMO_ASSERT(cli);
	OSMO_ASSERT(msg);

	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		msgb_enqueue(&cli->tx_queue, msg);
		osmo_fd_write_enable(&cli->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_write_msgb(cli->iofd, msg);
		break;
	default:
		OSMO_ASSERT(false);
	}
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
		if (errno == EPIPE || errno == ECONNRESET)
			LOGSCLI(cli, LOGL_ERROR, "lost connection with srv\n");
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
	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		msgb_queue_free(&cli->tx_queue);
		/* If in state 'connecting', keep WRITE flag up to receive
		* socket connection signal and then transition to STATE_CONNECTED: */
		if (cli->state == STREAM_CLI_STATE_CONNECTED)
			osmo_fd_write_disable(&cli->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_txqueue_clear(cli->iofd);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/*! @} */
