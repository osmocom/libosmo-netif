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

/*
 * Platforms that don't have MSG_NOSIGNAL (which disables SIGPIPE)
 * usually have SO_NOSIGPIPE (set via setsockopt).
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

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
	event.sctp_address_event = 1;
	event.sctp_send_failure_event = 1;
	event.sctp_peer_error_event = 1;
	event.sctp_shutdown_event = 1;
	/* IMPORTANT: Do NOT enable sender_dry_event here, see
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1442784 */
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			&event, sizeof(event));

	if (rc < 0)
		LOGP(DLINP, LOGL_ERROR, "couldn't activate SCTP events "
		     "on FD %u\n", fd);
	return rc;
#else
	return -1;
#endif
}

static int setsockopt_nodelay(int fd, int proto, int on)
{
	int rc;

	switch (proto) {
	case IPPROTO_SCTP:
		rc = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &on, sizeof(on));
		break;
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
        STREAM_CLI_STATE_NONE         = 0,
        STREAM_CLI_STATE_CONNECTING   = 1,
        STREAM_CLI_STATE_CONNECTED    = 2,
        STREAM_CLI_STATE_MAX
};

static const struct value_string stream_cli_state_names[] = {
	{ STREAM_CLI_STATE_NONE,       "      NONE" },
	{ STREAM_CLI_STATE_CONNECTING, "CONNECTING" },
	{ STREAM_CLI_STATE_CONNECTED,  " CONNECTED" },
	{ 0, NULL }
};

#define OSMO_STREAM_CLI_F_RECONF	(1 << 0)
#define OSMO_STREAM_CLI_F_NODELAY	(1 << 1)

struct osmo_stream_cli {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum osmo_stream_cli_state	state;
	char				*addr;
	uint16_t			port;
	char				*local_addr;
	uint16_t			local_port;
	uint16_t			proto;
	int (*connect_cb)(struct osmo_stream_cli *srv);
	int (*read_cb)(struct osmo_stream_cli *srv);
	int (*write_cb)(struct osmo_stream_cli *srv);
	void				*data;
	int				flags;
	int				reconnect_timeout;
};

void osmo_stream_cli_close(struct osmo_stream_cli *cli);

/*! \brief Re-connect an Osmocom Stream Client
 *  If re-connection is enabled for this client, we close any existing
 *  connection (if any) and schedule a re-connect timer */
void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli)
{
	osmo_stream_cli_close(cli);

	if (cli->reconnect_timeout < 0) {
		LOGSCLI(cli, LOGL_DEBUG, "not reconnecting, disabled.\n");
		return;
	}

	LOGSCLI(cli, LOGL_DEBUG, "retrying in %d seconds...\n",
		cli->reconnect_timeout);
	osmo_timer_schedule(&cli->timer, cli->reconnect_timeout, 0);
	cli->state = STREAM_CLI_STATE_CONNECTING;
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

	if (cli->state == STREAM_CLI_STATE_CONNECTED)
		LOGSCLI(cli, LOGL_DEBUG, "connection closed\n");

	cli->state = STREAM_CLI_STATE_NONE;
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

	LOGSCLI(cli, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&cli->tx_queue)) {
		cli->ofd.when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = cli->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	if (cli->state == STREAM_CLI_STATE_CONNECTING) {
		LOGSCLI(cli, LOGL_ERROR, "not connected, dropping data!\n");
		return 0;
	}

	switch (cli->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.sinfo_ppid = htonl(msgb_sctp_ppid(msg));
		sinfo.sinfo_stream = msgb_sctp_stream(msg);
		ret = sctp_send(cli->ofd.fd, msg->data, msgb_length(msg),
				&sinfo, MSG_NOSIGNAL);
		break;
#endif
	case IPPROTO_TCP:
	default:
		ret = send(cli->ofd.fd, msg->data, msg->len, 0);
		break;
	}
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			osmo_stream_cli_reconnect(cli);
		}
		LOGSCLI(cli, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
	return 0;
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
		ofd->when &= ~BSC_FD_WRITE;
		LOGSCLI(cli, LOGL_DEBUG, "connection done.\n");
		cli->state = STREAM_CLI_STATE_CONNECTED;
		if (cli->proto == IPPROTO_SCTP) {
#ifdef SO_NOSIGPIPE
			int val = 1;

			ret = setsockopt(ofd->fd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&val, sizeof(val));
			if (ret < 0)
				LOGSCLI(cli, LOGL_DEBUG, "Failed setting SO_NOSIGPIPE: %s\n", strerror(errno));
#endif
			sctp_sock_activate_events(ofd->fd);
		}
		if (cli->connect_cb)
			cli->connect_cb(cli);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (what & BSC_FD_READ) {
			LOGSCLI(cli, LOGL_DEBUG, "connected read\n");
			osmo_stream_cli_read(cli);
		}
		if (what & BSC_FD_WRITE) {
			LOGSCLI(cli, LOGL_DEBUG, "connected write\n");
			osmo_stream_cli_write(cli);
		}
		break;
	default:
		break;
	}
        return 0;
}

static void cli_timer_cb(void *data);

/*! \brief Create an Osmocom stream client
 *  \param[in] ctx talloc context from which to allocate memory
 *  This function allocates a new \ref osmo_stream_cli and initializes
 *  it with default values (5s reconnect timer, TCP protocol) */
struct osmo_stream_cli *osmo_stream_cli_create(void *ctx)
{
	struct osmo_stream_cli *cli;

	cli = talloc_zero(ctx, struct osmo_stream_cli);
	if (!cli)
		return NULL;

	cli->proto = IPPROTO_TCP;
	cli->ofd.fd = -1;
	cli->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
	cli->ofd.priv_nr = 0;	/* XXX */
	cli->ofd.cb = osmo_stream_cli_fd_cb;
	cli->ofd.data = cli;
	cli->state = STREAM_CLI_STATE_CONNECTING;
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
	osmo_talloc_replace_string(cli, &cli->addr, addr);
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
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
	osmo_talloc_replace_string(cli, &cli->local_addr, addr);
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
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

/*! \brief Set the reconnect time of the stream client socket
 *  \param[in] cli Stream Client to modify
 *  \param[in] timeout Re-connect timeout in seconds */
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

/*! \brief Open connection of an Osmocom stream client
 *  \param[in] cli Stream Client to connect
 *  \param[in] reconect 1 if we should not automatically reconnect
 */
int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && cli->ofd.fd >= 0)
		osmo_stream_cli_close(cli);

	cli->flags &= ~OSMO_STREAM_CLI_F_RECONF;

	ret = osmo_sock_init2(AF_INET, SOCK_STREAM, cli->proto,
			      cli->local_addr, cli->local_port,
			      cli->addr, cli->port,
			      OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0) {
		if (reconnect)
			osmo_stream_cli_reconnect(cli);
		return ret;
	}
	cli->ofd.fd = ret;

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = setsockopt_nodelay(cli->ofd.fd, cli->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	if (osmo_fd_register(&cli->ofd) < 0)
		goto error_close_socket;

	return 0;

error_close_socket:
	close(ret);
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
 *  \param[in] cli Stream Client to connect */
int osmo_stream_cli_open(struct osmo_stream_cli *cli)
{
	return osmo_stream_cli_open2(cli, 0);
}

static void cli_timer_cb(void *data)
{
	struct osmo_stream_cli *cli = data;

	LOGSCLI(cli, LOGL_DEBUG, "reconnecting.\n");

	switch(cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		cli->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
		osmo_stream_cli_open2(cli, 1);
	        break;
	default:
		break;
	}
}

/*! \brief Enqueue data to be sent via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg)
{
	msgb_enqueue(&cli->tx_queue, msg);
	cli->ofd.when |= BSC_FD_WRITE;
}

/*! \brief Receive data via an Osmocom stream client
 *  \param[in] cli Stream Client through which we want to send
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read; <=0 in case of error */
int osmo_stream_cli_recv(struct osmo_stream_cli *cli, struct msgb *msg)
{
	int ret;

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

/*
 * Server side.
 */

#define OSMO_STREAM_SRV_F_RECONF	(1 << 0)
#define OSMO_STREAM_SRV_F_NODELAY	(1 << 1)

struct osmo_stream_srv_link {
        struct osmo_fd                  ofd;
        char                            *addr;
        uint16_t                        port;
        uint16_t                        proto;
        int (*accept_cb)(struct osmo_stream_srv_link *srv, int fd);
        void                            *data;
	int				flags;
};

static int osmo_stream_srv_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int ret;
	int sock_fd;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	struct osmo_stream_srv_link *link = ofd->data;

	ret = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to accept from origin "
			"peer, reason=`%s'\n", strerror(errno));
		return ret;
	}
	LOGP(DLINP, LOGL_DEBUG, "accept()ed new link from %s to port %u\n",
		inet_ntoa(sa.sin_addr), link->port);
	sock_fd = ret;

	if (link->proto == IPPROTO_SCTP) {
		ret = sctp_sock_activate_events(sock_fd);
		if (ret < 0)
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

	link->proto = IPPROTO_TCP;
	link->ofd.fd = -1;
	link->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
	link->ofd.cb = osmo_stream_srv_fd_cb;
	link->ofd.data = link;

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
	osmo_talloc_replace_string(link, &link->addr, addr);
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
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
 *  \param[in] link Stream Server Link to open */
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

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, link->proto,
			     link->addr, link->port, OSMO_SOCK_F_BIND);
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
        struct osmo_fd                  ofd;
        struct llist_head               tx_queue;
        int (*closed_cb)(struct osmo_stream_srv *peer);
        int (*cb)(struct osmo_stream_srv *peer);
        void                            *data;
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

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&conn->tx_queue)) {
		conn->ofd.when &= ~BSC_FD_WRITE;
		return;
	}
	lh = conn->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	switch (conn->srv->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.sinfo_ppid = htonl(msgb_sctp_ppid(msg));
		sinfo.sinfo_stream = msgb_sctp_stream(msg);
		ret = sctp_send(conn->ofd.fd, msg->data, msgb_length(msg),
				&sinfo, MSG_NOSIGNAL);
		break;
#endif
	case IPPROTO_TCP:
	default:
		ret = send(conn->ofd.fd, msg->data, msg->len, 0);
		break;
	}
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);

	if (llist_empty(&conn->tx_queue) && (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY))
		osmo_stream_srv_destroy(conn);
}

static int osmo_stream_srv_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_srv *conn = ofd->data;
	int rc = 0;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write\n");
	if (what & BSC_FD_READ)
		rc = osmo_stream_srv_read(conn);
	if (rc != -EBADF && (what & BSC_FD_WRITE))
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

	conn = talloc_zero(ctx, struct osmo_stream_srv);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate new peer in srv, "
			"reason=`%s'\n", strerror(errno));
		return NULL;
	}
	conn->srv = link;
	conn->ofd.fd = fd;
	conn->ofd.data = conn;
	conn->ofd.cb = osmo_stream_srv_cb;
	conn->ofd.when = BSC_FD_READ;
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
	close(conn->ofd.fd);
	osmo_fd_unregister(&conn->ofd);
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
	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGP(DLINP, LOGL_DEBUG, "Connection is being flushed and closed; ignoring new outgoing message\n");
		return;
	}

	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

/*! \brief Receive data via Osmocom stream server
 *  \param[in] conn Stream Server from which to receive
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read, negative on error.
 */
int osmo_stream_srv_recv(struct osmo_stream_srv *conn, struct msgb *msg)
{
#ifdef HAVE_LIBSCTP
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
#endif
	int ret;

	if (!msg)
		return -EINVAL;

	switch (conn->srv->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		ret = sctp_recvmsg(conn->ofd.fd, msgb_data(msg), msgb_tailroom(msg),
				NULL, NULL, &sinfo, &flags);
		if (flags & MSG_NOTIFICATION) {
			union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
			LOGP(DLINP, LOGL_DEBUG, "NOTIFICATION %u flags=0x%x\n", notif->sn_header.sn_type, notif->sn_header.sn_flags);
			switch (notif->sn_header.sn_type) {
			case SCTP_ASSOC_CHANGE:
				LOGP(DLINP, LOGL_DEBUG, "===> ASSOC CHANGE:");
				switch (notif->sn_assoc_change.sac_state) {
				case SCTP_COMM_UP:
					LOGPC(DLINP, LOGL_DEBUG, " UP\n");
					break;
				case SCTP_COMM_LOST:
					LOGPC(DLINP, LOGL_DEBUG, " LOST\n");
					break;
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
			case SCTP_PEER_ADDR_CHANGE:
				LOGP(DLINP, LOGL_DEBUG, "===> PEER ADDR CHANGE\n");
				break;
			case SCTP_SHUTDOWN_EVENT:
				LOGP(DLINP, LOGL_DEBUG, "===> SHUTDOWN EVT\n");
				/* Handle this like a regular disconnect */
				return 0;
				break;
			}
			return -EAGAIN;
		}
		msgb_sctp_ppid(msg) = ntohl(sinfo.sinfo_ppid);
		msgb_sctp_stream(msg) = sinfo.sinfo_stream;
		break;
#endif
	case IPPROTO_TCP:
	default:
		ret = recv(conn->ofd.fd, msgb_data(msg), msgb_tailroom(msg), 0);
		break;
	}

	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR,
				"lost connection with srv\n");
		}
		return ret;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with srv\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from client\n", ret);
	return ret;
}

/*! @} */
