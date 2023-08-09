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


/*! \addtogroup stream Osmocom Stream Socket (server side)
 *  @{
 *
 *  This code is intended to abstract any use of stream-type sockets,
 *  such as TCP and SCTP.  It offers server side implementation,
 *  fully integrated with the libosmocore select loop abstraction.
 */

/*! \file stream_srv.c
 *  \brief Osmocom stream socket helpers (server side)
 */

#define LOGSLNK(link, level, fmt, args...) \
	LOGP(DLINP, level, "SRV(%s,%s) " fmt, \
	     link->name ? : "", \
	     link->sockname, \
	      ## args)

#define LOGSSRV(srv, level, fmt, args...) \
	LOGP(DLINP, level, "SRVCONN(%s,%s) " fmt, \
	     srv->name ? : "", \
	     srv->sockname, \
	      ## args)
/*
 * Server side.
 */

#define OSMO_STREAM_SRV_F_RECONF	(1 << 0)
#define OSMO_STREAM_SRV_F_NODELAY	(1 << 1)

struct osmo_stream_srv_link {
	struct osmo_fd		ofd;
	char			*name;
	char			sockname[OSMO_SOCK_NAME_MAXLEN];
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

static int _setsockopt_nosigpipe(struct osmo_stream_srv_link *link, int new_fd)
{
#ifdef SO_NOSIGPIPE
	int ret;
	int val = 1;
	ret = setsockopt(new_fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(val));
	if (ret < 0)
		LOGSLNK(link, LOGL_ERROR, "Failed setting SO_NOSIGPIPE: %s\n", strerror(errno));
	return ret;
#else
	return 0;
#endif
}

static int osmo_stream_srv_link_ofd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int ret;
	int sock_fd;
	struct osmo_sockaddr osa;
	socklen_t sa_len = sizeof(osa.u.sas);
	struct osmo_stream_srv_link *link = ofd->data;

	ret = accept(ofd->fd, &osa.u.sa, &sa_len);
	if (ret < 0) {
		LOGSLNK(link, LOGL_ERROR, "failed to accept from origin peer, reason=`%s'\n",
			strerror(errno));
		return ret;
	}
	sock_fd = ret;

	switch (osa.u.sa.sa_family) {
	case AF_UNIX:
		LOGSLNK(link, LOGL_INFO, "accept()ed new link on fd %d\n",
			sock_fd);
		_setsockopt_nosigpipe(link, sock_fd);
		break;
	case AF_INET6:
	case AF_INET:
		LOGSLNK(link, LOGL_INFO, "accept()ed new link from %s\n",
			osmo_sockaddr_to_str(&osa));

		if (link->proto == IPPROTO_SCTP) {
			_setsockopt_nosigpipe(link, sock_fd);
			ret = stream_sctp_sock_activate_events(sock_fd);
			if (ret < 0)
				goto error_close_socket;
		}
		break;
	default:
		LOGSLNK(link, LOGL_ERROR, "accept()ed unexpected address family %d\n",
			osa.u.sa.sa_family);
		goto error_close_socket;
	}

	if (link->flags & OSMO_STREAM_SRV_F_NODELAY) {
		ret = stream_setsockopt_nodelay(sock_fd, link->proto, 1);
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
	osmo_fd_setup(&link->ofd, -1, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_srv_link_ofd_cb, link, 0);

	return link;
}

/*! \brief Set a name on the srv_link object (used during logging)
 *  \param[in] link server link whose name is to be set
 *  \param[in] name the name to be set on link
 */
void osmo_stream_srv_link_set_name(struct osmo_stream_srv_link *link, const char *name)
{
	osmo_talloc_replace_string(link, &link->name, name);
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
							NULL, 0, 0, OSMO_SOCK_F_BIND|OSMO_SOCK_F_SCTP_ASCONF_SUPPORTED);
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

	OSMO_STRLCPY_ARRAY(link->sockname, osmo_stream_srv_link_get_sockname(link));
	return 0;
}

/*! \brief Check whether the stream server link is opened
 *  \param[in] link Stream Server Link to check */
bool osmo_stream_srv_link_is_opened(const struct osmo_stream_srv_link *link)
{
	if (!link)
		return false;

	if (link->ofd.fd == -1)
		return false;

	return true;
}

/*! \brief Close the stream server link and unregister from select loop
 *  Does not destroy the server link, merely closes it!
 *  \param[in] link Stream Server Link to close */
void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link)
{
	if (!osmo_stream_srv_link_is_opened(link))
		return;

	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
	link->ofd.fd = -1;
}

#define OSMO_STREAM_SRV_F_FLUSH_DESTROY	(1 << 0)

struct osmo_stream_srv {
	struct osmo_stream_srv_link	*srv;
	char				*name;
	char				sockname[OSMO_SOCK_NAME_MAXLEN];
	enum osmo_stream_mode mode;
	union {
		struct osmo_fd			ofd;
		struct osmo_io_fd		*iofd;
	};
	struct llist_head		tx_queue;
	int (*closed_cb)(struct osmo_stream_srv *peer);
	int (*read_cb)(struct osmo_stream_srv *peer);
	int (*iofd_read_cb)(struct osmo_stream_srv *peer, struct msgb *msg);
	void				*data;
	int				flags;
};

static void stream_srv_iofd_read_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);
	LOGSSRV(conn, LOGL_DEBUG, "message received (res=%d)\n", res);

	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGSSRV(conn, LOGL_INFO, "Connection is being flushed and closed; ignoring received message\n");
		msgb_free(msg);
		return;
	}

	if (res <= 0) {
		osmo_stream_srv_set_flush_and_destroy(conn);
		if (osmo_iofd_txqueue_len(iofd) == 0)
			osmo_stream_srv_destroy(conn);
	} else if (conn->iofd_read_cb) {
		conn->iofd_read_cb(conn, msg);
	}
}

static void stream_srv_iofd_write_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);
	LOGSSRV(conn, LOGL_DEBUG, "connected write\n");

	if (res == -1)
		LOGSSRV(conn, LOGL_ERROR, "error to send: %s\n", strerror(errno));

	if (osmo_iofd_txqueue_len(iofd) == 0)
		if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)
			osmo_stream_srv_destroy(conn);
}

static struct osmo_io_ops srv_ioops = {
	.read_cb = stream_srv_iofd_read_cb,
	.write_cb = stream_srv_iofd_write_cb,
};
static int osmo_stream_srv_read(struct osmo_stream_srv *conn)
{
	int rc = 0;

	LOGSSRV(conn, LOGL_DEBUG, "message received\n");

	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGSSRV(conn, LOGL_INFO, "Connection is being flushed and closed; ignoring received message\n");
		return 0;
	}

	if (conn->read_cb)
		rc = conn->read_cb(conn);

	return rc;
}

static void osmo_stream_srv_write(struct osmo_stream_srv *conn)
{
#ifdef HAVE_LIBSCTP
	struct sctp_sndrcvinfo sinfo;
#endif
	struct msgb *msg;
	int ret;

	if (llist_empty(&conn->tx_queue)) {
		osmo_fd_write_disable(&conn->ofd);
		return;
	}
	msg = llist_first_entry(&conn->tx_queue, struct msgb, list);
	llist_del(&msg->list);

	LOGSSRV(conn, LOGL_DEBUG, "sending %u bytes of data\n", msg->len);

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

	if (ret >= 0 && ret < msgb_length(msg)) {
		LOGSSRV(conn, LOGL_ERROR, "short send: %d < exp %u\n", ret, msgb_length(msg));
		/* Update msgb and re-add it at the start of the queue: */
		msgb_pull(msg, ret);
		llist_add(&msg->list, &conn->tx_queue);
		return;
	}

	if (ret == -1) {/* send(): On error -1 is returned, and errno is set appropriately */
		int err = errno;
		LOGSSRV(conn, LOGL_ERROR, "send(len=%u) error: %s\n", msgb_length(msg), strerror(err));
		if (err == EAGAIN) {
			/* Re-add at the start of the queue to re-attempt: */
			llist_add(&msg->list, &conn->tx_queue);
			return;
		}
		msgb_free(msg);
		osmo_stream_srv_destroy(conn);
		return;
	}

	msgb_free(msg);

	if (llist_empty(&conn->tx_queue)) {
		osmo_fd_write_disable(&conn->ofd);
		if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)
			osmo_stream_srv_destroy(conn);
	}
}

static int osmo_stream_srv_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_srv *conn = ofd->data;
	int rc = 0;

	LOGSSRV(conn, LOGL_DEBUG, "connected read/write (what=0x%x)\n", what);
	if (what & OSMO_FD_READ)
		rc = osmo_stream_srv_read(conn);
	if (rc != -EBADF && (what & OSMO_FD_WRITE))
		osmo_stream_srv_write(conn);

	return rc;
}

/*! \brief Create a Stream Server inside the specified link
 *  \param[in] ctx talloc allocation context from which to allocate
 *  \param[in] link Stream Server Link to which we belong
 *  \param[in] fd system file descriptor of the new connection
 *  \param[in] read_cb Call-back to call when the socket is readable
 *  \param[in] closed_cb Call-back to call when the connection is closed
 *  \param[in] data User data to save in the new Stream Server struct
 *  \returns Stream Server in case of success; NULL on error */
struct osmo_stream_srv *
osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link,
	int fd,
	int (*read_cb)(struct osmo_stream_srv *conn),
	int (*closed_cb)(struct osmo_stream_srv *conn), void *data)
{
	struct osmo_stream_srv *conn;

	OSMO_ASSERT(link);

	conn = talloc_zero(ctx, struct osmo_stream_srv);
	if (conn == NULL)
		return NULL;

	conn->mode = OSMO_STREAM_MODE_OSMO_FD;
	conn->srv = link;
	osmo_fd_setup(&conn->ofd, fd, OSMO_FD_READ, osmo_stream_srv_cb, conn, 0);
	conn->read_cb = read_cb;
	conn->closed_cb = closed_cb;
	conn->data = data;
	INIT_LLIST_HEAD(&conn->tx_queue);

	osmo_sock_get_name_buf(conn->sockname, sizeof(conn->sockname), fd);

	if (osmo_fd_register(&conn->ofd) < 0) {
		LOGSSRV(conn, LOGL_ERROR, "could not register FD\n");
		talloc_free(conn);
		return NULL;
	}
	return conn;
}

/*! \brief Create a Stream Server inside the specified link
 *  \param[in] ctx talloc allocation context from which to allocate
 *  \param[in] link Stream Server Link to which we belong
 *  \param[in] fd system file descriptor of the new connection
 *  \param[in] data User data to save in the new Stream Server struct
 *  \returns Stream Server in case of success; NULL on error */
struct osmo_stream_srv *
osmo_stream_srv_create2(void *ctx, struct osmo_stream_srv_link *link, int fd, void *data)
{
	struct osmo_stream_srv *conn;

	OSMO_ASSERT(link);

	conn = talloc_zero(ctx, struct osmo_stream_srv);
	if (conn == NULL)
		return NULL;

	conn->mode = OSMO_STREAM_MODE_OSMO_IO;
	conn->srv = link;

	osmo_sock_get_name_buf(conn->sockname, sizeof(conn->sockname), fd);

	conn->iofd = osmo_iofd_setup(conn, fd, conn->sockname,
				     OSMO_IO_FD_MODE_READ_WRITE, &srv_ioops, conn);
	if (!conn->iofd) {
		talloc_free(conn);
		return NULL;
	}
	conn->data = data;
	osmo_iofd_set_txqueue_max_length(conn->iofd, 1024);

	if (osmo_iofd_register(conn->iofd, fd) < 0) {
		LOGSSRV(conn, LOGL_ERROR, "could not register FD %d\n", fd);
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

/*! \brief Set a name on the srv object (used during logging)
 *  \param[in] conn server whose name is to be set
 *  \param[in] name the name to be set on conn
 */
void osmo_stream_srv_set_name(struct osmo_stream_srv *conn, const char *name)
{
	osmo_talloc_replace_string(conn, &conn->name, name);
	if (conn->mode == OSMO_STREAM_MODE_OSMO_IO && conn->iofd)
		osmo_iofd_set_name(conn->iofd, name);
}

/*! \brief Set the call-back function when data was read from the stream server socket
 *  Only for osmo_stream_srv created with osmo_stream_srv_create2()
 *  \param[in] conn Stream Server to modify
 *  \param[in] read_cb Call-back function to be called when data was read */
void osmo_stream_srv_set_read_cb(struct osmo_stream_srv *conn, int (*read_cb)(struct osmo_stream_srv *conn, struct msgb *msg))
{
	OSMO_ASSERT(conn && conn->mode == OSMO_STREAM_MODE_OSMO_IO);
	conn->iofd_read_cb = read_cb;
}

/*! \brief Set the call-back function called when the stream server socket was closed
 *  \param[in] conn Stream Server to modify
 *  \param[in] closed_cb Call-back function to be called when the connection was closed */
void osmo_stream_srv_set_closed_cb(struct osmo_stream_srv *conn, int (*closed_cb)(struct osmo_stream_srv *conn))
{
	OSMO_ASSERT(conn);
	conn->closed_cb = closed_cb;
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

/*! \brief Set the segmentation callback for target osmo_stream_srv structure.
 * The connection has to have been established prior to calling this function.
 *  \param[in,out] conn Target Stream Server to modify
 *  \param[in] segmentation_cb Segmentation callback to be set */
void osmo_stream_srv_set_segmentation_cb(struct osmo_stream_srv *conn,
					int (*segmentation_cb)(struct msgb *msg))
{
	/* Note that the following implies that iofd != NULL, since
	 * osmo_stream_srv_create2() creates the iofd member, too */
	OSMO_ASSERT(conn->mode == OSMO_STREAM_MODE_OSMO_IO);
	/* Copy default settings */
	struct osmo_io_ops conn_ops = srv_ioops;
	/* Set segmentation cb for this connection */
	conn_ops.segmentation_cb = segmentation_cb;
	osmo_iofd_set_ioops(conn->iofd, &conn_ops);
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
	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		osmo_fd_unregister(&conn->ofd);
		close(conn->ofd.fd);
		msgb_queue_free(&conn->tx_queue);
		conn->ofd.fd = -1;
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_free(conn->iofd);
		break;
	default:
		OSMO_ASSERT(false);
	}
	if (conn->closed_cb)
		conn->closed_cb(conn);
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
		LOGSSRV(conn, LOGL_DEBUG, "Connection is being flushed and closed; ignoring new outgoing message\n");
		msgb_free(msg);
		return;
	}

	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		msgb_enqueue(&conn->tx_queue, msg);
		osmo_fd_write_enable(&conn->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_write_msgb(conn->iofd, msg);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

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
		ret = recv(conn->ofd.fd, msg->tail, msgb_tailroom(msg), 0);
		break;
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		switch (conn->srv->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
		{
			char log_pfx[128];
			snprintf(log_pfx, sizeof(log_pfx), "SRV(%s,%s)", conn->name ? : "", conn->sockname);
			ret = stream_sctp_recvmsg_wrapper(conn->ofd.fd, msg, log_pfx);
			break;
		}
#endif
		case IPPROTO_TCP:
		default:
			ret = recv(conn->ofd.fd, msg->tail, msgb_tailroom(msg), 0);
			break;
		}
		break;
	default:
		ret = -ENOTSUP;
	}

	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET)
			LOGSSRV(conn, LOGL_ERROR, "lost connection with client\n");
		return ret;
	} else if (ret == 0) {
		LOGSSRV(conn, LOGL_ERROR, "connection closed with client\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGSSRV(conn, LOGL_DEBUG, "received %d bytes from client\n", ret);
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
