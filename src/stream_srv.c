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
#include <sys/un.h>
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

/*! \file stream_srv.c */

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

struct msgb_alloc_info {
		/*! Whether it was set by user or we use iofd defaults */
		bool set_by_user;
		/*! size of msgb to allocate (excluding headroom) */
		unsigned int size;
		/*! headroom to allocate when allocating msgb's */
		unsigned int headroom;
};

#define OSMO_STREAM_SRV_F_RECONF	(1 << 0)
#define OSMO_STREAM_SRV_F_NODELAY	(1 << 1)

struct osmo_stream_srv_link {
	struct osmo_fd		ofd;
	char			*name;
	char			sockname[OSMO_SOCK_MULTIADDR_PEER_STR_MAXLEN];
	char			*addr[OSMO_STREAM_MAX_ADDRS];
	uint8_t			addrcnt;
	uint16_t		port;
	int			sk_domain;
	int			sk_type;
	int			sk_prio; /* socket priority, SO_PRIORITY, default=0=unset */
	uint16_t		proto;
	uint8_t			ip_dscp; /* IP Differentiated services, 0..63, default=0=unset */
	osmo_stream_srv_link_accept_cb_t accept_cb;
	void			*data;
	int			flags;
	unsigned int		tx_queue_max_length; /* Max amount of msgbs which can be enqueued */
	struct msgb_alloc_info	msgb_alloc;
	struct osmo_sock_init2_multiaddr_pars ma_pars;
	struct stream_tcp_pars tcp_pars;
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

		switch (link->proto) {
		case IPPROTO_TCP:
			ret = stream_tcp_keepalive_pars_apply(sock_fd, &link->tcp_pars.ka);
			if (ret < 0) {
				LOGSLNK(link, LOGL_ERROR, "failed applying TCP keep-alive pars on fd %d\n", sock_fd);
				goto error_close_socket;
			}
			/* tcp_pars.user_timeout (sockopt TCP_USER_TIMEOUT) is
			 * inherited by accept() connected sockets automatically,
			 * no need to re-apply it here. */
			break;
		case IPPROTO_SCTP:
			_setsockopt_nosigpipe(link, sock_fd);
			ret = stream_sctp_sock_activate_events(sock_fd);
			if (ret < 0)
				goto error_close_socket;
			break;
		default:
			break;
		}
		break;
	default:
		LOGSLNK(link, LOGL_ERROR, "accept()ed unexpected address family %d\n",
			osa.u.sa.sa_family);
		goto error_close_socket;
	}

	if (link->flags & OSMO_STREAM_SRV_F_NODELAY) {
		ret = stream_setsockopt_nodelay(sock_fd, link->proto, 1);
		if (ret < 0) {
			LOGSLNK(link, LOGL_ERROR, "stream_setsockopt_nodelay: failed setsockopt err=%d\n",
				errno);
			goto error_close_socket;
		}
	}

	if (link->ip_dscp > 0) {
		ret = osmo_sock_set_dscp(sock_fd, link->ip_dscp);
		if (ret < 0) {
			LOGSLNK(link, LOGL_ERROR, "set_ip_dscp(%u): failed setsockopt err=%d\n",
				link->ip_dscp, errno);
			goto error_close_socket;
		}
	}

	if (link->sk_prio > 0) {
		ret = osmo_sock_set_priority(sock_fd, link->sk_prio);
		if (ret < 0) {
			LOGSLNK(link, LOGL_ERROR, "set_priority(%d): failed setsockopt err=%d\n",
				link->sk_prio, errno);
			goto error_close_socket;
		}
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

/*! \addtogroup stream_srv
 *  @{
 */

/*! Create an Osmocom Stream Server Link.
 *  A Stream Server Link is the listen()+accept() "parent" to individual connections from remote clients.
 *  \param[in] ctx talloc allocation context
 *  \returns Stream Server Link with default values (AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP)
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
	link->tx_queue_max_length = 1024; /* Default tx queue size, msgbs. */
	osmo_fd_setup(&link->ofd, -1, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_srv_link_ofd_cb, link, 0);

	link->ma_pars.sctp.version = 0;

	return link;
}

/*! Set a name on the srv_link object (used during logging).
 *  \param[in] link server link whose name is to be set.  The name is copied into the osmo_stream_srv_link, so
 *  the caller memory is not required to be valid beyond the call of this function.
 *  \param[in] name the name to be set on link
 */
void osmo_stream_srv_link_set_name(struct osmo_stream_srv_link *link, const char *name)
{
	osmo_talloc_replace_string(link, &link->name, name);
}

/*! Retrieve name previously set on the srv_link object (see osmo_stream_srv_link_set_name()).
 *  \param[in] link server link whose name is to be retrieved
 *  \returns The name to be set on link; NULL if never set
 */
const char *osmo_stream_srv_link_get_name(const struct osmo_stream_srv_link *link)
{
	return link->name;
}

/*! Set the NODELAY socket option to avoid Nagle-like behavior.
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

/*! Set the priority value of the stream socket.
 *  Setting this will automatically set the socket priority
 *  option on any socket established via this server link, before
 *  calling the accept_cb().
 *  \param[in] link server link whose sockets are to be configured
 *  \param[in] sk_prio priority value. Values outside 0..6 require CAP_NET_ADMIN.
 *  \return negative on error, 0 on success
 */
int osmo_stream_srv_link_set_priority(struct osmo_stream_srv_link *link, int sk_prio)
{
	link->sk_prio = sk_prio;
	return 0;
}

/*! Set the DSCP (differentiated services code point) of the stream socket.
 *  Setting this  will automatically set the IP DSCP option on any socket on any
 *  socket established via this server link, before calling the accept_cb().
 *  \param[in] link server link whose sockets are to be configured
 *  \param[in] ip_dscp DSCP value. Value range 0..63.
 *  \return negative on error, 0 on success
 */
int osmo_stream_srv_link_set_ip_dscp(struct osmo_stream_srv_link *link, uint8_t ip_dscp)
{
	link->ip_dscp = ip_dscp;
	return 0;
}

/*! Set the local address to which we bind.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] link Stream Server Link to modify
 *  \param[in] addr Local IP address
 */
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link,
				      const char *addr)
{
	osmo_stream_srv_link_set_addrs(link, &addr, 1);
}

/*! Set the local address set to which we bind.
 *  Useful for protocols allowing bind on more than one address (such as SCTP)
 *  Any changes to this setting will only become active upon next (re)connect.
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

/*! Set the local port number to which we bind.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] link Stream Server Link to modify
 *  \param[in] port Local port number
 */
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link,
				      uint16_t port)
{
	link->port = port;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}

/*! Set the protocol for the stream server link.
 *  Any changes to this setting will only become active upon next (re)connect.
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


/*! Set the socket type for the stream server link.
 *  Any changes to this setting will only become active upon next (re)connect.
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

/*! Set the socket domain for the stream server link.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] link Stream Server Link to modify
 *  \param[in] domain Socket Domain (like AF_UNSPEC (default for IP), AF_UNIX, AF_INET, ...)
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

/*! Set application private data of the stream server link.
 *  \param[in] link Stream Server Link to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link,
				 void *data)
{
	link->data = data;
}

/*! Retrieve application private data of the stream server link.
 *  \param[in] link Stream Server Link to modify
 *  \returns Application private data, as set by \ref osmo_stream_cli_set_data() */
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link)
{
	return link->data;
}

/*! Set the maximum length queue of the stream servers accepted and allocated from this server link.
 *  \param[in] link Stream Server Link to modify
 *  \param[in] size maximum amount of msgbs which can be queued in the internal tx queue.
 *  \returns 0 on success, negative on error.
 *
 *  The maximum length queue default value is 1024 msgbs. */
int osmo_stream_srv_link_set_tx_queue_max_length(struct osmo_stream_srv_link *link, unsigned int size)
{
	link->tx_queue_max_length = size;
	return 0;
}

/* Similar to osmo_sock_multiaddr_get_name_buf(), but aimed at listening sockets (only local part): */
static char *get_local_sockname_buf(char *buf, size_t buf_len, const struct osmo_stream_srv_link *link)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_len };
	int rc;

	if (buf_len > 0)
		buf[0] = '\0';

	switch (link->sk_domain) {
	case AF_UNSPEC:
		/* we assume INET(6) by default upon link creation: */
	case AF_INET:
	case AF_INET6:
	{
		char hostbuf[OSMO_STREAM_MAX_ADDRS][INET6_ADDRSTRLEN];
		size_t num_hostbuf = ARRAY_SIZE(hostbuf);
		char portbuf[6];
		bool need_more_bufs;
		rc = osmo_sock_multiaddr_get_ip_and_port(link->ofd.fd, link->proto, &hostbuf[0][0],
							 &num_hostbuf, sizeof(hostbuf[0]),
							 portbuf, sizeof(portbuf), true);
		if (rc < 0)
			return NULL;
		need_more_bufs = num_hostbuf > ARRAY_SIZE(hostbuf);
		if (need_more_bufs)
			num_hostbuf = ARRAY_SIZE(hostbuf);
		OSMO_STRBUF_APPEND(sb, osmo_multiaddr_ip_and_port_snprintf,
				   &hostbuf[0][0], num_hostbuf, sizeof(hostbuf[0]), portbuf);
		if (need_more_bufs)
			OSMO_STRBUF_PRINTF(sb, "<need-more-bufs!>");
		return buf;
	}
	case AF_UNIX:
	{
		struct osmo_sockaddr osa;
		struct sockaddr_un *sun;
		socklen_t len = sizeof(osa.u.sas);
		rc = getsockname(link->ofd.fd, &osa.u.sa, &len);
		if (rc < 0) {
			OSMO_STRBUF_PRINTF(sb, "<error-in-getsockname>");
			return buf;
		}
		/* Make sure sun_path is NULL terminated: */
		sun = (struct sockaddr_un *)&osa.u.sa;
		sun->sun_path[sizeof(sun->sun_path) - 1] = '\0';
		OSMO_STRBUF_PRINTF(sb, "%s", sun->sun_path);
		return buf;
	}
	default:
		return NULL;
	}
}

/*! Retrieve description of the stream server link e. g. 127.0.0.1:1234.
 *  Calling this function will build a string that describes the socket in terms of its local/remote
 *  address/port.  The returned name is stored in a static buffer; it is hence not re-entrant or thread-safe.
 *  \param[in] link Stream Server Link to examine
 *  \returns Link description or NULL in case of error */
char *osmo_stream_srv_link_get_sockname(const struct osmo_stream_srv_link *link)
{
	static char buf[sizeof(link->sockname)];

	if (!get_local_sockname_buf(buf, sizeof(buf), link))
		return NULL;
	return buf;
}

/*! Retrieve Osmocom File Descriptor of the stream server link.
 *  \param[in] link Stream Server Link
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link)
{
	return &link->ofd;
}

/*! Retrieve  File Descriptor of the stream server link.
 *  \param[in] conn Stream Server Link
 *  \returns file descriptor or negative on error */
int osmo_stream_srv_link_get_fd(const struct osmo_stream_srv_link *link)
{
	return link->ofd.fd;
}

/*! Set the accept() call-back of the stream server link.
 *  The provided call-back will be called whenever a new inbound connection
 *  is accept()ed.  The call-back then typically creates a new osmo_stream_srv.
 *  If the call-back returns a negative value, the file descriptor will be closed.
 *  \param[in] link Stream Server Link
 *  \param[in] accept_cb Call-back function executed upon accept() */
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link,
	int (*accept_cb)(struct osmo_stream_srv_link *link, int fd))

{
	link->accept_cb = accept_cb;
}

/*! Set the msgb allocation parameters on child osmo_stream_srv objects
 *  \param[in] link Stream Server Link
 *  \param[in] size Size of msgb to allocate (excluding headroom)
 *  \param[in] headroom Headroom to allocate when allocating msgb's
 *
 *  The parameters are applied to osmo_stream_srv objects upon creation.
 *  Setting both to 0 leaves it as implementation default.
 **/
int osmo_stream_srv_link_set_msgb_alloc_info(struct osmo_stream_srv_link *link, unsigned int size, unsigned int headroom)
{
	if (size == 0 && headroom == 0) {
		link->msgb_alloc.set_by_user = false;
	} else {
		link->msgb_alloc.set_by_user = true;
		link->msgb_alloc.headroom = headroom;
		link->msgb_alloc.size = size;
	}
	return 0;
}

/*! Destroy the stream server link. Closes + Releases Memory.
 *  \param[in] link Stream Server Link */
void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link)
{
	if (!link)
		return;
	osmo_stream_srv_link_close(link);
	talloc_free(link);
}

/*! Open the stream server link.  This actually initializes the
 *  underlying socket and binds it to the configured ip/port.
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
			ret = osmo_sock_init2_multiaddr2(link->sk_domain, link->sk_type, link->proto,
							 (const char **)link->addr, link->addrcnt, link->port,
							 NULL, 0, 0, OSMO_SOCK_F_BIND, &link->ma_pars);
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

	get_local_sockname_buf(link->sockname, sizeof(link->sockname), link);
	return 0;
}

/*! Check whether the stream server link is opened.
 *  \param[in] link Stream Server Link to check */
bool osmo_stream_srv_link_is_opened(const struct osmo_stream_srv_link *link)
{
	if (!link)
		return false;

	if (link->ofd.fd == -1)
		return false;

	return true;
}

/*! Close the stream server link and unregister from select loop.
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

/*! Set given parameter of stream_srv_link to given value.
 *  \param[in] link stream server link on which to set parameter.
 *  \param[in] par identifier of the parameter to be set.
 *  \param[in] val value of the parameter to be set.
 *  \param[in] val_len length of the parameter value.
 *  \returns 0 in success; negative -errno on error. */
int osmo_stream_srv_link_set_param(struct osmo_stream_srv_link *link, enum osmo_stream_srv_link_param par,
				   void *val, size_t val_len)
{
	OSMO_ASSERT(link);
	uint8_t val8;

	switch (par) {
	case OSMO_STREAM_SRV_LINK_PAR_SCTP_SOCKOPT_AUTH_SUPPORTED:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		val8 = *(uint8_t *)val;
		link->ma_pars.sctp.sockopt_auth_supported.set = true;
		link->ma_pars.sctp.sockopt_auth_supported.abort_on_failure = val8 > 1;
		link->ma_pars.sctp.sockopt_auth_supported.value = (val8 == 1 || val8 == 3) ? 1 : 0;
		break;
	case OSMO_STREAM_SRV_LINK_PAR_SCTP_SOCKOPT_ASCONF_SUPPORTED:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		val8 = *(uint8_t *)val;
		link->ma_pars.sctp.sockopt_asconf_supported.set = true;
		link->ma_pars.sctp.sockopt_asconf_supported.abort_on_failure = val8 > 1;
		link->ma_pars.sctp.sockopt_asconf_supported.value = (val8 == 1 || val8 == 3) ? 1 : 0;
		break;
	case OSMO_STREAM_SRV_LINK_PAR_SCTP_INIT_NUM_OSTREAMS:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		link->ma_pars.sctp.sockopt_initmsg.set = true;
		link->ma_pars.sctp.sockopt_initmsg.num_ostreams_present = true;
		link->ma_pars.sctp.sockopt_initmsg.num_ostreams_value = *(uint16_t *)val;
		break;
	case OSMO_STREAM_SRV_LINK_PAR_SCTP_INIT_MAX_INSTREAMS:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		link->ma_pars.sctp.sockopt_initmsg.set = true;
		link->ma_pars.sctp.sockopt_initmsg.max_instreams_present = true;
		link->ma_pars.sctp.sockopt_initmsg.max_instreams_value = *(uint16_t *)val;
		break;
	/* TCP keepalive params: */
	case OSMO_STREAM_SRV_LINK_PAR_TCP_SOCKOPT_KEEPALIVE:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		link->tcp_pars.ka.enable = !!*(uint8_t *)val;
		/* Will be applied on accepted sockets */
		break;
	case OSMO_STREAM_SRV_LINK_PAR_TCP_SOCKOPT_KEEPIDLE:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		link->tcp_pars.ka.time_present = true;
		link->tcp_pars.ka.time_value = *(int *)val;
		/* Will be applied on accepted sockets */
		break;
	case OSMO_STREAM_SRV_LINK_PAR_TCP_SOCKOPT_KEEPINTVL:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		link->tcp_pars.ka.intvl_present = true;
		link->tcp_pars.ka.intvl_value = *(int *)val;
		/* Will be applied on accepted sockets */
		break;
	case OSMO_STREAM_SRV_LINK_PAR_TCP_SOCKOPT_KEEPCNT:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		link->tcp_pars.ka.probes_present = true;
		link->tcp_pars.ka.probes_value = *(int *)val;
		/* Will be applied on accepted sockets */
		break;
	case OSMO_STREAM_SRV_LINK_PAR_TCP_SOCKOPT_USER_TIMEOUT:
		if (!val || val_len != sizeof(unsigned int))
			return -EINVAL;
		link->tcp_pars.user_timeout_present = true;
		link->tcp_pars.user_timeout_value = *(int *)val;
		/* This value is inherited by accept() connected sockets (hence by child stream_srv): */
		if (osmo_stream_srv_link_is_opened(link))
			return stream_setsockopt_tcp_user_timeout(osmo_stream_srv_link_get_fd(link),
								  link->tcp_pars.user_timeout_value);
	default:
		return -ENOENT;
	};
	return 0;
}

/*! @} */

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
	struct llist_head		tx_queue; /* osmo_ofd mode (only): Queue of msgbs */
	unsigned int			tx_queue_count; /* osmo_ofd mode (only): Current amount of msgbs queued */
	unsigned int			tx_queue_max_length; /* Max amount of msgbs which can be enqueued */
	osmo_stream_srv_closed_cb_t	closed_cb;
	osmo_stream_srv_read_cb_t	read_cb;
	osmo_stream_srv_read_cb2_t	iofd_read_cb;
	osmo_stream_srv_segmentation_cb_t segmentation_cb;
	osmo_stream_srv_segmentation_cb2_t segmentation_cb2;
	void				*data;
	int				flags;
};

/*! \addtogroup stream_srv
 *  @{
 */

static void stream_srv_iofd_read_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);

	switch (res) {
	case -EPIPE:
	case -ECONNRESET:
		LOGSSRV(conn, LOGL_ERROR, "lost connection with client (%d)\n", res);
		break;
	case 0:
		LOGSSRV(conn, LOGL_NOTICE, "connection closed with client\n");
		break;
	default:
		LOGSSRV(conn, LOGL_DEBUG, "received %d bytes from client\n", res);
		break;
	}
	if (OSMO_UNLIKELY(conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)) {
		LOGSSRV(conn, LOGL_INFO, "Connection is being flushed and closed; ignoring received message\n");
		msgb_free(msg);
		if (osmo_iofd_txqueue_len(iofd) == 0)
			osmo_stream_srv_destroy(conn);
		return;
	}

	if (conn->iofd_read_cb)
		conn->iofd_read_cb(conn, res, msg);
	else
		msgb_free(msg);
}

static void stream_srv_iofd_write_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);
	LOGSSRV(conn, LOGL_DEBUG, "connected write\n");

	if (res < 0)
		LOGSSRV(conn, LOGL_ERROR, "error to send: %s\n", strerror(errno));

	if (osmo_iofd_txqueue_len(iofd) == 0)
		if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)
			osmo_stream_srv_destroy(conn);
}

static const struct osmo_io_ops srv_ioops = {
	.read_cb = stream_srv_iofd_read_cb,
	.write_cb = stream_srv_iofd_write_cb,
};

#ifdef HAVE_LIBSCTP
static void stream_srv_iofd_recvmsg_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg, const struct msghdr *msgh)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);
	LOGSSRV(conn, LOGL_DEBUG, "message received (res=%d)\n", res);

	res = stream_iofd_sctp_recvmsg_trailer(iofd, msg, res, msgh);

	switch (res) {
	case -EPIPE:
	case -ECONNRESET:
		LOGSSRV(conn, LOGL_ERROR, "lost connection with client (%d)\n", res);
		break;
	case 0:
		LOGSSRV(conn, LOGL_NOTICE, "connection closed with client\n");
		break;
	default:
		if (OSMO_LIKELY(res > 0))
			LOGSSRV(conn, LOGL_DEBUG, "received %u bytes from client\n", res);
		break;
	}
	if (OSMO_UNLIKELY(conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)) {
		LOGSSRV(conn, LOGL_INFO, "Connection is being flushed and closed; ignoring received message\n");
		msgb_free(msg);
		if (osmo_iofd_txqueue_len(iofd) == 0)
			osmo_stream_srv_destroy(conn);
		return;
	}

	if (conn->iofd_read_cb)
		conn->iofd_read_cb(conn, res, msg);
	else
		msgb_free(msg);
}

static const struct osmo_io_ops srv_ioops_sctp = {
	.recvmsg_cb = stream_srv_iofd_recvmsg_cb,
	.sendmsg_cb = stream_srv_iofd_write_cb,
};
#endif

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

	msg = msgb_dequeue_count(&conn->tx_queue, &conn->tx_queue_count);
	if (!msg) { /* done, tx_queue empty */
		osmo_fd_write_disable(&conn->ofd);
		return;
	}

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
		conn->tx_queue_count++;
		return;
	}

	if (ret == -1) {/* send(): On error -1 is returned, and errno is set appropriately */
		int err = errno;
		LOGSSRV(conn, LOGL_ERROR, "send(len=%u) error: %s\n", msgb_length(msg), strerror(err));
		if (err == EAGAIN) {
			/* Re-add at the start of the queue to re-attempt: */
			llist_add(&msg->list, &conn->tx_queue);
			conn->tx_queue_count++;
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


/*! Create a legacy osmo_fd mode Stream Server inside the specified link.
 *
 *  This is the function an application traditionally calls from within the
 *  accept_cb call-back of the osmo_stream_srv_link.  It creates a new
 *  osmo_stream_srv within that link.
 *
 *  New users/programs should use osmo_stream_srv_create2 to operate in osmo_io
 *  mode instead.
 *
 *  \param[in] ctx talloc allocation context from which to allocate
 *  \param[in] link Stream Server Link to which we belong
 *  \param[in] fd system file descriptor of the new connection
 *  \param[in] read_cb Call-back to call when the socket is readable
 *  \param[in] closed_cb Call-back to call when the connection is closed
 *  \param[in] data User data to save in the new Stream Server struct
 *  \returns Stream Server in case of success; NULL on error
 *
 *  Note: In case of error, the caller is responsible for closing the fd.
 */
struct osmo_stream_srv *
osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link, int fd,
		       osmo_stream_srv_read_cb_t read_cb,
		       osmo_stream_srv_closed_cb_t closed_cb,
		       void *data)
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

	conn->tx_queue_max_length = conn->srv->tx_queue_max_length;

	if (osmo_fd_register(&conn->ofd) < 0) {
		LOGSSRV(conn, LOGL_ERROR, "could not register FD\n");
		talloc_free(conn);
		return NULL;
	}
	return conn;
}

/*! Create an osmo_iofd mode Stream Server inside the specified link.
 *
 *  This is the function an application typically calls from within the
 *  accept_cb call-back of the osmo_stream_srv_link.  It creates a new
 *  osmo_stream_srv in osmo_io mode within that link.
 *
 *  \param[in] ctx talloc allocation context from which to allocate
 *  \param[in] link Stream Server Link to which we belong
 *  \param[in] fd system file descriptor of the new connection
 *  \param[in] data User data to save in the new Stream Server struct
 *  \returns Stream Server in case of success; NULL on error
 *
 *  Note: In case of error, the caller is responsible for closing the fd.
 */
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
	conn->data = data;

	osmo_sock_get_name_buf(conn->sockname, sizeof(conn->sockname), fd);

	if (link->proto == IPPROTO_SCTP) {
		conn->iofd = osmo_iofd_setup(conn, fd, conn->sockname, OSMO_IO_FD_MODE_RECVMSG_SENDMSG,
					     &srv_ioops_sctp, conn);
		if (conn->iofd)
			osmo_iofd_set_cmsg_size(conn->iofd, CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)));
	} else {
		conn->iofd = osmo_iofd_setup(conn, fd, conn->sockname, OSMO_IO_FD_MODE_READ_WRITE,
					     &srv_ioops, conn);
	}
	if (!conn->iofd) {
		talloc_free(conn);
		return NULL;
	}

	conn->tx_queue_max_length = conn->srv->tx_queue_max_length;
	osmo_iofd_set_txqueue_max_length(conn->iofd, conn->tx_queue_max_length);
	if (conn->srv->msgb_alloc.set_by_user)
		osmo_iofd_set_alloc_info(conn->iofd, conn->srv->msgb_alloc.size, conn->srv->msgb_alloc.headroom);

	if (osmo_iofd_register(conn->iofd, fd) < 0) {
		LOGSSRV(conn, LOGL_ERROR, "could not register FD %d\n", fd);
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

/*! Set a name on the srv object (used during logging).
 *  \param[in] conn server whose name is to be set. The name is copied into the osmo_stream_srv_link, so
 *  the caller memory is not required to be valid beyond the call of this function.
 *  \param[in] name the name to be set on conn
 */
void osmo_stream_srv_set_name(struct osmo_stream_srv *conn, const char *name)
{
	osmo_stream_srv_set_name_f(conn, "%s", name);
}

/*! Set a name on the srv object using arguments like printf() (used during logging).
 *  \param[in] srv stream_srv whose name is to be set
 *  \param[in] name the name to be set on srv
 */
void osmo_stream_srv_set_name_f(struct osmo_stream_srv *conn, const char *fmt, ...)
{
	char *name = NULL;

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		name = talloc_vasprintf(conn, fmt, ap);
		va_end(ap);
	}

	if (conn->name)
		talloc_free((void *)conn->name);
	conn->name = name;

	if (conn->mode == OSMO_STREAM_MODE_OSMO_IO && conn->iofd)
		osmo_iofd_set_name(conn->iofd, conn->name);
}

/*! Retrieve name previously set on the srv object (see osmo_stream_srv_set_name()).
 *  \param[in] conn server whose name is to be retrieved
 *  \returns The name to be set on conn; NULL if never set
 */
const char *osmo_stream_srv_get_name(const struct osmo_stream_srv *conn)
{
	return conn->name;
}

/*! Set the call-back function for incoming data on an osmo_io stream_srv.
 *
 *  This function only works with osmo_stream_srv in osmo_io mode, created by osmo_stream_srv_create2()!
 *
 *  Whenever data is received on the osmo_stram_srv, the read_cb call-back function of the user application is
 *  called.
 *
 *  \param[in] conn Stream Server to modify
 *  \param[in] read_cb Call-back function to be called when data was read */
void osmo_stream_srv_set_read_cb(struct osmo_stream_srv *conn,
				 osmo_stream_srv_read_cb2_t read_cb)
{
	OSMO_ASSERT(conn && conn->mode == OSMO_STREAM_MODE_OSMO_IO);
	conn->iofd_read_cb = read_cb;
}

/*! Set the call-back function called when the stream server socket was closed.
 *  Whenever the socket was closed (network error, client disconnect, etc.), the user-provided
 *  call-back function given here is called.  This is typically used by the application to clean up any of its
 *  internal state related to this specific client/connection.
 *  \param[in] conn Stream Server to modify
 *  \param[in] closed_cb Call-back function to be called when the connection was closed */
void osmo_stream_srv_set_closed_cb(struct osmo_stream_srv *conn,
				   osmo_stream_srv_closed_cb_t closed_cb)
{
	OSMO_ASSERT(conn);
	conn->closed_cb = closed_cb;
}

/*! Prepare to send out all pending messages on the connection's Tx queue.
 *  and then automatically destroy the stream with osmo_stream_srv_destroy().
 *  This function disables queuing of new messages on the connection and also
 *  disables reception of new messages on the connection.
 *  \param[in] conn Stream Server to modify */
void osmo_stream_srv_set_flush_and_destroy(struct osmo_stream_srv *conn)
{
	conn->flags |= OSMO_STREAM_SRV_F_FLUSH_DESTROY;
}

/*! Set application private data of the stream server.
 *  \param[in] conn Stream Server to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_srv_set_data(struct osmo_stream_srv *conn,
				 void *data)
{
	conn->data = data;
}

/* Callback from iofd, forward to stream_srv user: */
static int stream_srv_iofd_segmentation_cb2(struct osmo_io_fd *iofd, struct msgb *msg)
{
	struct osmo_stream_srv *conn = osmo_iofd_get_data(iofd);
	if (conn->segmentation_cb2)
		return conn->segmentation_cb2(conn, msg);
	if (conn->segmentation_cb)
		return conn->segmentation_cb(msg);
	OSMO_ASSERT(0);
	return 0;
}

/* Configure server side segmentation for the iofd */
static void configure_srv_segmentation_cb(struct osmo_stream_srv *conn)
{
	/* Copy default settings */
	struct osmo_io_ops client_ops;
	osmo_iofd_get_ioops(conn->iofd, &client_ops);
	/* Set segmentation cb for this client */
	if (conn->segmentation_cb || conn->segmentation_cb2)
		client_ops.segmentation_cb2 = stream_srv_iofd_segmentation_cb2;
	else
		client_ops.segmentation_cb2 = NULL;
	osmo_iofd_set_ioops(conn->iofd, &client_ops);
}

/*! Set the segmentation callback for target osmo_stream_srv structure.
 *  \param[in,out] conn Target Stream Server to modify
 *  \param[in] segmentation_cb Segmentation callback to be set
 *
 *  A segmentation call-back can optionally be used when a packet based protocol
 *  (like TCP) is used within a STREAM style socket that does not preserve
 *  message boundaries within the stream.  If a segmentation call-back is given,
 *  the osmo_stream_srv library code will makes sure that the read_cb called
 *  only for complete single messages, and not arbitrary segments of the stream.
 *
 *  This function only works with osmo_stream_srv in osmo_io mode, created by
 *  osmo_stream_srv_create2()! The connection has to have been established prior
 *  to calling this function.
 *
 */
void osmo_stream_srv_set_segmentation_cb(struct osmo_stream_srv *conn,
					 osmo_stream_srv_segmentation_cb_t segmentation_cb)
{
	/* Note that the following implies that iofd != NULL, since
	 * osmo_stream_srv_create2() creates the iofd member, too */
	OSMO_ASSERT(conn->mode == OSMO_STREAM_MODE_OSMO_IO);
	conn->segmentation_cb = segmentation_cb;
	conn->segmentation_cb2 = NULL;
	configure_srv_segmentation_cb(conn);
}

/*! Set the segmentation callback for target osmo_stream_srv structure.
 *  \param[in,out] conn Target Stream Server to modify
 *  \param[in] segmentation_cb2 Segmentation callback to be set
 *
 * Same as osmo_stream_srv_set_segmentation_cb(), but a
 * osmo_stream_srv_segmentation_cb2_t is called instead which allows access to
 * the related conn object.
 */
void osmo_stream_srv_set_segmentation_cb2(struct osmo_stream_srv *conn,
					  osmo_stream_srv_segmentation_cb2_t segmentation_cb2)
{
	/* Note that the following implies that iofd != NULL, since
	 * osmo_stream_srv_create2() creates the iofd member, too */
	OSMO_ASSERT(conn->mode == OSMO_STREAM_MODE_OSMO_IO);
	conn->segmentation_cb = NULL;
	conn->segmentation_cb2 = segmentation_cb2;
	configure_srv_segmentation_cb(conn);
}

/*! Retrieve application private data of the stream server
 *  \param[in] conn Stream Server
 *  \returns Application private data, as set by \ref osmo_stream_srv_set_data() */
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn)
{
	return conn->data;
}

/*! Set the maximum length queue of the stream server connection.
 *  \param[in] conn Stream Server to modify
 *  \param[in] size maximum amount of msgbs which can be queued in the internal tx queue.
 *  \returns 0 on success, negative on error.
 *
 *  The default queue size of a osmo_stream_srv is inherited during creation time from
 *  osmo_stream_srv_link. */
int osmo_stream_srv_set_tx_queue_max_length(struct osmo_stream_srv *conn, unsigned int size)
{
	conn->tx_queue_max_length = size;
	if (conn->mode == OSMO_STREAM_MODE_OSMO_IO && conn->iofd)
		osmo_iofd_set_txqueue_max_length(conn->iofd, conn->tx_queue_max_length);
	return 0;
}

/*! Retrieve the stream server socket description.
 *  The returned name is stored in a static buffer; it is hence not re-entrant or thread-safe!
 *  \param[in] conn Stream Server to examine
 *  \returns Socket description or NULL in case of error */
const char *osmo_stream_srv_get_sockname(const struct osmo_stream_srv *conn)
{
	static char buf[OSMO_STREAM_MAX_ADDRS * OSMO_SOCK_NAME_MAXLEN];

	osmo_sock_multiaddr_get_name_buf(buf, sizeof(buf),
					 osmo_stream_srv_get_fd(conn), conn->srv->proto);

	return buf;
}

/*! Retrieve Osmocom File Descriptor of a stream server in osmo_fd mode.
 *  \param[in] conn Stream Server
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_srv_get_ofd(struct osmo_stream_srv *conn)
{
	OSMO_ASSERT(conn->mode == OSMO_STREAM_MODE_OSMO_FD);
	return &conn->ofd;
}

/*! Retrieve File Descriptor of the stream server
 *  \param[in] conn Stream Server
 *  \returns file descriptor or negative on error */
int
osmo_stream_srv_get_fd(const struct osmo_stream_srv *conn)
{
	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		return conn->ofd.fd;
	case OSMO_STREAM_MODE_OSMO_IO:
		if (conn->iofd)
			return osmo_iofd_get_fd(conn->iofd);
	default:
		break;
	}
	return -EINVAL;
}

/*! Retrieve osmo_io descriptor of the stream server socket.
 *  This function must not be called on a stream server in legacy osmo_fd mode!
 *  \param[in] srv Stream Server of which we want to obtain the osmo_io descriptor
 *  \returns osmo_io_fd of stream server. */
struct osmo_io_fd *
osmo_stream_srv_get_iofd(const struct osmo_stream_srv *srv)
{
	OSMO_ASSERT(srv->mode == OSMO_STREAM_MODE_OSMO_IO);
	return srv->iofd;
}

/*! Retrieve the master (Link) from a Stream Server.
 *  \param[in] conn Stream Server of which we want to know the Link
 *  \returns Link through which the given Stream Server is established */
struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn)
{
	return conn->srv;
}

/*! Destroy given Stream Server.
 *  This function closes the Stream Server socket, unregisters from the underlying I/O mechanism, invokes the
 *  connection's closed_cb() callback to allow API users to clean up any associated state they have for this
 *  connection, and then de-allocates associated memory.
 *  \param[in] conn Stream Server to be destroyed */
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn)
{
	if (!conn)
		return;

	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		osmo_fd_unregister(&conn->ofd);
		close(conn->ofd.fd);
		msgb_queue_free(&conn->tx_queue);
		conn->tx_queue_count = 0;
		conn->ofd.fd = -1;
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_free(conn->iofd);
		conn->iofd = NULL;
		break;
	default:
		OSMO_ASSERT(false);
	}
	if (conn->closed_cb)
		conn->closed_cb(conn);
	talloc_free(conn);
}

/*! Enqueue data to be sent via an Osmocom stream server.
 *  \param[in] conn Stream Server through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg)
{
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY) {
		LOGSSRV(conn, LOGL_DEBUG, "Connection is being flushed and closed; ignoring new outgoing message\n");
		msgb_free(msg);
		return;
	}

	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		if (conn->tx_queue_count >= conn->tx_queue_max_length) {
			LOGSSRV(conn, LOGL_ERROR, "send: tx queue full, dropping msg!\n");
			msgb_free(msg);
			return;
		}
		msgb_enqueue_count(&conn->tx_queue, msg, &conn->tx_queue_count);
		osmo_fd_write_enable(&conn->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		if (conn->srv->proto == IPPROTO_SCTP)
			rc = stream_iofd_sctp_send_msgb(conn->iofd, msg, MSG_NOSIGNAL);
		else
			rc = osmo_iofd_write_msgb(conn->iofd, msg);
		if (rc < 0)
			msgb_free(msg);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/*! Receive data via an Osmocom stream server in osmo_fd mode.
 *  \param[in] conn Stream Server from which to receive
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read, negative on error.
 *
 *  Application programs using the legacy osmo_fd mode of osmo_stream_srv will use
 *  this function to read/receive from a stream socket after they have been notified that
 *  it is readable (via select/poll).
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
	OSMO_ASSERT(conn->mode == OSMO_STREAM_MODE_OSMO_FD);

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
		if (ret == -EAGAIN) /* Received MSG_NOTIFICATION from stream_sctp_recvmsg_wrapper() */
			return ret;
		if (errno == EPIPE || errno == ECONNRESET)
			LOGSSRV(conn, LOGL_ERROR, "lost connection with client (%d)\n", errno);
		else
			LOGSSRV(conn, LOGL_ERROR, "recv failed (%d)\n", errno);
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
	switch (conn->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		msgb_queue_free(&conn->tx_queue);
		conn->tx_queue_count = 0;
		osmo_fd_write_disable(&conn->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		osmo_iofd_txqueue_clear(conn->iofd);
		break;
	case OSMO_STREAM_MODE_UNKNOWN:
	default:
		break;
	}

	if (conn->flags & OSMO_STREAM_SRV_F_FLUSH_DESTROY)
		osmo_stream_srv_destroy(conn);
}

/*! Set given parameter of stream_srv to given value.
 *  \param[in] conn stream server conn on which to set parameter.
 *  \param[in] par identifier of the parameter to be set.
 *  \param[in] val value of the parameter to be set.
 *  \param[in] val_len length of the parameter value.
 *  \returns 0 in success; negative -errno on error. */
int osmo_stream_srv_set_param(struct osmo_stream_srv *conn, enum osmo_stream_srv_param par,
			      void *val, size_t val_len)
{
	uint8_t on;
	int i;
	unsigned int u;
	OSMO_ASSERT(conn);

	switch (par) {
	/* TCP keepalive params: */
	case OSMO_STREAM_SRV_PAR_TCP_SOCKOPT_KEEPALIVE:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		on = !!*(uint8_t *)val;
		return stream_setsockopt_tcp_keepalive(osmo_stream_srv_get_fd(conn), on);
	case OSMO_STREAM_SRV_PAR_TCP_SOCKOPT_KEEPIDLE:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		i = *(int *)val;
		return stream_setsockopt_tcp_keepidle(osmo_stream_srv_get_fd(conn), i);
	case OSMO_STREAM_SRV_PAR_TCP_SOCKOPT_KEEPINTVL:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		i = *(int *)val;
		return stream_setsockopt_tcp_keepintvl(osmo_stream_srv_get_fd(conn), i);
	case OSMO_STREAM_SRV_PAR_TCP_SOCKOPT_KEEPCNT:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		i = *(int *)val;
		return stream_setsockopt_tcp_keepcnt(osmo_stream_srv_get_fd(conn), i);
	case OSMO_STREAM_SRV_PAR_TCP_SOCKOPT_USER_TIMEOUT:
		if (!val || val_len != sizeof(unsigned int))
			return -EINVAL;
		u = *(unsigned int *)val;
		return stream_setsockopt_tcp_user_timeout(osmo_stream_srv_get_fd(conn), u);
		break;
	default:
		return -ENOENT;
	};
}

/*! @} */
