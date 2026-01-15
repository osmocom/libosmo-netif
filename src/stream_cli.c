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

/*! \file stream_cli.c */

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

/* Mark whether the object is currently in a user callback. */
#define IN_CB_MASK_CONNECT_CB		(1 << 0)
#define IN_CB_MASK_DISCONNECT_CB	(1 << 1)
#define IN_CB_MASK_READ_CB		(1 << 2)

struct osmo_stream_cli {
	char *name;
	char sockname[OSMO_SOCK_NAME_MAXLEN];
	enum osmo_stream_mode mode;
	union {
		struct osmo_fd			ofd;
		struct osmo_io_fd		*iofd;
	};
	struct llist_head		tx_queue; /* osmo_ofd mode (only): Queue of msgbs */
	unsigned int			tx_queue_count; /* osmo_ofd mode (only): Current amount of msgbs queued */
	unsigned int			tx_queue_max_length; /* Max amount of msgbs which can be enqueued */
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
	int				sk_prio; /* socket priority, SO_PRIORITY, default=0=unset */
	uint16_t			proto;
	uint8_t				ip_dscp; /* IP Differentiated services, 0..63, default=0=unset */
	osmo_stream_cli_connect_cb_t	connect_cb;
	osmo_stream_cli_disconnect_cb_t	disconnect_cb;
	osmo_stream_cli_read_cb_t	read_cb;
	osmo_stream_cli_read_cb2_t	iofd_read_cb;
	osmo_stream_cli_segmentation_cb_t segmentation_cb;
	osmo_stream_cli_segmentation_cb2_t segmentation_cb2;
	void				*data;
	int				flags;
	int				reconnect_timeout;
	struct osmo_sock_init2_multiaddr_pars ma_pars;
	struct stream_tcp_pars		tcp_pars;
	uint8_t				in_cb_mask; /* IN_CB_MASK_* */
	bool				delay_free;
};

/*! \addtogroup stream_cli
 *  @{
 */

/* return true if freed */
static inline bool free_delayed_if_needed(struct osmo_stream_cli *cli)
{
	/* Nobody requested delayed free, skip */
	if (!cli->delay_free)
		return false;
	/* Check for other callbacks active in case we were e.g. in:
	* read_cb() -> [user] -> osmo_steam_client_close() -> disconnect_cb() --> [user] --> osmo_stream_client_destroy()
	* or:
	* connect_cb() -> [user] -> osmo_steam_client_close() -> disconnect_cb() --> [user] --> osmo_stream_client_destroy()
	*/
	if (cli->in_cb_mask != 0)
		return false;

	LOGSCLI(cli, LOGL_DEBUG, "free(delayed)\n");
	talloc_free(cli);
	return true;
}

static void stream_cli_close_iofd(struct osmo_stream_cli *cli)
{
	if (!cli->iofd)
		return;

	osmo_iofd_free(cli->iofd);
	cli->iofd = NULL;
}

static void stream_cli_close_ofd(struct osmo_stream_cli *cli)
{
	if (cli->ofd.fd == -1)
		return;
	osmo_fd_unregister(&cli->ofd);
	close(cli->ofd.fd);
	cli->ofd.fd = -1;
}

/*! Close an Osmocom Stream Client.
 *  \param[in] cli Osmocom Stream Client to be closed
 *  \return true if stream was freed due to disconnect_cb, false otherwise
 *  We unregister the socket fd from the osmocom select() loop
 *  abstraction and close the socket */
static bool stream_cli_close(struct osmo_stream_cli *cli)
{
	int old_state = cli->state;
	LOGSCLI(cli, LOGL_DEBUG, "close()\n");

	/* This guards against reentrant close through disconnect_cb(): */
	if (cli->state == STREAM_CLI_STATE_CLOSED)
		return false;
	if (cli->state == STREAM_CLI_STATE_WAIT_RECONNECT) {
		osmo_timer_del(&cli->timer);
		cli->state = STREAM_CLI_STATE_CLOSED;
		return false;
	}


	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		stream_cli_close_ofd(cli);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		stream_cli_close_iofd(cli);
		break;
	default:
		OSMO_ASSERT(false);
	}

	cli->state = STREAM_CLI_STATE_CLOSED;

	/* If conn was established, notify the disconnection to the user:
	 * Also, if reconnect is disabled by user, notify the user that connect() failed: */
	if (old_state == STREAM_CLI_STATE_CONNECTED ||
	    (old_state == STREAM_CLI_STATE_CONNECTING && cli->reconnect_timeout < 0)) {
		OSMO_ASSERT(!(cli->in_cb_mask & IN_CB_MASK_DISCONNECT_CB));
		cli->in_cb_mask |= IN_CB_MASK_DISCONNECT_CB;
		if (cli->disconnect_cb)
			cli->disconnect_cb(cli);
		cli->in_cb_mask &= ~IN_CB_MASK_DISCONNECT_CB;
		return free_delayed_if_needed(cli);
	}
	return false;
}

/*! Close an Osmocom Stream Client.
 *  \param[in] cli Osmocom Stream Client to be closed
 *  We unregister the socket fd from the osmocom select() loop
 *  abstraction and close the socket */
void osmo_stream_cli_close(struct osmo_stream_cli *cli)
{
	(void)stream_cli_close(cli);
}

/*! Re-connect an Osmocom Stream Client.
 *  If re-connection is enabled for this client
 *  (which is the case unless negative timeout was explicitly set via osmo_stream_cli_set_reconnect_timeout() call),
 *  we close any existing connection (if any) and schedule a re-connect timer */
static bool stream_cli_reconnect(struct osmo_stream_cli *cli)
{
	bool freed = stream_cli_close(cli);

	if (freed)
		return true;

	if (cli->reconnect_timeout < 0) {
		LOGSCLI(cli, LOGL_INFO, "not reconnecting, disabled\n");
		return false;
	}

	cli->state = STREAM_CLI_STATE_WAIT_RECONNECT;
	LOGSCLI(cli, LOGL_INFO, "retrying reconnect in %d seconds...\n",
		cli->reconnect_timeout);
	osmo_timer_schedule(&cli->timer, cli->reconnect_timeout, 0);
	return false;
}

/*! Re-connect an Osmocom Stream Client.
 *  If re-connection is enabled for this client
 *  (which is the case unless negative timeout was explicitly set via osmo_stream_cli_set_reconnect_timeout() call),
 *  we close any existing connection (if any) and schedule a re-connect timer */
void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli)
{
	(void)stream_cli_reconnect(cli);
}

/*! Check if Osmocom Stream Client is in connected state.
 *  \param[in] cli Osmocom Stream Client
 *  \return true if connected, false otherwise
 */
bool osmo_stream_cli_is_connected(struct osmo_stream_cli *cli)
{
	return cli->state == STREAM_CLI_STATE_CONNECTED;
}

/*! Check if Osmocom Stream Client is opened (has an FD available) according to
 *  its current state.
 *  \param[in] cli Osmocom Stream Client
 *  \return true if fd is available (osmo_stream_cli_get_fd()), false otherwise
 */
static bool stream_cli_is_opened(const struct osmo_stream_cli *cli)
{
	return cli->state == STREAM_CLI_STATE_CONNECTING ||
	       cli->state == STREAM_CLI_STATE_CONNECTED;
}

/*! Retrieve file descriptor of the stream client socket.
 *  \param[in] cli Stream Client of which we want to obtain the file descriptor
 *  \returns File descriptor or negative in case of error */
int
osmo_stream_cli_get_fd(const struct osmo_stream_cli *cli)
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

/*! Retrieve osmo_io descriptor of the stream client socket.
 *  This function must not be called on a stream client in legacy osmo_fd mode!
 *  The iofd is only valid once/after osmo_stream_cli_open() has successfully returned.
 *  \param[in] cli Stream Client of which we want to obtain the file descriptor
 *  \returns osmo_io_fd of stream client, or NULL if stream not yet opened. */
struct osmo_io_fd *
osmo_stream_cli_get_iofd(const struct osmo_stream_cli *cli)
{
	OSMO_ASSERT(cli->mode == OSMO_STREAM_MODE_OSMO_IO);
	return cli->iofd;
}

/* Return true if read_cb caused a delayed_free, hence cli not available anymore. */
static bool stream_cli_read(struct osmo_stream_cli *cli)
{
	LOGSCLI(cli, LOGL_DEBUG, "message received\n");

	cli->in_cb_mask |= IN_CB_MASK_READ_CB;
	if (cli->read_cb)
		cli->read_cb(cli);
	cli->in_cb_mask &= ~IN_CB_MASK_READ_CB;
	return free_delayed_if_needed(cli);
}

static int stream_cli_write(struct osmo_stream_cli *cli)
{
#ifdef HAVE_LIBSCTP
	struct sctp_sndrcvinfo sinfo;
#endif
	struct msgb *msg;
	int ret;

	msg = msgb_dequeue_count(&cli->tx_queue, &cli->tx_queue_count);
	if (!msg) { /* done, tx_queue empty */
		osmo_fd_write_disable(&cli->ofd);
		return 0;
	}

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
		cli->tx_queue_count++;
		return 0;
	}

	if (ret < 0) {
		int err = errno;
		LOGSCLI(cli, LOGL_ERROR, "send(len=%u) error: %s\n", msgb_length(msg), strerror(err));
		if (err == EAGAIN) {
			/* Re-add at the start of the queue to re-attempt: */
			llist_add(&msg->list, &cli->tx_queue);
			cli->tx_queue_count++;
			return 0;
		}
		msgb_free(msg);
		(void)stream_cli_reconnect(cli);
		return 0;
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
	ret = setsockopt(osmo_stream_cli_get_fd(cli), SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(val));
	if (ret < 0)
		LOGSCLI(cli, LOGL_ERROR, "Failed setting SO_NOSIGPIPE: %s\n", strerror(errno));
	return ret;
#else
	return 0;
#endif
}

/* Update cli->sockname based on socket info: */
static void stream_cli_update_iofd_name(struct osmo_stream_cli *cli)
{
	if (!(cli->mode == OSMO_STREAM_MODE_OSMO_IO && cli->iofd))
		return;

	char *tmp = talloc_asprintf(cli, "%s,%s", cli->name, cli->sockname);
	osmo_iofd_set_name(cli->iofd, tmp);
	talloc_free(tmp);
}

/* Update cli->sockname based on socket info: */
static void stream_cli_update_sockname(struct osmo_stream_cli *cli)
{
	osmo_sock_get_name_buf(cli->sockname, sizeof(cli->sockname), osmo_stream_cli_get_fd(cli));
	/* Update stream iofd with the new cli->sockname too: */
	stream_cli_update_iofd_name(cli);

}

/* returns true if cli is freed */
static bool stream_cli_handle_connecting(struct osmo_stream_cli *cli, int res)
{
	int error, ret = res;
	socklen_t len = sizeof(error);

	int fd = osmo_stream_cli_get_fd(cli);
	OSMO_ASSERT(fd >= 0);

	if (ret < 0) {
		LOGSCLI(cli, LOGL_ERROR, "connect failed (%d)\n", res);
		return stream_cli_reconnect(cli);
	}
	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret >= 0 && error > 0) {
		LOGSCLI(cli, LOGL_ERROR, "connect so_error (%d)\n", error);
		return stream_cli_reconnect(cli);
	}

	/* If messages got enqueued while 'connecting', keep WRITE flag
	   up to dispatch them upon next main loop step */
	if (cli->mode == OSMO_STREAM_MODE_OSMO_FD && llist_empty(&cli->tx_queue))
		osmo_fd_write_disable(&cli->ofd);

	stream_cli_update_sockname(cli);

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
	cli->in_cb_mask |= IN_CB_MASK_CONNECT_CB;
	if (cli->connect_cb)
		cli->connect_cb(cli);
	cli->in_cb_mask &= ~IN_CB_MASK_CONNECT_CB;
	return free_delayed_if_needed(cli);
}

static int osmo_stream_cli_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_cli *cli = ofd->data;

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		(void)stream_cli_handle_connecting(cli, 0);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (what & OSMO_FD_READ) {
			LOGSCLI(cli, LOGL_DEBUG, "connected read\n");
			if (stream_cli_read(cli) == true)
				break; /* cli (and hence ofd) freed, done. */
		}
		if (what & OSMO_FD_WRITE) {
			LOGSCLI(cli, LOGL_DEBUG, "connected write\n");
			stream_cli_write(cli);
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

/*! Create an Osmocom stream client.
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
	cli->tx_queue_max_length = 1024; /* Default tx queue size, msgbs. */

	cli->ma_pars.sctp.version = 0;

	return cli;
}

static void stream_cli_iofd_read_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_cli *cli  = osmo_iofd_get_data(iofd);
	bool freed;

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		freed = stream_cli_handle_connecting(cli, res);
		if (freed)
			return; /* msg was also freed as part of the talloc tree. */
		if (cli->state != STREAM_CLI_STATE_CONNECTED) {
			msgb_free(msg);
			return;
		}
		/* Follow below common path submitting read_cb(msg) to user. */
		break;
	case STREAM_CLI_STATE_CONNECTED:
		switch (res) {
		case -EPIPE:
		case -ECONNRESET:
			LOGSCLI(cli, LOGL_ERROR, "lost connection with srv (%d)\n", res);
			freed = stream_cli_reconnect(cli);
			break;
		case 0:
			LOGSCLI(cli, LOGL_NOTICE, "connection closed with srv\n");
			freed = stream_cli_reconnect(cli);
			break;
		default:
			LOGSCLI(cli, LOGL_DEBUG, "received %d bytes from srv\n", res);
			freed = false;
			break;
		}
		if (freed)
			return; /* msg was also freed as part of the talloc tree. */
		/* Follow below common path submitting read_cb(msg) to user. */
		break;
	default:
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
	}

	/* Notify user of new data or error: */
	if (!cli->iofd_read_cb) {
		msgb_free(msg);
		return;
	}
	cli->in_cb_mask |= IN_CB_MASK_READ_CB;
	cli->iofd_read_cb(cli, res, msg);
	cli->in_cb_mask &= ~IN_CB_MASK_READ_CB;
	OSMO_ASSERT(cli->in_cb_mask == 0);
	(void)free_delayed_if_needed(cli);
}

static void stream_cli_iofd_write_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_stream_cli *cli = osmo_iofd_get_data(iofd);
	/* msgb is not owned by us here, no need to free it. */

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		(void)stream_cli_handle_connecting(cli, res);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (msg && res <= 0) {
			LOGSCLI(cli, LOGL_ERROR, "received error %d in response to send\n", res);
			(void)stream_cli_reconnect(cli);
		}
		/* res=0 && msgb=NULL: "connected notify", but we already received before a read_cb
		 * which moved us to CONNECTED state. Do nothing.
		 */
		break;
	default:
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
	}
}

static const struct osmo_io_ops osmo_stream_cli_ioops = {
	.read_cb = stream_cli_iofd_read_cb,
	.write_cb = stream_cli_iofd_write_cb,
};

#ifdef HAVE_LIBSCTP
static void stream_cli_iofd_recvmsg_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg, const struct msghdr *msgh)
{
	struct osmo_stream_cli *cli  = osmo_iofd_get_data(iofd);
	bool freed;

	res = stream_iofd_sctp_recvmsg_trailer(iofd, msg, res, msgh);

	switch (cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		freed = stream_cli_handle_connecting(cli, res);
		if (freed)
			return; /* msg was also freed as part of the talloc tree. */
		if (cli->state != STREAM_CLI_STATE_CONNECTED) {
			msgb_free(msg);
			return;
		}
		/* Follow below common path submitting read_cb(msg) to user. */
		break;
	case STREAM_CLI_STATE_CONNECTED:
		switch (res) {
		case -EPIPE:
		case -ECONNRESET:
			LOGSCLI(cli, LOGL_ERROR, "lost connection with srv (%d)\n", res);
			freed = stream_cli_reconnect(cli);
			break;
		case 0:
			LOGSCLI(cli, LOGL_NOTICE, "connection closed with srv\n");
			freed = stream_cli_reconnect(cli);
			break;
		default:
			freed = false;
			break;
		}
		if (freed)
			return; /* msg was also freed as part of the talloc tree. */
		/* Follow below common path submitting read_cb(msg) to user. */
		break;
	default:
		osmo_panic("%s() called with unexpected state %d\n", __func__, cli->state);
	}

	/* Notify user of new data or error: */
	if (!cli->iofd_read_cb) {
		msgb_free(msg);
		return;
	}
	cli->in_cb_mask |= IN_CB_MASK_READ_CB;
	cli->iofd_read_cb(cli, res, msg);
	cli->in_cb_mask &= ~IN_CB_MASK_READ_CB;
	OSMO_ASSERT(cli->in_cb_mask == 0);
	(void)free_delayed_if_needed(cli);
}

static const struct osmo_io_ops osmo_stream_cli_ioops_sctp = {
	.recvmsg_cb = stream_cli_iofd_recvmsg_cb,
	.sendmsg_cb = stream_cli_iofd_write_cb,
};
#endif


/*! Set a name on the cli object (used during logging).
 *  \param[in] cli stream_cli whose name is to be set
 *  \param[in] name the name to be set on cli
 */
void osmo_stream_cli_set_name(struct osmo_stream_cli *cli, const char *name)
{
	osmo_stream_cli_set_name_f(cli, "%s", name);
}

/*! Set a name on the cli object using arguments like printf() (used during logging).
 *  \param[in] cli stream_cli whose name is to be set
 *  \param[in] name the name to be set on cli
 */
void osmo_stream_cli_set_name_f(struct osmo_stream_cli *cli, const char *fmt, ...)
{
	char *name = NULL;

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		name = talloc_vasprintf(cli, fmt, ap);
		va_end(ap);
	}

	if (cli->name)
		talloc_free((void *)cli->name);
	cli->name = name;

	/* Update stream iofd with the new cli->name too: */
	stream_cli_update_iofd_name(cli);
}

/*! Retrieve name previously set on the cli object (see osmo_stream_cli_set_name()).
 *  \param[in] cli stream_cli whose name is to be retrieved
 *  \returns The name to be set on cli; NULL if never set
 */
const char *osmo_stream_cli_get_name(const struct osmo_stream_cli *cli)
{
	return cli->name;
}

/*! Set the remote address to which we connect.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] addr Remote IP address
 */
void
osmo_stream_cli_set_addr(struct osmo_stream_cli *cli, const char *addr)
{
	osmo_stream_cli_set_addrs(cli, &addr, 1);
}

/*! Set the remote address set to which we connect.
 *  Useful for protocols allowing connecting to more than one address (such as SCTP)
 *  Any changes to this setting will only become active upon next (re)connect.
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

/*! Set the remote port number to which we connect.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Remote port number
 */
void
osmo_stream_cli_set_port(struct osmo_stream_cli *cli, uint16_t port)
{
	cli->port = port;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/*! Set the local port number for the socket (to be bound to).
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Local port number
 */
void
osmo_stream_cli_set_local_port(struct osmo_stream_cli *cli, uint16_t port)
{
	cli->local_port = port;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/*! Set the local address for the socket (to be bound to).
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] port Local host name
 */
void
osmo_stream_cli_set_local_addr(struct osmo_stream_cli *cli, const char *addr)
{
	osmo_stream_cli_set_local_addrs(cli, &addr, 1);
}

/*! Set the local address set to which we bind.
 *  Useful for protocols allowing bind to more than one address (such as SCTP)
 *  Any changes to this setting will only become active upon next (re)connect.
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

/*! Set the protocol for the stream client socket.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] proto Protocol (like IPPROTO_TCP (default), IPPROTO_SCTP, ...)
 */
void
osmo_stream_cli_set_proto(struct osmo_stream_cli *cli, uint16_t proto)
{
	cli->proto = proto;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

/* Callback from iofd, forward to stream_cli user: */
static int stream_cli_iofd_segmentation_cb2(struct osmo_io_fd *iofd, struct msgb *msg)
{
	struct osmo_stream_cli *cli = osmo_iofd_get_data(iofd);
	if (cli->segmentation_cb2)
		return cli->segmentation_cb2(cli, msg);
	if (cli->segmentation_cb)
		return cli->segmentation_cb(msg);
	OSMO_ASSERT(0);
	return 0;
}

/* Configure client side segmentation for the iofd */
static void configure_cli_segmentation_cb(struct osmo_stream_cli *cli)
{
	/* Copy default settings */
	struct osmo_io_ops client_ops;
	osmo_iofd_get_ioops(cli->iofd, &client_ops);
	/* Set segmentation cb for this client */
	if (cli->segmentation_cb || cli->segmentation_cb2)
		client_ops.segmentation_cb2 = stream_cli_iofd_segmentation_cb2;
	else
		client_ops.segmentation_cb2 = NULL;
	osmo_iofd_set_ioops(cli->iofd, &client_ops);
}

/*! Set the segmentation callback for the client.
 *  \param[in,out] cli Stream Client to modify
 *  \param[in] segmentation_cb Target segmentation callback
 *
 *  A segmentation call-back can optionally be used when a packet based protocol
 *  (like TCP) is used within a STREAM style socket that does not preserve
 *  message boundaries within the stream.  If a segmentation call-back is given,
 *  the osmo_stream_srv library code will makes sure that the read_cb called
 *  only for complete single messages, and not arbitrary segments of the stream.
 */
void osmo_stream_cli_set_segmentation_cb(struct osmo_stream_cli *cli,
					 osmo_stream_cli_segmentation_cb_t segmentation_cb)
{
	cli->segmentation_cb = segmentation_cb;
	cli->segmentation_cb2 = NULL;
	if (cli->iofd) /* Otherwise, this will be done in osmo_stream_cli_open() */
		configure_cli_segmentation_cb(cli);
}

/*! Set the segmentation callback for the client.
 *  \param[in,out] cli Stream Client to modify
 *  \param[in] segmentation_cb2 Target segmentation callback
 *
 * Same as osmo_stream_cli_set_segmentation_cb(), but a
 * osmo_stream_cli_segmentation_cb2_t is called instead which allows access to
 * the related cli object.
 */
void osmo_stream_cli_set_segmentation_cb2(struct osmo_stream_cli *cli,
					  osmo_stream_cli_segmentation_cb2_t segmentation_cb2)
{
	cli->segmentation_cb = NULL;
	cli->segmentation_cb2 = segmentation_cb2;
	if (cli->iofd) /* Otherwise, this will be done in osmo_stream_cli_open() */
		configure_cli_segmentation_cb(cli);
}

/*! Set the socket type for the stream client.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] type Socket Type (like SOCK_STREAM (default), SOCK_SEQPACKET, ...)
 *  \returns zero on success, negative -errno on error.
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

/*! Set the socket domain for the stream client.
 *  Any changes to this setting will only become active upon next (re)connect.
 *  \param[in] cli Stream Client to modify
 *  \param[in] domain Socket Domain (like AF_UNSPEC (default for IP), AF_UNIX, AF_INET, ...)
 *  \returns zero on success, negative -errno on error.
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

/*! Set the reconnect time of the stream client socket.
 *  \param[in] cli Stream Client to modify
 *  \param[in] timeout Re-connect timeout in seconds or negative value to disable auto-reconnection */
void
osmo_stream_cli_set_reconnect_timeout(struct osmo_stream_cli *cli, int timeout)
{
	cli->reconnect_timeout = timeout;
}

/*! Set application private data of the stream client socket.
 *  \param[in] cli Stream Client to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_stream_cli_set_data(struct osmo_stream_cli *cli, void *data)
{
	cli->data = data;
}

/*! Retrieve application private data of the stream client socket.
 *  \param[in] cli Stream Client to modify
 *  \returns Application private data, as set by \ref osmo_stream_cli_set_data() */
void *osmo_stream_cli_get_data(struct osmo_stream_cli *cli)
{
	return cli->data;
}

/*! Set the maximum length queue of the stream client.
 *  \param[in] cli Stream Client to modify
 *  \param[in] size maximum amount of msgbs which can be queued in the internal tx queue.
 *  \returns 0 on success, negative on error.
 *
 *  The maximum length queue default value is 1024 msgbs. */
int osmo_stream_cli_set_tx_queue_max_length(struct osmo_stream_cli *cli, unsigned int size)
{
	cli->tx_queue_max_length = size;

	if (cli->iofd) /* Otherwise, this will be done in osmo_stream_cli_open() */
		osmo_iofd_set_txqueue_max_length(cli->iofd, cli->tx_queue_max_length);

	/* XXX: Here, in OSMO_STREAM_MODE_OSMO_FD mode we could check current
	 * size of cli->tx_queue and shrink it from the front or back... */
	return 0;
}

/*! Retrieve the stream client socket description.
 *  Calling this function will build a string that describes the socket in terms of its local/remote
 *  address/port.  The returned name is stored in a static buffer; it is hence not re-entrant or thread-safe.
 *  \param[in] cli Stream Client to examine
 *  \returns Socket description or NULL in case of error */
char *osmo_stream_cli_get_sockname(const struct osmo_stream_cli *cli)
{
	static char buf[OSMO_STREAM_MAX_ADDRS * OSMO_SOCK_NAME_MAXLEN];

	osmo_sock_multiaddr_get_name_buf(buf, sizeof(buf),
					 osmo_stream_cli_get_fd(cli), cli->proto);

	return buf;
}

/*! Retrieve Osmocom File Descriptor of the stream client socket.
 *  This function only works in case you operate osmo_stream_cli in osmo_fd mode!
 *  \param[in] cli Stream Client to modify
 *  \returns Pointer to \ref osmo_fd */
struct osmo_fd *
osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli)
{
	OSMO_ASSERT(cli->mode == OSMO_STREAM_MODE_OSMO_FD);
	return &cli->ofd;
}

/*! Set the call-back function called on connect of the stream client socket.
 *  The call-back function registered via this function will be called upon completion of the non-blocking
 *  outbound connect operation.
 *  \param[in] cli Stream Client to modify
 *  \param[in] connect_cb Call-back function to be called upon connect */
void
osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli,
			       osmo_stream_cli_connect_cb_t connect_cb)
{
	cli->connect_cb = connect_cb;
}

/*! Set the call-back function called on disconnect of the stream client socket.
 *  \param[in] cli Stream Client to modify
 *  \param[in] disconnect_cb Call-back function to be called upon disconnect */
void osmo_stream_cli_set_disconnect_cb(struct osmo_stream_cli *cli,
				       osmo_stream_cli_disconnect_cb_t disconnect_cb)
{
	cli->disconnect_cb = disconnect_cb;
}

/*! Set the call-back function called to read from the stream client socket.
 *  This function will implicitly configure osmo_stream_cli to use legacy osmo_ofd mode.
 *  \param[in] cli Stream Client to modify
 *  \param[in] read_cb Call-back function to be called when we want to read */
void
osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli,
			    osmo_stream_cli_read_cb_t read_cb)
{
	OSMO_ASSERT(cli->mode != OSMO_STREAM_MODE_OSMO_IO);
	cli->mode = OSMO_STREAM_MODE_OSMO_FD;
	cli->read_cb = read_cb;
}

/*! Set the call-back function called to read from the stream client socket.
 *  This function will implicitly configure osmo_stream_cli to use osmo_iofd mode.
 *  \param[in] cli Stream Client to modify
 *  \param[in] read_cb Call-back function to be called when data was read from the socket */
void
osmo_stream_cli_set_read_cb2(struct osmo_stream_cli *cli,
			     osmo_stream_cli_read_cb2_t read_cb)
{
	OSMO_ASSERT(cli->mode != OSMO_STREAM_MODE_OSMO_FD);
	cli->mode = OSMO_STREAM_MODE_OSMO_IO;
	cli->iofd_read_cb = read_cb;
}

/*! Destroy a Osmocom stream client (includes close).
 *  \param[in] cli Stream Client to destroy */
void osmo_stream_cli_destroy(struct osmo_stream_cli *cli)
{
	if (!cli)
		return;

	LOGSCLI(cli, LOGL_DEBUG, "destroy()\n");
	OSMO_ASSERT(stream_cli_close(cli) == false);
	osmo_timer_del(&cli->timer);
	msgb_queue_free(&cli->tx_queue);
	cli->tx_queue_count = 0;
	/* if we are in a user callback, delay freeing. */
	if (cli->in_cb_mask != 0) {
		LOGSCLI(cli, LOGL_DEBUG, "delay free() in_cb_mask=0x%02x\n", cli->in_cb_mask);
		cli->delay_free = true;
		/* Move ptr to avoid double free if parent ctx of cli is freed
		 * meanwhile (eg. during user callback after calling
		 * osmo_stream_client_destroy() and before returning from user
		 * callback. */
		talloc_steal(OTC_GLOBAL, cli);
	} else {
		LOGSCLI(cli, LOGL_DEBUG, "free(destroy)\n");
		talloc_free(cli);
	}
}

/*! DEPRECATED: use osmo_stream_cli_set_reconnect_timeout() or osmo_stream_cli_reconnect() instead!
 * Open connection of an Osmocom stream client
 *  \param[in] cli Stream Client to connect
 *  \param[in] reconect 1 if we should not automatically reconnect
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && cli->ofd.fd >= 0) {
		if (stream_cli_close(cli) == true)
			return -ENAVAIL; /* freed */
	}

	cli->flags &= ~OSMO_STREAM_CLI_F_RECONF;

	switch (cli->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		ret = osmo_sock_init2_multiaddr2(AF_UNSPEC, SOCK_STREAM, cli->proto,
						(const char **)cli->local_addr, cli->local_addrcnt, cli->local_port,
						(const char **)cli->addr, cli->addrcnt, cli->port,
						OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK |
						OSMO_SOCK_F_DSCP(cli->ip_dscp) | OSMO_SOCK_F_PRIO(cli->sk_prio),
						&cli->ma_pars);
		break;
#endif
	default:
		ret = osmo_sock_init2(AF_UNSPEC, SOCK_STREAM, cli->proto,
				      cli->local_addr[0], cli->local_port,
				      cli->addr[0], cli->port,
				      OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK |
				      OSMO_SOCK_F_DSCP(cli->ip_dscp) | OSMO_SOCK_F_PRIO(cli->sk_prio));
	}

	if (ret < 0) {
		LOGSCLI(cli, LOGL_ERROR, "connect: socket creation error (%d)\n", ret);
		if (reconnect)
			(void)stream_cli_reconnect(cli);
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

/*! Set the NODELAY socket option to avoid Nagle-like behavior.
 *  Setting this to nodelay=true will automatically set the NODELAY
 *  socket option on any socket established via \ref osmo_stream_cli_open
 *  or any re-connect. This can be set either before or after opening the
 *  socket.
 *  \param[in] cli Stream client whose sockets are to be configured
 *  \param[in] nodelay whether to set (true) NODELAY before connect()
 */
void osmo_stream_cli_set_nodelay(struct osmo_stream_cli *cli, bool nodelay)
{
	int fd;
	if (nodelay)
		cli->flags |= OSMO_STREAM_CLI_F_NODELAY;
	else
		cli->flags &= ~OSMO_STREAM_CLI_F_NODELAY;

	if (!stream_cli_is_opened(cli))
		return; /* Config will be applied upon open() time */

	if ((fd = osmo_stream_cli_get_fd(cli)) < 0) {
		LOGSCLI(cli, LOGL_ERROR, "set_nodelay(%u): failed obtaining socket\n", nodelay);
		return;
	}
	if (stream_setsockopt_nodelay(fd, cli->proto, nodelay ? 1 : 0) < 0)
		LOGSCLI(cli, LOGL_ERROR, "set_nodelay(%u): failed setsockopt err=%d\n",
			nodelay, errno);
}

/*! Set the priority value of the stream socket.
 *  Setting this  will automatically set the socket priority
 *  option on any socket established via \ref osmo_stream_cli_open
 *  or any re-connect. This can be set either before or after opening the
 *  socket.
 *  \param[in] cli Stream client whose sockets are to be configured
 *  \param[in] sk_prio priority value. Values outside 0..6 require CAP_NET_ADMIN.
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_set_priority(struct osmo_stream_cli *cli, int sk_prio)
{
	int rc;
	int fd;

	if (cli->sk_prio == sk_prio)
		return 0; /* No change needed */

	cli->sk_prio = sk_prio;

	if (!stream_cli_is_opened(cli))
		return 0; /* Config will be applied upon open() time */

	if ((fd = osmo_stream_cli_get_fd(cli)) < 0) { /* Shouldn't happen... */
		LOGSCLI(cli, LOGL_ERROR, "set_priority(%d): failed obtaining socket\n", cli->sk_prio);
		return -EBADFD;
	}
	if ((rc = osmo_sock_set_priority(fd, cli->sk_prio)) < 0)
		LOGSCLI(cli, LOGL_ERROR, "set_priority(%d): failed setsockopt err=%d\n",
			cli->sk_prio, errno);
	return rc;
}

/*! Set the DSCP (differentiated services code point) of the stream socket.
 *  Setting this  will automatically set the IP DSCP option on any socket established
 *  via \ref osmo_stream_cli_open or any re-connect. This can be set either before or
 *  after opening the socket.
 *  \param[in] cli Stream client whose sockets are to be configured
 *  \param[in] ip_dscp DSCP value. Value range 0..63.
 *  \return negative on error, 0 on success
 */
int osmo_stream_cli_set_ip_dscp(struct osmo_stream_cli *cli, uint8_t ip_dscp)
{
	int rc;
	int fd;

	if (cli->ip_dscp == ip_dscp)
		return 0; /* No change needed */

	cli->ip_dscp = ip_dscp;

	if (!stream_cli_is_opened(cli))
		return 0; /* Config will be applied upon open() time */

	if ((fd = osmo_stream_cli_get_fd(cli)) < 0) { /* Shouldn't happen... */
		LOGSCLI(cli, LOGL_ERROR, "set_ip_dscp(%u): failed obtaining socket\n", cli->ip_dscp);
		return -EBADFD;
	}
	if ((rc = osmo_sock_set_dscp(fd, cli->ip_dscp)) < 0)
		LOGSCLI(cli, LOGL_ERROR, "set_ip_dscp(%u): failed setsockopt err=%d\n",
			cli->ip_dscp, errno);
	return rc;
}

/*! Open connection of an Osmocom stream client.
 *  This will initiate an non-blocking outbound connect to the configured destination (server) address.
 *  By default the client will automatically attempt to reconnect after default timeout.
 *  To disable this, use osmo_stream_cli_set_reconnect_timeout() before calling this function.
 *  \param[in] cli Stream Client to connect
 *  \return negative on error, 0 on success */
int osmo_stream_cli_open(struct osmo_stream_cli *cli)
{
	int ret, flags;
	int fd = -1;
	unsigned int local_addrcnt;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && osmo_stream_cli_get_fd(cli) >= 0) {
		if (stream_cli_close(cli) == true)
			return -ENAVAIL; /* freed */
	}

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
			local_addrcnt = cli->local_addrcnt;
			flags = OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_NONBLOCK |
				OSMO_SOCK_F_DSCP(cli->ip_dscp) | OSMO_SOCK_F_PRIO(cli->sk_prio);
			if (cli->local_addrcnt > 0 || cli->local_port > 0) { /* explicit bind required? */
				flags |= OSMO_SOCK_F_BIND;
				/* If no local addr configured, use local_addr[0]=NULL by default when creating the socket. */
				if (cli->local_addrcnt == 0)
					local_addrcnt = 1;
			}
			ret = osmo_sock_init2_multiaddr2(cli->sk_domain, cli->sk_type, cli->proto,
							(const char **)cli->local_addr, local_addrcnt, cli->local_port,
							(const char **)cli->addr, cli->addrcnt, cli->port,
							flags, &cli->ma_pars);
			break;
#endif
		default:
			ret = osmo_sock_init2(cli->sk_domain, cli->sk_type, cli->proto,
					      cli->local_addr[0], cli->local_port,
					      cli->addr[0], cli->port,
					      OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK |
					      OSMO_SOCK_F_DSCP(cli->ip_dscp) | OSMO_SOCK_F_PRIO(cli->sk_prio));
		}
		break;
	default:
		return -ENOTSUP;
	}

	if (ret < 0) {
		LOGSCLI(cli, LOGL_ERROR, "connect: socket creation error (%d)\n", ret);
		(void)stream_cli_reconnect(cli);
		return ret;
	}

	fd = ret;

	if (cli->flags & OSMO_STREAM_CLI_F_NODELAY) {
		ret = stream_setsockopt_nodelay(fd, cli->proto, 1);
		if (ret < 0)
			goto error_close_socket;
	}

	if (cli->proto == IPPROTO_TCP) {
		ret = stream_tcp_keepalive_pars_apply(fd, &cli->tcp_pars.ka);
		if (ret < 0)
			goto error_close_socket;
		if (cli->tcp_pars.user_timeout_present) {
			ret = stream_setsockopt_tcp_user_timeout(fd, cli->tcp_pars.user_timeout_value);
			if (ret < 0)
				goto error_close_socket;
		}
	}

	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		osmo_fd_setup(&cli->ofd, fd, OSMO_FD_READ | OSMO_FD_WRITE, osmo_stream_cli_fd_cb, cli, 0);
		if (osmo_fd_register(&cli->ofd) < 0)
			goto error_close_socket;
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		/* Be sure that previous osmo_io instance is freed before creating a new one. */
		stream_cli_close_iofd(cli);
#ifdef HAVE_LIBSCTP
		if (cli->proto == IPPROTO_SCTP) {
			cli->iofd = osmo_iofd_setup(cli, fd, cli->name, OSMO_IO_FD_MODE_RECVMSG_SENDMSG,
						    &osmo_stream_cli_ioops_sctp, cli);
			if (cli->iofd)
				osmo_iofd_set_cmsg_size(cli->iofd, CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)));
		} else {
#else
		if (true) {
#endif
			cli->iofd = osmo_iofd_setup(cli, fd, cli->name, OSMO_IO_FD_MODE_READ_WRITE,
						    &osmo_stream_cli_ioops, cli);
		}
		if (!cli->iofd)
			goto error_close_socket;

		osmo_iofd_set_txqueue_max_length(cli->iofd, cli->tx_queue_max_length);
		osmo_iofd_notify_connected(cli->iofd);
		configure_cli_segmentation_cb(cli);

		if (osmo_iofd_register(cli->iofd, fd) < 0)
			goto error_close_socket;
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

/*! Enqueue data to be sent via an Osmocom stream client..
 *  This is the function you use for writing/sending/transmitting data via the osmo_stream_cli.
 *  \param[in] cli Stream Client through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg)
{
	int rc;

	OSMO_ASSERT(cli);
	OSMO_ASSERT(msg);

	if (!osmo_stream_cli_is_connected(cli)) {
		LOGSCLI(cli, LOGL_ERROR, "send: not connected, dropping data!\n");
		msgb_free(msg);
		return;
	}

	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		if (cli->tx_queue_count >= cli->tx_queue_max_length) {
			LOGSCLI(cli, LOGL_ERROR, "send: tx queue full, dropping msg!\n");
			msgb_free(msg);
			return;
		}
		msgb_enqueue_count(&cli->tx_queue, msg, &cli->tx_queue_count);
		osmo_fd_write_enable(&cli->ofd);
		break;
	case OSMO_STREAM_MODE_OSMO_IO:
		/* whenever osmo_stream_cli_is_connected() [see above check], we should have an iofd */
		OSMO_ASSERT(cli->iofd);
		if (cli->proto == IPPROTO_SCTP)
			rc = stream_iofd_sctp_send_msgb(cli->iofd, msg, MSG_NOSIGNAL);
		else
			rc = osmo_iofd_write_msgb(cli->iofd, msg);
		if (rc < 0)
			msgb_free(msg);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/*! Receive data via an Osmocom stream client in osmo_fd mode.
 *  \param[in] cli Stream Client through which we want to send
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read; <=0 in case of error
 *
 *  Application programs using the legacy osmo_fd mode of osmo_stream_cli will use
 *  this function to read/receive from a stream client socket after they have been notified that
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
int osmo_stream_cli_recv(struct osmo_stream_cli *cli, struct msgb *msg)
{
	int ret;
	OSMO_ASSERT(cli);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(cli->mode == OSMO_STREAM_MODE_OSMO_FD);

	switch (cli->sk_domain) {
	case AF_UNIX:
		ret = recv(cli->ofd.fd, msg->tail, msgb_tailroom(msg), 0);
		break;
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		switch (cli->proto) {
#ifdef HAVE_LIBSCTP
		case IPPROTO_SCTP:
		{
			char log_pfx[128];
			snprintf(log_pfx, sizeof(log_pfx), "CLICONN(%s,%s){%s}",
				 cli->name ? : "", cli->sockname,
				 get_value_string(stream_cli_state_names, cli->state));
			ret = stream_sctp_recvmsg_wrapper(cli->ofd.fd, msg, log_pfx);
			break;
		}
#endif
		case IPPROTO_TCP:
		default:
			ret = recv(cli->ofd.fd, msg->tail, msgb_tailroom(msg), 0);
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
			LOGSCLI(cli, LOGL_ERROR, "lost connection with srv (%d)\n", errno);
		else
			LOGSCLI(cli, LOGL_ERROR, "recv failed (%d)\n", errno);
		(void)stream_cli_reconnect(cli);
		return ret;
	} else if (ret == 0) {
		LOGSCLI(cli, LOGL_ERROR, "connection closed with srv\n");
		(void)stream_cli_reconnect(cli);
		return ret;
	}
	msgb_put(msg, ret);
	LOGSCLI(cli, LOGL_DEBUG, "received %d bytes from srv\n", ret);
	return ret;
}

/*! Clear the transmit queue of the stream client.
 *  Calling this function wil clear (delete) any pending, not-yet transmitted data from the transmit queue. */
void osmo_stream_cli_clear_tx_queue(struct osmo_stream_cli *cli)
{
	switch (cli->mode) {
	case OSMO_STREAM_MODE_OSMO_FD:
		msgb_queue_free(&cli->tx_queue);
		cli->tx_queue_count = 0;
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

/*! Set given parameter of stream client to given value.
 *  \param[in] cli stream client on which to set parameter.
 *  \param[in] par identifier of the parameter to be set.
 *  \param[in] val value of the parameter to be set.
 *  \param[in] val_len length of the parameter value.
 *  \returns 0 in success; negative -errno on error. */
int osmo_stream_cli_set_param(struct osmo_stream_cli *cli, enum osmo_stream_cli_param par, void *val, size_t val_len)
{
	OSMO_ASSERT(cli);
	uint8_t val8;

	switch (par) {
	case OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_AUTH_SUPPORTED:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		val8 = *(uint8_t *)val;
		cli->ma_pars.sctp.sockopt_auth_supported.set = true;
		cli->ma_pars.sctp.sockopt_auth_supported.abort_on_failure = val8 > 1;
		cli->ma_pars.sctp.sockopt_auth_supported.value = (val8 == 1 || val8 == 3) ? 1 : 0;
		break;
	case OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_ASCONF_SUPPORTED:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		val8 = *(uint8_t *)val;
		cli->ma_pars.sctp.sockopt_asconf_supported.set = true;
		cli->ma_pars.sctp.sockopt_asconf_supported.abort_on_failure = val8 > 1;
		cli->ma_pars.sctp.sockopt_asconf_supported.value = (val8 == 1 || val8 == 3) ? 1 : 0;
		break;
	case OSMO_STREAM_CLI_PAR_SCTP_INIT_NUM_OSTREAMS:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		cli->ma_pars.sctp.sockopt_initmsg.set = true;
		cli->ma_pars.sctp.sockopt_initmsg.num_ostreams_present = true;
		cli->ma_pars.sctp.sockopt_initmsg.num_ostreams_value = *(uint16_t *)val;
		break;
	case OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_INSTREAMS:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		cli->ma_pars.sctp.sockopt_initmsg.set = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_instreams_present = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_instreams_value = *(uint16_t *)val;
		break;
	case OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_ATTEMPTS:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		cli->ma_pars.sctp.sockopt_initmsg.set = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_attempts_present = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_attempts_value = *(uint16_t *)val;
		break;
	case OSMO_STREAM_CLI_PAR_SCTP_INIT_TIMEOUT:
		if (!val || val_len != sizeof(uint16_t))
			return -EINVAL;
		cli->ma_pars.sctp.sockopt_initmsg.set = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_init_timeo_present = true;
		cli->ma_pars.sctp.sockopt_initmsg.max_init_timeo_value = *(uint16_t *)val;
		break;
	/* TCP keepalive params: */
	case OSMO_STREAM_CLI_PAR_TCP_SOCKOPT_KEEPALIVE:
		if (!val || val_len != sizeof(uint8_t))
			return -EINVAL;
		cli->tcp_pars.ka.enable = !!*(uint8_t *)val;
		if (stream_cli_is_opened(cli))
			return stream_setsockopt_tcp_keepalive(osmo_stream_cli_get_fd(cli), cli->tcp_pars.ka.enable);
		break;
	case OSMO_STREAM_CLI_PAR_TCP_SOCKOPT_KEEPIDLE:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		cli->tcp_pars.ka.time_present = true;
		cli->tcp_pars.ka.time_value = *(int *)val;
		if (stream_cli_is_opened(cli))
			return stream_setsockopt_tcp_keepidle(osmo_stream_cli_get_fd(cli), cli->tcp_pars.ka.time_value);
		break;
	case OSMO_STREAM_CLI_PAR_TCP_SOCKOPT_KEEPINTVL:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		cli->tcp_pars.ka.intvl_present = true;
		cli->tcp_pars.ka.intvl_value = *(int *)val;
		if (stream_cli_is_opened(cli))
			return stream_setsockopt_tcp_keepintvl(osmo_stream_cli_get_fd(cli), cli->tcp_pars.ka.intvl_value);
		break;
	case OSMO_STREAM_CLI_PAR_TCP_SOCKOPT_KEEPCNT:
		if (!val || val_len != sizeof(int))
			return -EINVAL;
		cli->tcp_pars.ka.probes_present = true;
		cli->tcp_pars.ka.probes_value = *(int *)val;
		if (stream_cli_is_opened(cli))
			return stream_setsockopt_tcp_keepcnt(osmo_stream_cli_get_fd(cli), cli->tcp_pars.ka.probes_value);
		break;
	case OSMO_STREAM_CLI_PAR_TCP_SOCKOPT_USER_TIMEOUT:
		if (!val || val_len != sizeof(unsigned int))
			return -EINVAL;
		cli->tcp_pars.user_timeout_present = true;
		cli->tcp_pars.user_timeout_value = *(int *)val;
		if (stream_cli_is_opened(cli))
			return stream_setsockopt_tcp_user_timeout(osmo_stream_cli_get_fd(cli), cli->tcp_pars.user_timeout_value);
		break;
	default:
		return -ENOENT;
	};
	return 0;
}

/*! @} */
