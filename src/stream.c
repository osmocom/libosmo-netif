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

#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
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

static int sctp_sock_activate_events(int fd)
{
#ifdef HAVE_LIBSCTP
	struct sctp_event_subscribe event;
	int rc;

	/* subscribe for all events */
	memset((uint8_t *)&event, 1, sizeof(event));
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			&event, sizeof(event));

	return rc;
#else
	return -1;
#endif
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

#define OSMO_STREAM_CLI_F_RECONF	(1 << 0)

struct osmo_stream_cli {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum osmo_stream_cli_state	state;
	const char			*addr;
	uint16_t			port;
	uint16_t			proto;
	int (*connect_cb)(struct osmo_stream_cli *srv);
	int (*read_cb)(struct osmo_stream_cli *srv);
	int (*write_cb)(struct osmo_stream_cli *srv);
	void				*data;
	int				flags;
	int				reconnect_timeout;
};

void osmo_stream_cli_close(struct osmo_stream_cli *cli);

static void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli)
{
	if (cli->reconnect_timeout < 0) {
		LOGP(DLINP, LOGL_DEBUG, "not reconnecting, disabled.\n");
		return;
	}
	LOGP(DLINP, LOGL_DEBUG, "connection closed\n");
	osmo_stream_cli_close(cli);
	LOGP(DLINP, LOGL_DEBUG, "retrying in %d seconds...\n",
		cli->reconnect_timeout);
	osmo_timer_schedule(&cli->timer, cli->reconnect_timeout, 0);
	cli->state = STREAM_CLI_STATE_CONNECTING;
}

void osmo_stream_cli_close(struct osmo_stream_cli *cli)
{
	osmo_fd_unregister(&cli->ofd);
	close(cli->ofd.fd);
}

static void osmo_stream_cli_read(struct osmo_stream_cli *cli)
{
	LOGP(DLINP, LOGL_DEBUG, "message received\n");

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

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&cli->tx_queue)) {
		cli->ofd.when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = cli->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	if (cli->state == STREAM_CLI_STATE_CONNECTING) {
		LOGP(DLINP, LOGL_ERROR, "not connected, dropping data!\n");
		return 0;
	}

	switch (cli->proto) {
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.sinfo_ppid = htonl(msgb_sctp_ppid(msg));
		sinfo.sinfo_stream = htonl(msgb_sctp_stream(msg));
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
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
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
		LOGP(DLINP, LOGL_DEBUG, "connection done.\n");
		cli->state = STREAM_CLI_STATE_CONNECTED;
		if (cli->proto == IPPROTO_SCTP)
			sctp_sock_activate_events(ofd->fd);
		if (cli->connect_cb)
			cli->connect_cb(cli);
		break;
	case STREAM_CLI_STATE_CONNECTED:
		if (what & BSC_FD_READ) {
			LOGP(DLINP, LOGL_DEBUG, "connected read\n");
			osmo_stream_cli_read(cli);
		}
		if (what & BSC_FD_WRITE) {
			LOGP(DLINP, LOGL_DEBUG, "connected write\n");
			osmo_stream_cli_write(cli);
		}
		break;
	default:
		break;
	}
        return 0;
}

static void cli_timer_cb(void *data);

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
	cli->timer.cb = cli_timer_cb;
	cli->timer.data = cli;
	cli->reconnect_timeout = 5;	/* default is 5 seconds. */
	INIT_LLIST_HEAD(&cli->tx_queue);

	return cli;
}

void
osmo_stream_cli_set_addr(struct osmo_stream_cli *cli, const char *addr)
{
	cli->addr = talloc_strdup(cli, addr);
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

void
osmo_stream_cli_set_port(struct osmo_stream_cli *cli, uint16_t port)
{
	cli->port = port;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

void
osmo_stream_cli_set_proto(struct osmo_stream_cli *cli, uint16_t proto)
{
	cli->proto = proto;
	cli->flags |= OSMO_STREAM_CLI_F_RECONF;
}

void
osmo_stream_cli_set_reconnect_timeout(struct osmo_stream_cli *cli, int timeout)
{
	cli->reconnect_timeout = timeout;
}

void
osmo_stream_cli_set_data(struct osmo_stream_cli *cli, void *data)
{
	cli->data = data;
}

void *osmo_stream_cli_get_data(struct osmo_stream_cli *cli)
{
	return cli->data;
}

struct osmo_fd *
osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli)
{
	return &cli->ofd;
}

void
osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli,
	int (*connect_cb)(struct osmo_stream_cli *cli))
{
	cli->connect_cb = connect_cb;
}

void
osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli,
			    int (*read_cb)(struct osmo_stream_cli *cli))
{
	cli->read_cb = read_cb;
}

void osmo_stream_cli_destroy(struct osmo_stream_cli *cli)
{
	talloc_free(cli);
}

int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((cli->flags & OSMO_STREAM_CLI_F_RECONF) && cli->ofd.fd >= 0)
		osmo_stream_cli_close(cli);

	cli->flags &= ~OSMO_STREAM_CLI_F_RECONF;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, cli->proto,
			     cli->addr, cli->port,
			     OSMO_SOCK_F_CONNECT);
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			if (reconnect) {
				osmo_timer_schedule(&cli->timer, cli->reconnect_timeout, 0);
				cli->state = STREAM_CLI_STATE_CONNECTING;
				return 0;
			} else
				return ret;
		}
	}
	cli->ofd.fd = ret;
	if (osmo_fd_register(&cli->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}


int osmo_stream_cli_open(struct osmo_stream_cli *cli)
{
	return osmo_stream_cli_open2(cli, 0);
}

static void cli_timer_cb(void *data)
{
	struct osmo_stream_cli *cli = data;

	LOGP(DLINP, LOGL_DEBUG, "reconnecting.\n");

	switch(cli->state) {
	case STREAM_CLI_STATE_CONNECTING:
		osmo_stream_cli_open2(cli, 1);
	        break;
	default:
		break;
	}
}

void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg)
{
	msgb_enqueue(&cli->tx_queue, msg);
	cli->ofd.when |= BSC_FD_WRITE;
}

int osmo_stream_cli_recv(struct osmo_stream_cli *cli, struct msgb *msg)
{
	int ret;

	ret = recv(cli->ofd.fd, msg->data, msg->data_len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR,
				"lost connection with srv\n");
		}
		osmo_stream_cli_reconnect(cli);
		return ret;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with srv\n");
		osmo_stream_cli_reconnect(cli);
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from srv\n", ret);
	return ret;
}

/*
 * Server side.
 */

#define OSMO_STREAM_SRV_F_RECONF	(1 << 0)

struct osmo_stream_srv_link {
        struct osmo_fd                  ofd;
        const char                      *addr;
        uint16_t                        port;
        uint16_t                        proto;
        int (*accept_cb)(struct osmo_stream_srv_link *srv, int fd);
        void                            *data;
	int				flags;
};

static int osmo_stream_srv_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int ret;
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

	if (link->proto == IPPROTO_SCTP)
		sctp_sock_activate_events(ret);

	if (link->accept_cb)
		link->accept_cb(link, ret);

	return 0;
}

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

void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link,
				      const char *addr)
{
	link->addr = talloc_strdup(link, addr);
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}

void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link,
				      uint16_t port)
{
	link->port = port;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}

void
osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link,
			  uint16_t proto)
{
	link->proto = proto;
	link->flags |= OSMO_STREAM_SRV_F_RECONF;
}

void
osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link,
				 void *data)
{
	link->data = data;
}

void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link)
{
	return link->data;
}

struct osmo_fd *
osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link)
{
	return &link->ofd;
}

void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link,
	int (*accept_cb)(struct osmo_stream_srv_link *link, int fd))

{
	link->accept_cb = accept_cb;
}

void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link)
{
	talloc_free(link);
}

int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((link->flags & OSMO_STREAM_SRV_F_RECONF) && link->ofd.fd >= 0)
		osmo_stream_srv_link_close(link);

	link->flags &= ~OSMO_STREAM_SRV_F_RECONF;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, link->proto,
			     link->addr, link->port, OSMO_SOCK_F_BIND);
	if (ret < 0)
		return ret;

	link->ofd.fd = ret;
	if (osmo_fd_register(&link->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link)
{
	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
}

struct osmo_stream_srv {
	struct osmo_stream_srv_link	*srv;
        struct osmo_fd                  ofd;
        struct llist_head               tx_queue;
        int (*closed_cb)(struct osmo_stream_srv *peer);
        int (*cb)(struct osmo_stream_srv *peer);
        void                            *data;
};

static void osmo_stream_srv_read(struct osmo_stream_srv *conn)
{
	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	if (conn->cb)
		conn->cb(conn);

	return;
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
		sinfo.sinfo_stream = htonl(msgb_sctp_stream(msg));
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
}

static int osmo_stream_srv_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_stream_srv *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write\n");
	if (what & BSC_FD_READ)
		osmo_stream_srv_read(conn);
	if (what & BSC_FD_WRITE)
		osmo_stream_srv_write(conn);

	return 0;
}

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

void
osmo_stream_srv_set_data(struct osmo_stream_srv *conn,
				 void *data)
{
	conn->data = data;
}

void *osmo_stream_srv_get_data(struct osmo_stream_srv *link)
{
	return link->data;
}

struct osmo_fd *
osmo_stream_srv_get_ofd(struct osmo_stream_srv *link)
{
	return &link->ofd;
}

struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn)
{
	return conn->srv;
}

void osmo_stream_srv_destroy(struct osmo_stream_srv *conn)
{
	close(conn->ofd.fd);
	osmo_fd_unregister(&conn->ofd);
	if (conn->closed_cb)
		conn->closed_cb(conn);
	talloc_free(conn);
}

void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

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
		msgb_sctp_stream(msg) = ntohl(sinfo.sinfo_stream);
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
