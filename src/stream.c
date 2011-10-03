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

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/stream.h>

/*
 * Client side.
 */

enum stream_client_conn_state {
        STREAM_CLIENT_LINK_STATE_NONE         = 0,
        STREAM_CLIENT_LINK_STATE_CONNECTING   = 1,
        STREAM_CLIENT_LINK_STATE_CONNECTED    = 2,
        STREAM_CLIENT_LINK_STATE_MAX
};

struct stream_client_conn {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum stream_client_conn_state	state;
	const char			*addr;
	uint16_t			port;
	int (*connect_cb)(struct stream_client_conn *link);
	int (*read_cb)(struct stream_client_conn *link, struct msgb *msg);
	int (*write_cb)(struct stream_client_conn *link);
	void				*data;
};

static int stream_msg_recv(int fd, struct msgb *msg)
{
	int ret;

	ret = recv(fd, msg->data, msg->data_len, 0);
	if (ret <= 0)
		return ret;

	msgb_put(msg, ret);
	return ret;
}

void stream_client_conn_close(struct stream_client_conn *link);

static void stream_client_retry(struct stream_client_conn *link)
{
	LOGP(DLINP, LOGL_DEBUG, "connection closed\n");
	stream_client_conn_close(link);
	LOGP(DLINP, LOGL_DEBUG, "retrying in 5 seconds...\n");
	osmo_timer_schedule(&link->timer, 5, 0);
	link->state = STREAM_CLIENT_LINK_STATE_CONNECTING;
}

void stream_client_conn_close(struct stream_client_conn *link)
{
	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
}

static void stream_client_read(struct stream_client_conn *link)
{
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	msg = msgb_alloc(1200, "LAPD/client");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate room for message\n");
		return;
	}
	ret = stream_msg_recv(link->ofd.fd, msg);
	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		}
		stream_client_retry(link);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		stream_client_retry(link);
		return;
	}
	msgb_put(msg, ret);
	if (link->read_cb)
		link->read_cb(link, msg);
}

static int stream_client_write(struct stream_client_conn *link)
{
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&link->tx_queue)) {
		link->ofd.when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = link->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	if (link->state == STREAM_CLIENT_LINK_STATE_CONNECTING) {
		LOGP(DLINP, LOGL_ERROR, "not connected, dropping data!\n");
		return 0;
	}

	ret = send(link->ofd.fd, msg->data, msg->len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			stream_client_retry(link);
		}
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
	return 0;
}

static int stream_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct stream_client_conn *link = ofd->data;
	int error, ret;
	socklen_t len = sizeof(error);

	switch(link->state) {
	case STREAM_CLIENT_LINK_STATE_CONNECTING:
		ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (ret >= 0 && error > 0) {
			stream_client_retry(link);
			return 0;
		}
		ofd->when &= ~BSC_FD_WRITE;
		LOGP(DLINP, LOGL_DEBUG, "connection done.\n");
		link->state = STREAM_CLIENT_LINK_STATE_CONNECTED;
		if (link->connect_cb)
			link->connect_cb(link);
		break;
	case STREAM_CLIENT_LINK_STATE_CONNECTED:
		if (what & BSC_FD_READ) {
			LOGP(DLINP, LOGL_DEBUG, "connected read\n");
			stream_client_read(link);
		}
		if (what & BSC_FD_WRITE) {
			LOGP(DLINP, LOGL_DEBUG, "connected write\n");
			stream_client_write(link);
		}
		break;
	default:
		break;
	}
        return 0;
}

static void link_timer_cb(void *data);

struct stream_client_conn *stream_client_conn_create(void *ctx)
{
	struct stream_client_conn *link;

	link = talloc_zero(ctx, struct stream_client_conn);
	if (!link)
		return NULL;

	link->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
	link->ofd.priv_nr = 0;	/* XXX */
	link->ofd.cb = stream_client_fd_cb;
	link->ofd.data = link;
	link->state = STREAM_CLIENT_LINK_STATE_CONNECTING;
	link->timer.cb = link_timer_cb;
	link->timer.data = link;
	INIT_LLIST_HEAD(&link->tx_queue);

	return link;
}

void
stream_client_conn_set_addr(struct stream_client_conn *link, const char *addr)
{
	link->addr = talloc_strdup(link, addr);
}

void
stream_client_conn_set_port(struct stream_client_conn *link, uint16_t port)
{
	link->port = port;
}

void
stream_client_conn_set_data(struct stream_client_conn *link, void *data)
{
	link->data = data;
}

void
stream_client_conn_set_connect_cb(struct stream_client_conn *link,
			int (*connect_cb)(struct stream_client_conn *link))
{
	link->connect_cb = connect_cb;
}

void
stream_client_conn_set_read_cb(struct stream_client_conn *link,
	int (*read_cb)(struct stream_client_conn *link, struct msgb *msgb))
{
	link->read_cb = read_cb;
}

void stream_client_conn_destroy(struct stream_client_conn *link)
{
	talloc_free(link);
}

int stream_client_conn_open(struct stream_client_conn *link)
{
	int ret;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			     link->addr, link->port,
			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0) {
		if (errno != EINPROGRESS)
			return ret;
	}
	link->ofd.fd = ret;
	if (osmo_fd_register(&link->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

static void link_timer_cb(void *data)
{
	struct stream_client_conn *link = data;

	LOGP(DLINP, LOGL_DEBUG, "reconnecting.\n");

	switch(link->state) {
	case STREAM_CLIENT_LINK_STATE_CONNECTING:
		stream_client_conn_open(link);
	        break;
	default:
		break;
	}
}

void stream_client_conn_send(struct stream_client_conn *link, struct msgb *msg)
{
	msgb_enqueue(&link->tx_queue, msg);
	link->ofd.when |= BSC_FD_WRITE;
}

/*
 * Server side.
 */

struct stream_server_link {
        struct osmo_fd                  ofd;
        const char                      *addr;
        uint16_t                        port;
        int (*accept_cb)(struct stream_server_link *link, int fd);
        void                            *data;
};

static int stream_server_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int ret;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	struct stream_server_link *link = ofd->data;

	ret = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to accept from origin "
			"peer, reason=`%s'\n", strerror(errno));
		return ret;
	}
	LOGP(DLINP, LOGL_DEBUG, "accept()ed new link from %s to port %u\n",
		inet_ntoa(sa.sin_addr), link->port);

	if (link->accept_cb)
		link->accept_cb(link, ret);

	return 0;
}

struct stream_server_link *stream_server_link_create(void *ctx)
{
	struct stream_server_link *link;

	link = talloc_zero(ctx, struct stream_server_link);
	if (!link)
		return NULL;

	link->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
	link->ofd.cb = stream_server_fd_cb;
	link->ofd.data = link;

	return link;
}

void stream_server_link_set_addr(struct stream_server_link *link, const char *addr)
{
	link->addr = talloc_strdup(link, addr);
}

void stream_server_link_set_port(struct stream_server_link *link, uint16_t port)
{
	link->port = port;
}

void stream_server_link_set_accept_cb(struct stream_server_link *link,
		int (*accept_cb)(struct stream_server_link *link, int fd))

{
	link->accept_cb = accept_cb;
}

void stream_server_link_destroy(struct stream_server_link *link)
{
	talloc_free(link);
}

int stream_server_link_open(struct stream_server_link *link)
{
	int ret;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
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

void stream_server_link_close(struct stream_server_link *link)
{
	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
}

struct stream_server_conn {
	struct stream_server_link	*server;
        struct osmo_fd                  ofd;
        struct llist_head               tx_queue;
        int (*closed_cb)(struct stream_server_conn *peer);
        int (*cb)(struct stream_server_conn *peer, struct msgb *msg);
        void                            *data;
};

static void stream_server_conn_read(struct stream_server_conn *conn)
{
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	msg = msgb_alloc(1200, "LAPD/client");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate room for message\n");
		return;
	}
	ret = stream_msg_recv(conn->ofd.fd, msg);
	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		}
		stream_server_conn_destroy(conn);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		stream_server_conn_destroy(conn);
		return;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_NOTICE, "received %d bytes from client\n", ret);
	if (conn->cb)
		conn->cb(conn, msg);

	return;
}

static void stream_server_conn_write(struct stream_server_conn *conn)
{
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

	ret = send(conn->ofd.fd, msg->data, msg->len, 0);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
}

static int stream_server_conn_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct stream_server_conn *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write\n");
	if (what & BSC_FD_READ)
		stream_server_conn_read(conn);
	if (what & BSC_FD_WRITE)
		stream_server_conn_write(conn);

	return 0;
}

struct stream_server_conn *
stream_server_conn_create(void *ctx, struct stream_server_link *link, int fd,
		int (*cb)(struct stream_server_conn *conn, struct msgb *msg),
		int (*closed_cb)(struct stream_server_conn *conn), void *data)
{
	struct stream_server_conn *conn;

	conn = talloc_zero(ctx, struct stream_server_conn);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate new peer in server, "
			"reason=`%s'\n", strerror(errno));
		return NULL;
	}
	conn->server = link;
	conn->ofd.fd = fd;
	conn->ofd.data = conn;
	conn->ofd.cb = stream_server_conn_cb;
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

void stream_server_conn_destroy(struct stream_server_conn *conn)
{
	close(conn->ofd.fd);
	osmo_fd_unregister(&conn->ofd);
	if (conn->closed_cb)
		conn->closed_cb(conn);
	talloc_free(conn);
}

void stream_server_conn_send(struct stream_server_conn *conn, struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}
