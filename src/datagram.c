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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/datagram.h>

/*
 * Client side.
 */

struct datagram_client_conn {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	const char			*addr;
	uint16_t			port;
	int (*write_cb)(struct datagram_client_conn *conn);
	void				*data;
};

void datagram_client_conn_close(struct datagram_client_conn *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

static int datagram_client_write(struct datagram_client_conn *conn)
{
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&conn->tx_queue)) {
		conn->ofd.when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = conn->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(conn->ofd.fd, msg->data, msg->len, 0);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "error to send (%s)\n",
			strerror(errno));
	}
	msgb_free(msg);
	return 0;
}

static int datagram_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct datagram_client_conn *conn = ofd->data;

	if (what & BSC_FD_WRITE) {
		LOGP(DLINP, LOGL_DEBUG, "connected write\n");
		datagram_client_write(conn);
	}
        return 0;
}

struct datagram_client_conn *datagram_client_conn_create(void *ctx)
{
	struct datagram_client_conn *conn;

	conn = talloc_zero(ctx, struct datagram_client_conn);
	if (!conn)
		return NULL;

	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.priv_nr = 0;	/* XXX */
	conn->ofd.cb = datagram_client_fd_cb;
	conn->ofd.data = conn;
	INIT_LLIST_HEAD(&conn->tx_queue);

	return conn;
}

void
datagram_client_conn_set_addr(struct datagram_client_conn *conn, const char *addr)
{
	conn->addr = talloc_strdup(conn, addr);
}

void
datagram_client_conn_set_port(struct datagram_client_conn *conn, uint16_t port)
{
	conn->port = port;
}

void
datagram_client_conn_set_data(struct datagram_client_conn *conn, void *data)
{
	conn->data = data;
}

void datagram_client_conn_destroy(struct datagram_client_conn *conn)
{
	talloc_free(conn);
}

int datagram_client_conn_open(struct datagram_client_conn *conn)
{
	int ret;

	ret = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			     conn->addr, conn->port,
			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0) {
		if (errno != EINPROGRESS)
			return ret;
	}
	conn->ofd.fd = ret;
	if (osmo_fd_register(&conn->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

void datagram_client_conn_send(struct datagram_client_conn *conn, struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

/*
 * Server side.
 */

struct datagram_server_conn {
        struct osmo_fd                  ofd;
        const char                      *addr;
        uint16_t                        port;
	int (*cb)(struct datagram_server_conn *conn, struct msgb *msg);
        void                            *data;
};

static void datagram_server_conn_read(struct datagram_server_conn *conn)
{
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	msg = msgb_alloc(1200, "LAPD/client");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate room for message\n");
		return;
	}
	ret = recv(conn->ofd.fd, msg->data, msg->data_len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ECONNRESET) {
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		}
		datagram_server_conn_destroy(conn);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		datagram_server_conn_destroy(conn);
		return;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_NOTICE, "received %d bytes from client\n", ret);
	if (conn->cb)
		conn->cb(conn, msg);

	return;
}

static int datagram_server_conn_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct datagram_server_conn *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write\n");
	if (what & BSC_FD_READ)
		datagram_server_conn_read(conn);

	return 0;
}

struct datagram_server_conn *datagram_server_conn_create(void *ctx)
{
	struct datagram_server_conn *conn;

	conn = talloc_zero(ctx, struct datagram_server_conn);
	if (!conn)
		return NULL;

	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.cb = datagram_server_conn_cb;
	conn->ofd.data = conn;

	return conn;
}

void datagram_server_conn_set_addr(struct datagram_server_conn *conn, const char *addr)
{
	conn->addr = talloc_strdup(conn, addr);
}

void datagram_server_conn_set_port(struct datagram_server_conn *conn, uint16_t port)
{
	conn->port = port;
}

void datagram_server_conn_set_read_cb(struct datagram_server_conn *conn,
	int (*read_cb)(struct datagram_server_conn *conn, struct msgb *msg))
{
	conn->cb = read_cb;
}

void datagram_server_conn_destroy(struct datagram_server_conn *conn)
{
	talloc_free(conn);
}

int datagram_server_conn_open(struct datagram_server_conn *conn)
{
	int ret;

	ret = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			     conn->addr, conn->port, OSMO_SOCK_F_BIND);
	if (ret < 0)
		return ret;

	conn->ofd.fd = ret;
	if (osmo_fd_register(&conn->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

void datagram_server_conn_close(struct datagram_server_conn *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

/*
 * Client+Server (bidirectional communications).
 */

struct datagram_conn {
	struct datagram_server_conn	*server;
	struct datagram_client_conn	*client;
	void				*data;
};

struct datagram_conn *datagram_conn_create(void *ctx)
{
	struct datagram_conn *conn;

	conn = talloc_zero(ctx, struct datagram_conn);
	if (!conn)
		return NULL;

	conn->server = datagram_server_conn_create(ctx);
	if (conn->server == NULL)
		return NULL;

	conn->client = datagram_client_conn_create(ctx);
	if (conn->client == NULL) {
		datagram_server_conn_destroy(conn->server);
		return NULL;
	}

	return conn;
}

void datagram_conn_destroy(struct datagram_conn *conn)
{
	datagram_server_conn_destroy(conn->server);
	datagram_client_conn_destroy(conn->client);
}

void
datagram_conn_set_local_addr(struct datagram_conn *conn, const char *addr)
{
	datagram_server_conn_set_addr(conn->server, addr);
}

void
datagram_conn_set_remote_addr(struct datagram_conn *conn, const char *addr)
{
	datagram_client_conn_set_addr(conn->client, addr);
}

void
datagram_conn_set_local_port(struct datagram_conn *conn, uint16_t port)
{
	datagram_server_conn_set_port(conn->server, port);
}

void
datagram_conn_set_remote_port(struct datagram_conn *conn, uint16_t port)
{
	datagram_client_conn_set_port(conn->client, port);
}

void datagram_conn_set_read_cb(struct datagram_conn *conn,
	int (*read_cb)(struct datagram_server_conn *conn, struct msgb *msg))
{
	conn->server->cb = read_cb;
}

void
datagram_conn_set_data(struct datagram_client_conn *conn, void *data)
{
	conn->data = data;
}

int datagram_conn_open(struct datagram_conn *conn)
{
	int ret;

	ret = datagram_server_conn_open(conn->server);
	if (ret < 0)
		return ret;

	ret = datagram_client_conn_open(conn->client);
	if (ret < 0) {
		datagram_server_conn_close(conn->server);
		return ret;
	}
	return ret;
}

void datagram_conn_close(struct datagram_conn *conn)
{
	datagram_server_conn_close(conn->server);
	datagram_client_conn_close(conn->client);
}

void datagram_conn_send(struct datagram_conn *conn, struct msgb *msg)
{
	datagram_client_conn_send(conn->client, msg);
}
