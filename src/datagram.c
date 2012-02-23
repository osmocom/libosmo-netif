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

#define OSMO_DGRAM_CLIENT_F_RECONFIG	(1 << 0)

struct osmo_dgram_client_conn {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	const char			*addr;
	uint16_t			port;
	int (*write_cb)(struct osmo_dgram_client_conn *conn);
	void				*data;
	unsigned int			flags;
};

void osmo_dgram_client_conn_close(struct osmo_dgram_client_conn *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

static int osmo_dgram_client_write(struct osmo_dgram_client_conn *conn)
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

static int osmo_dgram_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_client_conn *conn = ofd->data;

	if (what & BSC_FD_WRITE) {
		LOGP(DLINP, LOGL_DEBUG, "write\n");
		osmo_dgram_client_write(conn);
	}
        return 0;
}

struct osmo_dgram_client_conn *osmo_dgram_client_conn_create(void *ctx)
{
	struct osmo_dgram_client_conn *conn;

	conn = talloc_zero(ctx, struct osmo_dgram_client_conn);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.priv_nr = 0;	/* XXX */
	conn->ofd.cb = osmo_dgram_client_fd_cb;
	conn->ofd.data = conn;
	INIT_LLIST_HEAD(&conn->tx_queue);

	return conn;
}

void
osmo_dgram_client_conn_set_addr(struct osmo_dgram_client_conn *conn,
				const char *addr)
{
	if (conn->addr != NULL)
		talloc_free((void *)conn->addr);

	conn->addr = talloc_strdup(conn, addr);
	conn->flags |= OSMO_DGRAM_CLIENT_F_RECONFIG;
}

void
osmo_dgram_client_conn_set_port(struct osmo_dgram_client_conn *conn,
				uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_CLIENT_F_RECONFIG;
}

void
osmo_dgram_client_conn_set_data(struct osmo_dgram_client_conn *conn, void *data)
{
	conn->data = data;
}

void osmo_dgram_client_conn_destroy(struct osmo_dgram_client_conn *conn)
{
	talloc_free(conn);
}

int osmo_dgram_client_conn_open(struct osmo_dgram_client_conn *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_CLIENT_F_RECONFIG) && conn->ofd.fd >= 0)
		osmo_dgram_client_conn_close(conn);

	conn->flags &= ~OSMO_DGRAM_CLIENT_F_RECONFIG;

	ret = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			     conn->addr, conn->port,
			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0)
		return ret;

	conn->ofd.fd = ret;
	if (osmo_fd_register(&conn->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

void osmo_dgram_client_conn_send(struct osmo_dgram_client_conn *conn,
				 struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

/*
 * Server side.
 */

#define OSMO_DGRAM_SERVER_F_RECONFIG	(1 << 0)

struct osmo_dgram_server_conn {
        struct osmo_fd                  ofd;
        const char                      *addr;
        uint16_t                        port;
	int (*cb)(struct osmo_dgram_server_conn *conn);
        void                            *data;
	unsigned int			flags;
};

int osmo_dgram_server_conn_recv(struct osmo_dgram_server_conn *conn,
				struct msgb *msg)
{
	int ret;

	ret = recv(conn->ofd.fd, msg->data, msg->data_len, 0);
	if (ret <= 0) {
		LOGP(DLINP, LOGL_ERROR, "error receiving data from client\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from client\n", ret);
	return ret;
}

static void osmo_dgram_server_conn_read(struct osmo_dgram_server_conn *conn)
{
	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	if (conn->cb)
		conn->cb(conn);
}

static int osmo_dgram_server_conn_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_server_conn *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "read\n");
	if (what & BSC_FD_READ)
		osmo_dgram_server_conn_read(conn);

	return 0;
}

struct osmo_dgram_server_conn *osmo_dgram_server_conn_create(void *ctx)
{
	struct osmo_dgram_server_conn *conn;

	conn = talloc_zero(ctx, struct osmo_dgram_server_conn);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.cb = osmo_dgram_server_conn_cb;
	conn->ofd.data = conn;

	return conn;
}

void osmo_dgram_server_conn_set_addr(struct osmo_dgram_server_conn *conn,
				     const char *addr)
{
	if (conn->addr != NULL)
		talloc_free((void *)conn->addr);

	conn->addr = talloc_strdup(conn, addr);
	conn->flags |= OSMO_DGRAM_SERVER_F_RECONFIG;
}

void osmo_dgram_server_conn_set_port(struct osmo_dgram_server_conn *conn,
				     uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_SERVER_F_RECONFIG;
}

void osmo_dgram_server_conn_set_read_cb(struct osmo_dgram_server_conn *conn,
	int (*read_cb)(struct osmo_dgram_server_conn *conn))
{
	conn->cb = read_cb;
}

void osmo_dgram_server_conn_destroy(struct osmo_dgram_server_conn *conn)
{
	talloc_free(conn);
}

int osmo_dgram_server_conn_open(struct osmo_dgram_server_conn *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_SERVER_F_RECONFIG) && conn->ofd.fd >= 0)
		osmo_dgram_server_conn_close(conn);

	conn->flags &= ~OSMO_DGRAM_SERVER_F_RECONFIG;

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

void osmo_dgram_server_conn_close(struct osmo_dgram_server_conn *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

/*
 * Client+Server (bidirectional communications).
 */

struct osmo_dgram_conn {
	struct osmo_dgram_server_conn	*server;
	struct osmo_dgram_client_conn	*client;
	int (*read_cb)(struct osmo_dgram_conn *conn);
	void				*data;
};

static int
dgram_server_conn_cb(struct osmo_dgram_server_conn *server)
{
	struct osmo_dgram_conn *conn = server->data;

	if (conn->read_cb)
		return conn->read_cb(conn);

	return 0;
}

struct osmo_dgram_conn *osmo_dgram_conn_create(void *ctx)
{
	struct osmo_dgram_conn *conn;

	conn = talloc_zero(ctx, struct osmo_dgram_conn);
	if (!conn)
		return NULL;

	conn->server = osmo_dgram_server_conn_create(ctx);
	if (conn->server == NULL)
		return NULL;

	osmo_dgram_server_conn_set_read_cb(conn->server, dgram_server_conn_cb);
	conn->server->data = conn;

	conn->client = osmo_dgram_client_conn_create(ctx);
	if (conn->client == NULL) {
		osmo_dgram_server_conn_destroy(conn->server);
		return NULL;
	}

	return conn;
}

void osmo_dgram_conn_destroy(struct osmo_dgram_conn *conn)
{
	osmo_dgram_server_conn_destroy(conn->server);
	osmo_dgram_client_conn_destroy(conn->client);
}

void
osmo_dgram_conn_set_local_addr(struct osmo_dgram_conn *conn, const char *addr)
{
	osmo_dgram_server_conn_set_addr(conn->server, addr);
}

void
osmo_dgram_conn_set_remote_addr(struct osmo_dgram_conn *conn, const char *addr)
{
	osmo_dgram_client_conn_set_addr(conn->client, addr);
}

void
osmo_dgram_conn_set_local_port(struct osmo_dgram_conn *conn, uint16_t port)
{
	osmo_dgram_server_conn_set_port(conn->server, port);
}

void
osmo_dgram_conn_set_remote_port(struct osmo_dgram_conn *conn, uint16_t port)
{
	osmo_dgram_client_conn_set_port(conn->client, port);
}

void osmo_dgram_conn_set_read_cb(struct osmo_dgram_conn *conn,
	int (*read_cb)(struct osmo_dgram_conn *conn))
{
	conn->read_cb = read_cb;
}

void
osmo_dgram_conn_set_data(struct osmo_dgram_client_conn *conn, void *data)
{
	conn->data = data;
}

int osmo_dgram_conn_open(struct osmo_dgram_conn *conn)
{
	int ret;

	ret = osmo_dgram_server_conn_open(conn->server);
	if (ret < 0)
		return ret;

	ret = osmo_dgram_client_conn_open(conn->client);
	if (ret < 0) {
		osmo_dgram_server_conn_close(conn->server);
		return ret;
	}
	return ret;
}

void osmo_dgram_conn_close(struct osmo_dgram_conn *conn)
{
	osmo_dgram_server_conn_close(conn->server);
	osmo_dgram_client_conn_close(conn->client);
}

void osmo_dgram_conn_send(struct osmo_dgram_conn *conn, struct msgb *msg)
{
	osmo_dgram_client_conn_send(conn->client, msg);
}

int osmo_dgram_conn_recv(struct osmo_dgram_conn *conn, struct msgb *msg)
{
	return osmo_dgram_server_conn_recv(conn->server, msg);
}
