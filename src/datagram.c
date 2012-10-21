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

#define OSMO_DGRAM_CLI_F_RECONF	(1 << 0)

struct osmo_dgram_tx {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	const char			*addr;
	uint16_t			port;
	int (*write_cb)(struct osmo_dgram_tx *conn);
	void				*data;
	unsigned int			flags;
};

void osmo_dgram_tx_close(struct osmo_dgram_tx *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

static int osmo_dgram_tx_write(struct osmo_dgram_tx *conn)
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

static int osmo_dgram_tx_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_tx *conn = ofd->data;

	if (what & BSC_FD_WRITE) {
		LOGP(DLINP, LOGL_DEBUG, "write\n");
		osmo_dgram_tx_write(conn);
	}
        return 0;
}

struct osmo_dgram_tx *osmo_dgram_tx_create(void *crx)
{
	struct osmo_dgram_tx *conn;

	conn = talloc_zero(crx, struct osmo_dgram_tx);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.priv_nr = 0;	/* XXX */
	conn->ofd.cb = osmo_dgram_tx_fd_cb;
	conn->ofd.data = conn;
	INIT_LLIST_HEAD(&conn->tx_queue);

	return conn;
}

void
osmo_dgram_tx_set_addr(struct osmo_dgram_tx *conn,
				const char *addr)
{
	if (conn->addr != NULL)
		talloc_free((void *)conn->addr);

	conn->addr = talloc_strdup(conn, addr);
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

void
osmo_dgram_tx_set_port(struct osmo_dgram_tx *conn,
				uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

void
osmo_dgram_tx_set_data(struct osmo_dgram_tx *conn, void *data)
{
	conn->data = data;
}

void osmo_dgram_tx_destroy(struct osmo_dgram_tx *conn)
{
	talloc_free(conn);
}

int osmo_dgram_tx_open(struct osmo_dgram_tx *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_CLI_F_RECONF) && conn->ofd.fd >= 0)
		osmo_dgram_tx_close(conn);

	conn->flags &= ~OSMO_DGRAM_CLI_F_RECONF;

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

void osmo_dgram_tx_send(struct osmo_dgram_tx *conn,
				 struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

/*
 * Server side.
 */

#define OSMO_DGRAM_RX_F_RECONF	(1 << 0)

struct osmo_dgram_rx {
        struct osmo_fd                  ofd;
        const char                      *addr;
        uint16_t                        port;
	int (*cb)(struct osmo_dgram_rx *conn);
        void                            *data;
	unsigned int			flags;
};

int osmo_dgram_rx_recv(struct osmo_dgram_rx *conn,
				struct msgb *msg)
{
	int ret;

	ret = recv(conn->ofd.fd, msg->data, msg->data_len, 0);
	if (ret <= 0) {
		LOGP(DLINP, LOGL_ERROR, "error receiving data from tx\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from tx\n", ret);
	return ret;
}

static void osmo_dgram_rx_read(struct osmo_dgram_rx *conn)
{
	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	if (conn->cb)
		conn->cb(conn);
}

static int osmo_dgram_rx_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_rx *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "read\n");
	if (what & BSC_FD_READ)
		osmo_dgram_rx_read(conn);

	return 0;
}

struct osmo_dgram_rx *osmo_dgram_rx_create(void *crx)
{
	struct osmo_dgram_rx *conn;

	conn = talloc_zero(crx, struct osmo_dgram_rx);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.cb = osmo_dgram_rx_cb;
	conn->ofd.data = conn;

	return conn;
}

void osmo_dgram_rx_set_addr(struct osmo_dgram_rx *conn,
				     const char *addr)
{
	if (conn->addr != NULL)
		talloc_free((void *)conn->addr);

	conn->addr = talloc_strdup(conn, addr);
	conn->flags |= OSMO_DGRAM_RX_F_RECONF;
}

void osmo_dgram_rx_set_port(struct osmo_dgram_rx *conn,
				     uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_RX_F_RECONF;
}

void osmo_dgram_rx_set_read_cb(struct osmo_dgram_rx *conn,
	int (*read_cb)(struct osmo_dgram_rx *conn))
{
	conn->cb = read_cb;
}

void osmo_dgram_rx_destroy(struct osmo_dgram_rx *conn)
{
	talloc_free(conn);
}

int osmo_dgram_rx_open(struct osmo_dgram_rx *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_RX_F_RECONF) && conn->ofd.fd >= 0)
		osmo_dgram_rx_close(conn);

	conn->flags &= ~OSMO_DGRAM_RX_F_RECONF;

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

void osmo_dgram_rx_close(struct osmo_dgram_rx *conn)
{
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
}

/*
 * Client+Server (bidirectional communications).
 */

struct osmo_dgram {
	struct osmo_dgram_rx	*rx;
	struct osmo_dgram_tx	*tx;
	int (*read_cb)(struct osmo_dgram *conn);
	void				*data;
};

static int
dgram_rx_cb(struct osmo_dgram_rx *rx)
{
	struct osmo_dgram *conn = rx->data;

	if (conn->read_cb)
		return conn->read_cb(conn);

	return 0;
}

struct osmo_dgram *osmo_dgram_create(void *crx)
{
	struct osmo_dgram *conn;

	conn = talloc_zero(crx, struct osmo_dgram);
	if (!conn)
		return NULL;

	conn->rx= osmo_dgram_rx_create(crx);
	if (conn->rx == NULL)
		return NULL;

	osmo_dgram_rx_set_read_cb(conn->rx, dgram_rx_cb);
	conn->rx->data = conn;

	conn->tx = osmo_dgram_tx_create(crx);
	if (conn->tx == NULL) {
		osmo_dgram_rx_destroy(conn->rx);
		return NULL;
	}

	return conn;
}

void osmo_dgram_destroy(struct osmo_dgram *conn)
{
	osmo_dgram_rx_destroy(conn->rx);
	osmo_dgram_tx_destroy(conn->tx);
}

void
osmo_dgram_set_local_addr(struct osmo_dgram *conn, const char *addr)
{
	osmo_dgram_rx_set_addr(conn->rx, addr);
}

void
osmo_dgram_set_remote_addr(struct osmo_dgram *conn, const char *addr)
{
	osmo_dgram_tx_set_addr(conn->tx, addr);
}

void
osmo_dgram_set_local_port(struct osmo_dgram *conn, uint16_t port)
{
	osmo_dgram_rx_set_port(conn->rx, port);
}

void
osmo_dgram_set_remote_port(struct osmo_dgram *conn, uint16_t port)
{
	osmo_dgram_tx_set_port(conn->tx, port);
}

void osmo_dgram_set_read_cb(struct osmo_dgram *conn,
			    int (*read_cb)(struct osmo_dgram *conn))
{
	conn->read_cb = read_cb;
}

void osmo_dgram_set_data(struct osmo_dgram *conn, void *data)
{
	conn->data = data;
}

void *osmo_dgram_get_data(struct osmo_dgram *conn)
{
	return conn->data;
}

int osmo_dgram_open(struct osmo_dgram *conn)
{
	int ret;

	ret = osmo_dgram_rx_open(conn->rx);
	if (ret < 0)
		return ret;

	ret = osmo_dgram_tx_open(conn->tx);
	if (ret < 0) {
		osmo_dgram_rx_close(conn->rx);
		return ret;
	}
	return ret;
}

void osmo_dgram_close(struct osmo_dgram *conn)
{
	osmo_dgram_rx_close(conn->rx);
	osmo_dgram_tx_close(conn->tx);
}

void osmo_dgram_send(struct osmo_dgram *conn, struct msgb *msg)
{
	osmo_dgram_tx_send(conn->tx, msg);
}

int osmo_dgram_recv(struct osmo_dgram *conn, struct msgb *msg)
{
	return osmo_dgram_rx_recv(conn->rx, msg);
}
