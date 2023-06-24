#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/msgb.h>

/*! \addtogroup stream
 *  @{
 */

/*! \brief Access SCTP flags from the msgb control buffer */
#define OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION 0x80 /* sctp_recvmsg() flags=MSG_NOTIFICATION, msgb_data() contains "union sctp_notification*" */
#define msgb_sctp_msg_flags(msg)	(msg)->cb[2]

/*! \brief Access the SCTP PPID from the msgb control buffer */
#define msgb_sctp_ppid(msg)             (msg)->cb[3]
/*! \brief Access the SCTP Stream ID from the msgb control buffer */
#define msgb_sctp_stream(msg)           (msg)->cb[4]

/*! \brief Osmocom Stream Server Link: A server socket listening/accepting */
struct osmo_stream_srv_link;

struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx);
void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link);

void osmo_stream_srv_link_set_name(struct osmo_stream_srv_link *link, const char *name);
void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay);
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link, const char *addr);
int osmo_stream_srv_link_set_addrs(struct osmo_stream_srv_link *link, const char **addr, size_t addrcnt);
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link, uint16_t port);
void osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link, uint16_t proto);
int osmo_stream_srv_link_set_type(struct osmo_stream_srv_link *link, int type);
int osmo_stream_srv_link_set_domain(struct osmo_stream_srv_link *link, int domain);
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link, int (*accept_cb)(struct osmo_stream_srv_link *link, int fd));
void osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link, void *data);
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link);
char *osmo_stream_srv_link_get_sockname(const struct osmo_stream_srv_link *link);
struct osmo_fd *osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link);
bool osmo_stream_srv_link_is_opened(const struct osmo_stream_srv_link *link);
int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link);
void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link);

enum osmo_stream_srv_link_param {
	OSMO_STREAM_SRV_LINK_PAR_SCTP_SOCKOPT_AUTH_SUPPORTED, /* uint8_t: 0 disable, 1 enable, 2 force disable, 3 force enable */
	OSMO_STREAM_SRV_LINK_PAR_SCTP_SOCKOPT_ASCONF_SUPPORTED, /* uint8_t: 0 disable, 1 enable, 2 force disable, 3 force enable */
	OSMO_STREAM_SRV_LINK_PAR_SCTP_INIT_NUM_OSTREAMS, /* uint16_t: amount of streams */
	OSMO_STREAM_SRV_LINK_PAR_SCTP_INIT_MAX_INSTREAMS, /* uint16_t: amount of streams */
};

int osmo_stream_srv_link_set_param(struct osmo_stream_srv_link *link, enum osmo_stream_srv_link_param par,
				   void *val, size_t val_len);

/*! \brief Osmocom Stream Server: Single connection accept()ed via \ref
 * osmo_stream_srv_link */
struct osmo_stream_srv;

struct osmo_stream_srv *osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link, int fd, int (*read_cb)(struct osmo_stream_srv *conn), int (*closed_cb)(struct osmo_stream_srv *conn), void *data);
struct osmo_stream_srv *osmo_stream_srv_create2(void *ctx, struct osmo_stream_srv_link *link, int fd, void *data);
void osmo_stream_srv_set_name(struct osmo_stream_srv *conn, const char *name);
void osmo_stream_srv_set_read_cb(struct osmo_stream_srv *conn, int (*read_cb)(struct osmo_stream_srv *conn, struct msgb *msg));
void osmo_stream_srv_set_closed_cb(struct osmo_stream_srv *conn, int (*closed_cb)(struct osmo_stream_srv *conn));
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn);
struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn);
struct osmo_fd *osmo_stream_srv_get_ofd(struct osmo_stream_srv *srv);
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn);

void osmo_stream_srv_set_flush_and_destroy(struct osmo_stream_srv *conn);
void osmo_stream_srv_set_data(struct osmo_stream_srv *conn, void *data);

void osmo_stream_srv_set_segmentation_cb(struct osmo_stream_srv *conn,
					int (*segmentation_cb)(struct msgb *msg));

void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg);
int osmo_stream_srv_recv(struct osmo_stream_srv *conn, struct msgb *msg);

void osmo_stream_srv_clear_tx_queue(struct osmo_stream_srv *conn);

/*! \brief Osmocom Stream Client: Single client connection */
struct osmo_stream_cli;

void osmo_stream_cli_set_name(struct osmo_stream_cli *cli, const char *name);
void osmo_stream_cli_set_nodelay(struct osmo_stream_cli *cli, bool nodelay);
void osmo_stream_cli_set_addr(struct osmo_stream_cli *cli, const char *addr);
int osmo_stream_cli_set_addrs(struct osmo_stream_cli *cli, const char **addr, size_t addrcnt);
void osmo_stream_cli_set_port(struct osmo_stream_cli *cli, uint16_t port);
int osmo_stream_cli_set_type(struct osmo_stream_cli *cli, int type);
int osmo_stream_cli_set_domain(struct osmo_stream_cli *cli, int domain);
void osmo_stream_cli_set_proto(struct osmo_stream_cli *cli, uint16_t proto);
void osmo_stream_cli_set_local_addr(struct osmo_stream_cli *cli, const char *addr);
int osmo_stream_cli_set_local_addrs(struct osmo_stream_cli *cli, const char **addr, size_t addrcnt);
void osmo_stream_cli_set_local_port(struct osmo_stream_cli *cli, uint16_t port);
void osmo_stream_cli_set_data(struct osmo_stream_cli *cli, void *data);
void osmo_stream_cli_set_reconnect_timeout(struct osmo_stream_cli *cli, int timeout);
void *osmo_stream_cli_get_data(struct osmo_stream_cli *cli);
char *osmo_stream_cli_get_sockname(const struct osmo_stream_cli *cli);
struct osmo_fd *osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli);
void osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli, int (*connect_cb)(struct osmo_stream_cli *cli));
void osmo_stream_cli_set_disconnect_cb(struct osmo_stream_cli *cli, int (*disconnect_cb)(struct osmo_stream_cli *cli));
void osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli, int (*read_cb)(struct osmo_stream_cli *cli));
void osmo_stream_cli_set_read_cb2(struct osmo_stream_cli *cli, int (*read_cb)(struct osmo_stream_cli *cli, struct msgb *msg));
void osmo_stream_cli_set_segmentation_cb(struct osmo_stream_cli *cli, int (*segmentation_cb)(struct msgb *msg));
void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli);
bool osmo_stream_cli_is_connected(struct osmo_stream_cli *cli);

struct osmo_stream_cli *osmo_stream_cli_create(void *ctx);
void osmo_stream_cli_destroy(struct osmo_stream_cli *cli);

int osmo_stream_cli_open(struct osmo_stream_cli *cli);
int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect) \
	OSMO_DEPRECATED("Use osmo_stream_cli_set_reconnect_timeout() or osmo_stream_cli_reconnect() instead");
void osmo_stream_cli_close(struct osmo_stream_cli *cli);

void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg);
int osmo_stream_cli_recv(struct osmo_stream_cli *cli, struct msgb *msg);

void osmo_stream_cli_clear_tx_queue(struct osmo_stream_cli *cli);

enum osmo_stream_cli_param {
	OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_AUTH_SUPPORTED, /* uint8_t: 0 disable, 1 enable, 2 force disable, 3 force enable */
	OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_ASCONF_SUPPORTED, /* uint8_t: 0 disable, 1 enable, 2 force disable, 3 force enable */
	OSMO_STREAM_CLI_PAR_SCTP_INIT_NUM_OSTREAMS, /* uint16_t: amount of streams */
	OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_INSTREAMS, /* uint16_t: amount of streams */
	OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_ATTEMPTS, /* uint16_t: amount of attempts */
	OSMO_STREAM_CLI_PAR_SCTP_INIT_TIMEOUT, /* uint16_t: milliseconds */
};

int osmo_stream_cli_set_param(struct osmo_stream_cli *cli, enum osmo_stream_cli_param par,
			      void *val, size_t val_len);

/*! @} */
