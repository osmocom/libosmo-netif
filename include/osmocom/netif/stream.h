#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/msgb.h>

/*! \file stream.h */

/*! \brief Access SCTP flags from the msgb control buffer */
#define OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION 0x80 /* sctp_recvmsg() flags=MSG_NOTIFICATION, msgb_data() contains "union sctp_notification*" */
#define msgb_sctp_msg_flags(msg)	(msg)->cb[2]

/*! \brief Access the SCTP PPID from the msgb control buffer */
#define msgb_sctp_ppid(msg)             (msg)->cb[3]
/*! \brief Access the SCTP Stream ID from the msgb control buffer */
#define msgb_sctp_stream(msg)           (msg)->cb[4]

/*! \defgroup stream_srv Osmocom Stream Server
 *  @{
 *
 *  This code is intended to abstract any server-side use of stream-type sockets, such as TCP and SCTP.
 *
 *  The Osmocom stream socket helper is an abstraction layer for connected SOCK_STREAM/SOCK_SEQPACKET sockets.
 *  It encapsulates common functionality like binding, accepting client connections, etc.
 *
 *  osmo_stream_srv can operate in two different modes:
 *  1. The legacy mode using osmo_fd (from libosmocore)
 *  2. The modern (2023) mode using osmo_io (from libosmocore)
 *
 *  For any new applications, you definitely should use the modern mode, as it provides you with a higher
 *  layer of abstraction and allows you to perform efficient I/O using the io_uring backend of osmo_io.
 *
 *  The modern mode is chosen by invoking osmo_stream_srv_create2().
 *  The legacy mode is chosen by invoking the older osmo_stream_srv_create().
 *
 *  The two main objects are osmo_stream_srv_link (main server accept()ing incoming connections) and
 *  osmo_stream_srv (a single given connection from a remote client).
 *
 *  A typical stream_srv usage would look like this:
 *
 *  * create new osmo_stream_srv_link using osmo_stream_srv_link_create()
 *  * call osmo_stream_srv_link_set_addr() to set local bind address/port
 *  * call osmo_stream_srv_link_set_accept_cb() to register the accept call-back
 *  * optionally call further osmo_stream_srv_link_set_*() functions
 *  * call osmo_stream_srv_link_open() to create socket and start listening
 *
 *  Whenever a client connects to your listening socket, the connection will now be automatically accept()ed
 *  and the registered accept_cb call-back called.  From within that accept_cb, you then
 *  * call osmo_stream_srv_create() to create a osmo_stream_srv for that specific connection
 *  * call osmo_stream_srv_set_read_cb() to register the read call-back for incoming data
 *  * call osmo_stream_srv_set_closed_cb() to register the closed call-back
 *  * call osmo_stream_srv_set_data() to associate opaque application-layer state
 *
 *  Whenever data from a client arrives on a connection, your registered read_cb will be called together
 *  with a message buffer containing the received data. Ownership of the message buffer is transferred
 *  into the call-back, i.e. in your application.  It's your responsibility to eventually msgb_free()
 *  it after usage.
 *
 *  Whenever your application wants to transmit something to a given connection, it uses the
 *  osmo_stream_srv_send() function.
 */

/*! \brief Osmocom Stream Server Link: A server socket listening/accepting */
struct osmo_stream_srv_link;

typedef int (*osmo_stream_srv_link_accept_cb_t)(struct osmo_stream_srv_link *link, int fd);

struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx);
void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link);

void osmo_stream_srv_link_set_name(struct osmo_stream_srv_link *link, const char *name);
const char *osmo_stream_srv_link_get_name(const struct osmo_stream_srv_link *link);
void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay);
int osmo_stream_srv_link_set_priority(struct osmo_stream_srv_link *link, int sk_prio);
int osmo_stream_srv_link_set_ip_dscp(struct osmo_stream_srv_link *link, uint8_t ip_dscp);
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link, const char *addr);
int osmo_stream_srv_link_set_addrs(struct osmo_stream_srv_link *link, const char **addr, size_t addrcnt);
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link, uint16_t port);
void osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link, uint16_t proto);
int osmo_stream_srv_link_set_type(struct osmo_stream_srv_link *link, int type);
int osmo_stream_srv_link_set_domain(struct osmo_stream_srv_link *link, int domain);
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link, osmo_stream_srv_link_accept_cb_t accept_cb);
void osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link, void *data);
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link);
int osmo_stream_srv_link_set_tx_queue_max_length(struct osmo_stream_srv_link *link, unsigned int size);
char *osmo_stream_srv_link_get_sockname(const struct osmo_stream_srv_link *link);
struct osmo_fd *osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link);
int osmo_stream_srv_link_get_fd(const struct osmo_stream_srv_link *link);
int osmo_stream_srv_link_set_msgb_alloc_info(struct osmo_stream_srv_link *link, unsigned int size, unsigned int headroom);
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

typedef int (*osmo_stream_srv_read_cb_t)(struct osmo_stream_srv *conn);
typedef int (*osmo_stream_srv_closed_cb_t)(struct osmo_stream_srv *conn);

/*! Completion call-back function when something was read from from the stream client socket.
 * \param[in] conn Stream Server that got receive event.
 * \param[in] res return value of the read()/recvmsg()/... call, or -errno in case of error.
 * \param[in] msg message buffer containing the read data. Ownership is transferred to the
 * call-back, and it must make sure to msgb_free() it eventually! */
typedef int (*osmo_stream_srv_read_cb2_t)(struct osmo_stream_srv *conn, int res, struct msgb *msg);

typedef int (*osmo_stream_srv_segmentation_cb_t)(struct msgb *msg);
typedef int (*osmo_stream_srv_segmentation_cb2_t)(struct osmo_stream_srv *conn, struct msgb *msg);

struct osmo_stream_srv *osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link, int fd,
					       osmo_stream_srv_read_cb_t read_cb,
					       osmo_stream_srv_closed_cb_t closed_cb,
					       void *data);
struct osmo_stream_srv *osmo_stream_srv_create2(void *ctx, struct osmo_stream_srv_link *link, int fd, void *data);
void osmo_stream_srv_set_name(struct osmo_stream_srv *conn, const char *name);
const char *osmo_stream_srv_get_name(const struct osmo_stream_srv *conn);
void osmo_stream_srv_set_read_cb(struct osmo_stream_srv *conn, osmo_stream_srv_read_cb2_t read_cb);
void osmo_stream_srv_set_closed_cb(struct osmo_stream_srv *conn, osmo_stream_srv_closed_cb_t close_cb);
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn);
struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn);
const char *osmo_stream_srv_get_sockname(const struct osmo_stream_srv *conn);
struct osmo_fd *osmo_stream_srv_get_ofd(struct osmo_stream_srv *srv);
int osmo_stream_srv_get_fd(const struct osmo_stream_srv *srv);
struct osmo_io_fd *osmo_stream_srv_get_iofd(const struct osmo_stream_srv *srv);
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn);

void osmo_stream_srv_set_flush_and_destroy(struct osmo_stream_srv *conn);
void osmo_stream_srv_set_data(struct osmo_stream_srv *conn, void *data);

void osmo_stream_srv_set_segmentation_cb(struct osmo_stream_srv *conn, osmo_stream_srv_segmentation_cb_t segmentation_cb);
void osmo_stream_srv_set_segmentation_cb2(struct osmo_stream_srv *conn, osmo_stream_srv_segmentation_cb2_t segmentation_cb2);

void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg);
int osmo_stream_srv_recv(struct osmo_stream_srv *conn, struct msgb *msg);

void osmo_stream_srv_clear_tx_queue(struct osmo_stream_srv *conn);

/*! @} */

/*! \defgroup stream_cli Osmocom Stream Client
 *  @{
 *
 *  This code is intended to abstract any client use of stream-type sockets, such as TCP and SCTP
 *
 *  An osmo_stream_cli represents a client implementation of a SOCK_STREAM or SOCK_SEQPACKET socket. It
 *  contains all the common logic like non-blocking outbound connect to a remote server, re-connecting after
 *  disconnect or connect failure, etc.
 *
 *  osmo_stream_cli can operate in two different modes:
 *  1. The legacy mode using osmo_fd (from libosmocore)
 *  2. The modern (2023) mode using osmo_io_fd (from libosmocore)
 *
 *  For any new applications, you definitely should use the modern mode, as it provides you with a higher
 *  layer of abstraction and allows you to perform efficient I/O using the io_uring backend of osmo_io.
 *
 *  The modern mode is chosen by invoking osmo_stream_cli_set_read_cb2().
 *  The legacy mode is chosen by invoking the older osmo_stream_cli_set_read_cb().
 *
 *  A typical usage of osmo_stream_cli would look as follows:
 *
 *  * call osmo_stream_cli_create() to create a new osmo_stream_cli
 *  * call osmo_stream_cli_set_addr() / osmo_stream_cli_set_port() to specify the remote address/port to connect to
 *  * optionally call further functions of the osmo_stream_cli_set_*() family
 *  * call osmo_stream_cli_set_connect_cb() to register the call-back called on completion of outbound connect()
 *  * call osmo_stream_cli_set_read_cb2() to register the call-back called when incoming data has been read
 *  * call osmo_stream_cli_open() to open the connection (start outbound connect process)
 *
 *  Once the connection is established, your connect_cb is called to notify you.
 *
 *  You may send data to the connection using osmo_tream_cli_send().
 *
 *  Any received inbound data on the connection is reported vie the read_cb.
 */

/*! \brief Osmocom Stream Client: Single client connection */
struct osmo_stream_cli;

typedef int (*osmo_stream_cli_connect_cb_t)(struct osmo_stream_cli *cli);
typedef int (*osmo_stream_cli_disconnect_cb_t)(struct osmo_stream_cli *cli);
typedef int (*osmo_stream_cli_read_cb_t)(struct osmo_stream_cli *cli);

/*! Completion call-back function when something was read from from the stream client socket.
 * \param[in] cli Stream Client that got receive event.
 * \param[in] res return value of the read()/recvmsg()/... call, or -errno in case of error.
 * \param[in] msg message buffer containing the read data. Ownership is transferred to the
 * call-back, and it must make sure to msgb_free() it eventually! */
typedef int (*osmo_stream_cli_read_cb2_t)(struct osmo_stream_cli *cli, int res, struct msgb *msg);

typedef int (*osmo_stream_cli_segmentation_cb_t)(struct msgb *msg);
typedef int (*osmo_stream_cli_segmentation_cb2_t)(struct osmo_stream_cli *cli, struct msgb *msg);

void osmo_stream_cli_set_name(struct osmo_stream_cli *cli, const char *name);
const char *osmo_stream_cli_get_name(const struct osmo_stream_cli *cli);
void osmo_stream_cli_set_nodelay(struct osmo_stream_cli *cli, bool nodelay);
int osmo_stream_cli_set_priority(struct osmo_stream_cli *cli, int sk_prio);
int osmo_stream_cli_set_ip_dscp(struct osmo_stream_cli *cli, uint8_t ip_dscp);
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
int osmo_stream_cli_set_tx_queue_max_length(struct osmo_stream_cli *cli, unsigned int size);
char *osmo_stream_cli_get_sockname(const struct osmo_stream_cli *cli);
struct osmo_fd *osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli);
int osmo_stream_cli_get_fd(const struct osmo_stream_cli *cli);
struct osmo_io_fd *osmo_stream_cli_get_iofd(const struct osmo_stream_cli *cli);
void osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli, osmo_stream_cli_connect_cb_t connect_cb);
void osmo_stream_cli_set_disconnect_cb(struct osmo_stream_cli *cli, osmo_stream_cli_disconnect_cb_t disconnect_cb);
void osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli, osmo_stream_cli_read_cb_t read_cb);
void osmo_stream_cli_set_read_cb2(struct osmo_stream_cli *cli, osmo_stream_cli_read_cb2_t read_cb);
void osmo_stream_cli_set_segmentation_cb(struct osmo_stream_cli *cli, osmo_stream_cli_segmentation_cb_t segmentation_cb);
void osmo_stream_cli_set_segmentation_cb2(struct osmo_stream_cli *cli, osmo_stream_cli_segmentation_cb2_t segmentation_cb2);
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
