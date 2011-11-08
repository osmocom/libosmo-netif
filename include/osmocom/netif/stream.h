#ifndef _OSMO_STREAM_H_
#define _OSMO_STREAM_H_

struct osmo_stream_server_link;

struct osmo_stream_server_link *osmo_stream_server_link_create(void *ctx);
void osmo_stream_server_link_destroy(struct osmo_stream_server_link *link);

void osmo_stream_server_link_set_addr(struct osmo_stream_server_link *link, const char *addr);
void osmo_stream_server_link_set_port(struct osmo_stream_server_link *link, uint16_t port);
void osmo_stream_server_link_set_accept_cb(struct osmo_stream_server_link *link, int (*accept_cb)(struct osmo_stream_server_link *link, int fd));
void osmo_stream_server_link_set_data(struct osmo_stream_server_link *link, void *data);
void *osmo_stream_server_link_get_data(struct osmo_stream_server_link *link);
struct osmo_fd *osmo_stream_server_link_get_ofd(struct osmo_stream_server_link *link);

int osmo_stream_server_link_open(struct osmo_stream_server_link *link);
void osmo_stream_server_link_close(struct osmo_stream_server_link *link);

struct osmo_stream_server_conn;

struct osmo_stream_server_conn *osmo_stream_server_conn_create(void *ctx, struct osmo_stream_server_link *link, int fd, int (*cb)(struct osmo_stream_server_conn *conn), int (*closed_cb)(struct osmo_stream_server_conn *conn), void *data);
void *osmo_stream_server_conn_get_data(struct osmo_stream_server_conn *conn);
struct osmo_fd *osmo_stream_server_conn_get_ofd(struct osmo_stream_server_conn *link);
void osmo_stream_server_conn_destroy(struct osmo_stream_server_conn *conn);

void osmo_stream_server_conn_send(struct osmo_stream_server_conn *conn, struct msgb *msg);
int osmo_stream_server_conn_recv(struct osmo_stream_server_conn *conn, struct msgb *msg);

struct osmo_stream_client_conn;

void osmo_stream_client_conn_set_addr(struct osmo_stream_client_conn *link, const char *addr);
void osmo_stream_client_conn_set_port(struct osmo_stream_client_conn *link, uint16_t port);
void osmo_stream_client_conn_set_data(struct osmo_stream_client_conn *link, void *data);
void osmo_stream_client_conn_set_reconnect_timeout(struct osmo_stream_client_conn *link, int timeout);
void *osmo_stream_client_conn_get_data(struct osmo_stream_client_conn *link);
struct osmo_fd *osmo_stream_client_conn_get_ofd(struct osmo_stream_client_conn *link);
void osmo_stream_client_conn_set_connect_cb(struct osmo_stream_client_conn *link, int (*connect_cb)(struct osmo_stream_client_conn *link));
void osmo_stream_client_conn_set_read_cb(struct osmo_stream_client_conn *link, int (*read_cb)(struct osmo_stream_client_conn *link));

struct osmo_stream_client_conn *osmo_stream_client_conn_create(void *ctx);
void osmo_stream_client_conn_destroy(struct osmo_stream_client_conn *link);

int osmo_stream_client_conn_open(struct osmo_stream_client_conn *link);
void osmo_stream_client_conn_close(struct osmo_stream_client_conn *link);

void osmo_stream_client_conn_send(struct osmo_stream_client_conn *link, struct msgb *msg);
int osmo_stream_client_conn_recv(struct osmo_stream_client_conn *conn, struct msgb *msg);

#endif
