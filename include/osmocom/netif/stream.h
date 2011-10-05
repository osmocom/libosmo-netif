#ifndef _OSMO_STREAM_H_
#define _OSMO_STREAM_H_

struct stream_server_link;

struct stream_server_link *stream_server_link_create(void *ctx);
void stream_server_link_destroy(struct stream_server_link *link);

void stream_server_link_set_addr(struct stream_server_link *link, const char *addr);
void stream_server_link_set_port(struct stream_server_link *link, uint16_t port);
void stream_server_link_set_accept_cb(struct stream_server_link *link, int (*accept_cb)(struct stream_server_link *link, int fd));

int stream_server_link_open(struct stream_server_link *link);
void stream_server_link_close(struct stream_server_link *link);

struct stream_server_conn;

struct stream_server_conn *stream_server_conn_create(void *ctx, struct stream_server_link *link, int fd, int (*cb)(struct stream_server_conn *conn, struct msgb *msg), int (*closed_cb)(struct stream_server_conn *conn), void *data);
void stream_server_conn_destroy(struct stream_server_conn *conn);

void stream_server_conn_send(struct stream_server_conn *conn, struct msgb *msg);

struct stream_client_conn;

void stream_client_conn_set_addr(struct stream_client_conn *link, const char *addr);
void stream_client_conn_set_port(struct stream_client_conn *link, uint16_t port);
void stream_client_conn_set_data(struct stream_client_conn *link, void *data);
void stream_client_conn_set_connect_cb(struct stream_client_conn *link, int (*connect_cb)(struct stream_client_conn *link));
void stream_client_conn_set_read_cb(struct stream_client_conn *link, int (*read_cb)(struct stream_client_conn *link, struct msgb *msgb));

struct stream_client_conn *stream_client_conn_create(void *ctx);
void stream_client_conn_destroy(struct stream_client_conn *link);

int stream_client_conn_open(struct stream_client_conn *link);
void stream_client_conn_close(struct stream_client_conn *link);

void stream_client_conn_send(struct stream_client_conn *link, struct msgb *msg);

#endif
