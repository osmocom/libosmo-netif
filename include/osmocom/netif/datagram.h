#ifndef _OSMO_DGRAM_H_
#define _OSMO_DGRAM_H_

struct datagram_client_conn;

struct datagram_client_conn *datagram_client_conn_create(void *ctx);
void datagram_client_conn_destroy(struct datagram_client_conn *conn);

void datagram_client_conn_set_addr(struct datagram_client_conn *conn, const char *addr);
void datagram_client_conn_set_port(struct datagram_client_conn *conn, uint16_t port);
void datagram_client_conn_set_data(struct datagram_client_conn *conn, void *data);

int datagram_client_conn_open(struct datagram_client_conn *conn);
void datagram_client_conn_close(struct datagram_client_conn *conn);

void datagram_client_conn_send(struct datagram_client_conn *conn, struct msgb *msg);

struct datagram_server_conn;

struct datagram_server_conn *datagram_server_conn_create(void *ctx);

void datagram_server_conn_set_addr(struct datagram_server_conn *conn, const char *addr);
void datagram_server_conn_set_port(struct datagram_server_conn *conn, uint16_t port);
void datagram_server_conn_set_read_cb(struct datagram_server_conn *conn, int (*read_cb)(struct datagram_server_conn *conn, struct msgb *msg));
void datagram_server_conn_destroy(struct datagram_server_conn *conn);

int datagram_server_conn_open(struct datagram_server_conn *conn);
void datagram_server_conn_close(struct datagram_server_conn *conn);

struct datagram_conn;

struct datagram_conn *datagram_conn_create(void *ctx);
void datagram_conn_destroy(struct datagram_conn *conn);

int datagram_conn_open(struct datagram_conn *conn);
void datagram_conn_close(struct datagram_conn *conn);

void datagram_conn_set_local_addr(struct datagram_conn *conn, const char *addr);
void datagram_conn_set_remote_addr(struct datagram_conn *conn, const char *addr);
void datagram_conn_set_local_port(struct datagram_conn *conn, uint16_t port);
void datagram_conn_set_remote_port(struct datagram_conn *conn, uint16_t port);
void datagram_conn_set_read_cb(struct datagram_conn *conn, int (*read_cb)(struct datagram_server_conn *conn, struct msgb *msg));
void datagram_conn_set_data(struct datagram_client_conn *conn, void *data);

void datagram_conn_send(struct datagram_conn *conn, struct msgb *msg);

#endif
