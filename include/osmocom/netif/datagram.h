#ifndef _OSMO_DGRAM_H_
#define _OSMO_DGRAM_H_

struct osmo_dgram_client_conn;

struct osmo_dgram_client_conn *osmo_dgram_client_conn_create(void *ctx);
void osmo_dgram_client_conn_destroy(struct osmo_dgram_client_conn *conn);

void osmo_dgram_client_conn_set_addr(struct osmo_dgram_client_conn *conn, const char *addr);
void osmo_dgram_client_conn_set_port(struct osmo_dgram_client_conn *conn, uint16_t port);
void osmo_dgram_client_conn_set_data(struct osmo_dgram_client_conn *conn, void *data);

int osmo_dgram_client_conn_open(struct osmo_dgram_client_conn *conn);
void osmo_dgram_client_conn_close(struct osmo_dgram_client_conn *conn);

void osmo_dgram_client_conn_send(struct osmo_dgram_client_conn *conn, struct msgb *msg);

struct osmo_dgram_server_conn;

struct osmo_dgram_server_conn *osmo_dgram_server_conn_create(void *ctx);

void osmo_dgram_server_conn_set_addr(struct osmo_dgram_server_conn *conn, const char *addr);
void osmo_dgram_server_conn_set_port(struct osmo_dgram_server_conn *conn, uint16_t port);
void osmo_dgram_server_conn_set_read_cb(struct osmo_dgram_server_conn *conn, int (*read_cb)(struct osmo_dgram_server_conn *conn, struct msgb *msg));
void osmo_dgram_server_conn_destroy(struct osmo_dgram_server_conn *conn);

int osmo_dgram_server_conn_open(struct osmo_dgram_server_conn *conn);
void osmo_dgram_server_conn_close(struct osmo_dgram_server_conn *conn);

struct osmo_dgram_conn;

struct osmo_dgram_conn *osmo_dgram_conn_create(void *ctx);
void osmo_dgram_conn_destroy(struct osmo_dgram_conn *conn);

int osmo_dgram_conn_open(struct osmo_dgram_conn *conn);
void osmo_dgram_conn_close(struct osmo_dgram_conn *conn);

void osmo_dgram_conn_set_local_addr(struct osmo_dgram_conn *conn, const char *addr);
void osmo_dgram_conn_set_remote_addr(struct osmo_dgram_conn *conn, const char *addr);
void osmo_dgram_conn_set_local_port(struct osmo_dgram_conn *conn, uint16_t port);
void osmo_dgram_conn_set_remote_port(struct osmo_dgram_conn *conn, uint16_t port);
void osmo_dgram_conn_set_read_cb(struct osmo_dgram_conn *conn, int (*read_cb)(struct osmo_dgram_server_conn *conn, struct msgb *msg));
void osmo_dgram_conn_set_data(struct osmo_dgram_client_conn *conn, void *data);

void osmo_dgram_conn_send(struct osmo_dgram_conn *conn, struct msgb *msg);

#endif
