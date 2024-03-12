/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/lienses/>.
 *
 */
#pragma once

#include <stdint.h>

#include <osmocom/core/prim.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>

struct osmo_prim_srv_link;
struct osmo_prim_srv;

typedef int (*osmo_prim_srv_conn_cb)(struct osmo_prim_srv *prim_srv);
/*! oph and related msgb is owned by srv and wll be freed after the callback returns. */
typedef int (*osmo_prim_srv_rx_cb)(struct osmo_prim_srv *prim_srv, struct osmo_prim_hdr *oph);

/*! Return value:
 * RET=rem_version: Accept the version
 * RET!=rem_version && RET > 0: Reject the requested version but propose another candidate version
 *                              In this case, the client can decide whether to request another VER
 *                              or close the connection.
 * RET<0: Reject the proposed version and close the connection.
 */
typedef int (*osmo_prim_srv_rx_sapi_version)(struct osmo_prim_srv *prim_srv, uint32_t sapi, uint16_t rem_version);

struct osmo_prim_hdr *osmo_prim_msgb_alloc(unsigned int sap, unsigned int primitive,
					  enum osmo_prim_operation operation, size_t alloc_len);

struct osmo_prim_srv_link *osmo_prim_srv_link_alloc(void *ctx);
void osmo_prim_srv_link_free(struct osmo_prim_srv_link *prim_link);
void osmo_prim_srv_link_set_name(struct osmo_prim_srv_link *prim_link, const char *name);
int osmo_prim_srv_link_set_addr(struct osmo_prim_srv_link *prim_link, const char *path);
const char *osmo_prim_srv_link_get_addr(struct osmo_prim_srv_link *prim_link);
void osmo_prim_srv_link_set_priv(struct osmo_prim_srv_link *prim_link, void *priv);
void *osmo_prim_srv_link_get_priv(const struct osmo_prim_srv_link *prim_link);
void osmo_prim_srv_link_set_log_category(struct osmo_prim_srv_link *prim_link, int log_cat);
void osmo_prim_srv_link_set_opened_conn_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_conn_cb opened_conn_cb);
void osmo_prim_srv_link_set_closed_conn_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_conn_cb closed_conn_cb);
void osmo_prim_srv_link_set_rx_sapi_version_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_rx_sapi_version rx_sapi_version_cb);
void osmo_prim_srv_link_set_rx_cb(struct osmo_prim_srv_link *prim_link, osmo_prim_srv_rx_cb rx_cb);
void osmo_prim_srv_link_set_rx_msgb_alloc_len(struct osmo_prim_srv_link *prim_link, size_t alloc_len);
int osmo_prim_srv_link_open(struct osmo_prim_srv_link *prim_link);

int osmo_prim_srv_send(struct osmo_prim_srv *prim_srv, struct msgb *msg);
struct osmo_prim_srv_link *osmo_prim_srv_get_link(struct osmo_prim_srv *prims_srv);
void osmo_prim_srv_set_name(struct osmo_prim_srv *prim_srv, const char *name);
void osmo_prim_srv_set_priv(struct osmo_prim_srv *prim_srv, void *priv);
void *osmo_prim_srv_get_priv(const struct osmo_prim_srv *prim_srv);
void osmo_prim_srv_close(struct osmo_prim_srv *prim_srv);
