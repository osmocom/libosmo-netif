#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/netif/channel.h>
#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

/* default IPA server ports. */
#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

static void *abis_ipa_server_tall;

static int oml_accept_cb(struct osmo_stream_server_link *server, int fd);
static int rsl_accept_cb(struct osmo_stream_server_link *server, int fd);

struct chan_abis_ipa_server {
	struct osmo_stream_server_link *oml;
	struct osmo_stream_server_link *rsl;

	struct llist_head bts_list;
	struct llist_head conn_list;

	void (*signal_msg)(struct msgb *msg, int type);
};

struct ipa_unit {
	struct llist_head	head;
	uint16_t		site_id;
	uint16_t		bts_id;
};

struct ipa_conn {
	struct llist_head		head;
	struct ipa_unit 		*unit;
	struct osmo_chan		*chan;
	struct osmo_stream_server_conn	*oml;
	struct osmo_stream_server_conn	*rsl;
};

static int chan_abis_ipa_server_create(struct osmo_chan *chan)
{
	struct chan_abis_ipa_server *c =
		(struct chan_abis_ipa_server *)chan->data;
	struct ipa_conn *ipa_conn;

	/* dummy connection. */
	ipa_conn = talloc_zero(chan->ctx, struct ipa_conn);
	if (ipa_conn == NULL)
		goto err;

	ipa_conn->chan = chan;

	c->oml = osmo_stream_server_link_create(abis_ipa_server_tall);
	if (c->oml == NULL)
		goto err_oml;

	/* default address and port for OML. */
	osmo_stream_server_link_set_addr(c->oml, "0.0.0.0");
	osmo_stream_server_link_set_port(c->oml, IPA_TCP_PORT_OML);
	osmo_stream_server_link_set_accept_cb(c->oml, oml_accept_cb);
	osmo_stream_server_link_set_data(c->oml, ipa_conn);

	c->rsl = osmo_stream_server_link_create(abis_ipa_server_tall);
	if (c->rsl == NULL)
		goto err_rsl;

	/* default address and port for RSL. */
	osmo_stream_server_link_set_addr(c->rsl, "0.0.0.0");
	osmo_stream_server_link_set_port(c->rsl, IPA_TCP_PORT_RSL);
	osmo_stream_server_link_set_accept_cb(c->rsl, rsl_accept_cb);
	osmo_stream_server_link_set_data(c->rsl, ipa_conn);

	INIT_LLIST_HEAD(&c->bts_list);
	INIT_LLIST_HEAD(&c->conn_list);

	return 0;
err_rsl:
	osmo_stream_server_link_destroy(c->oml);
err_oml:
	talloc_free(ipa_conn);
err:
	return -1;
}

static void chan_abis_ipa_server_destroy(struct osmo_chan *chan)
{
	struct chan_abis_ipa_server *c =
		(struct chan_abis_ipa_server *)chan->data;
	struct ipa_conn *ipa_conn =
		osmo_stream_server_link_get_data(c->oml);

	talloc_free(ipa_conn);
	talloc_free(c->rsl);
	talloc_free(c->oml);
}

static int chan_abis_ipa_server_open(struct osmo_chan *chan)
{
	struct chan_abis_ipa_server *c =
		(struct chan_abis_ipa_server *)chan->data;
	struct osmo_fd *ofd;
	int ret, on = 1;

	if (osmo_stream_server_link_open(c->oml) < 0)
		goto err;

	ofd = osmo_stream_server_link_get_ofd(c->oml);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_oml;

	if (osmo_stream_server_link_open(c->rsl) < 0)
		goto err_oml;

	ofd = osmo_stream_server_link_get_ofd(c->rsl);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_rsl;

	return 0;

err_rsl:
	osmo_stream_server_link_close(c->rsl);
err_oml:
	osmo_stream_server_link_close(c->oml);
err:
	return -1;
}

static void chan_abis_ipa_server_close(struct osmo_chan *chan)
{
	struct chan_abis_ipa_server *c =
		(struct chan_abis_ipa_server *)chan->data;

	osmo_stream_server_link_close(c->oml);
	osmo_stream_server_link_close(c->rsl);
}

static int chan_abis_ipa_server_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	osmo_stream_server_conn_send(msg->dst, msg);
	return 0;
}

void
osmo_chan_abis_ipa_server_set_oml_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)&c->data;

	osmo_stream_server_link_set_addr(s->oml, addr);
}

void
osmo_chan_abis_ipa_server_set_oml_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)&c->data;

	osmo_stream_server_link_set_port(s->oml, port);
}

void
osmo_chan_abis_ipa_server_set_rsl_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)&c->data;

	osmo_stream_server_link_set_addr(s->rsl, addr);
}

void
osmo_chan_abis_ipa_server_set_rsl_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)&c->data;

	osmo_stream_server_link_set_port(s->rsl, port);
}

void
osmo_chan_abis_ipa_server_set_cb_signalmsg(struct osmo_chan *c,
	void (*signal_msg)(struct msgb *msg, int type))
{
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)&c->data;

	s->signal_msg = signal_msg;
}

static int oml_read_cb(struct osmo_stream_server_conn *conn);

static int oml_accept_cb(struct osmo_stream_server_link *server, int fd)
{
	struct osmo_stream_server_conn *conn;
	struct ipa_conn *ipa_conn = osmo_stream_server_link_get_data(server);
	struct osmo_fd *ofd;

	conn = osmo_stream_server_conn_create(abis_ipa_server_tall,
					      server, fd,
					      oml_read_cb, NULL, ipa_conn);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_server_conn_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_server_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static int rsl_read_cb(struct osmo_stream_server_conn *conn);

static int rsl_accept_cb(struct osmo_stream_server_link *server, int fd)
{
	struct osmo_stream_server_conn *conn;
	struct ipa_conn *ipa_conn = osmo_stream_server_link_get_data(server);
	struct osmo_fd *ofd;

	conn = osmo_stream_server_conn_create(abis_ipa_server_tall,
					      server, fd,
					      rsl_read_cb, NULL, ipa_conn);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_server_conn_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_server_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static struct ipa_unit *
osmo_ipa_unit_find(struct osmo_chan *c, uint16_t site_id, uint16_t bts_id)
{
	struct ipa_unit *unit;
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)c->data;

	llist_for_each_entry(unit, &s->bts_list, head) {
		if (unit->site_id == site_id &&
		    unit->bts_id == bts_id)
			return unit;
	}
	return NULL;
}

int
osmo_chan_abis_ipa_unit_add(struct osmo_chan *c,
			    uint16_t site_id, uint16_t bts_id)
{
	struct ipa_unit *unit;
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)c->data;

	unit = talloc_zero(c->ctx, struct ipa_unit);
	if (unit == NULL)
		return -1;

	unit->site_id = site_id;
	unit->bts_id = bts_id;
	llist_add(&unit->head, &s->bts_list);

	return 0;
}

static struct ipa_conn *
osmo_ipa_conn_alloc(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa_conn *ipa_conn;

	ipa_conn = talloc_zero(chan->ctx, struct ipa_conn);
	if (ipa_conn == NULL)
		return NULL;

	ipa_conn->unit = unit;
	ipa_conn->chan = chan;

	return ipa_conn;
}

static struct ipa_conn *
osmo_ipa_conn_add(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa_conn *ipa_conn;
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)chan->data;

	ipa_conn = osmo_ipa_conn_alloc(unit, chan);
	if (ipa_conn == NULL)
		return NULL;

	llist_add(&ipa_conn->head, &s->conn_list);

	return ipa_conn;
}

static struct ipa_conn *
osmo_ipa_conn_find(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa_conn *ipa_conn;
	struct chan_abis_ipa_server *s =
		(struct chan_abis_ipa_server *)chan->data;

	llist_for_each_entry(ipa_conn, &s->conn_list, head) {
		if (ipa_conn->unit->site_id == unit->site_id &&
		    ipa_conn->unit->bts_id == unit->bts_id) {
			return ipa_conn;
		}
	}
	return NULL;
}

static void
osmo_ipa_conn_put(struct ipa_conn *ipa_conn)
{
	llist_del(&ipa_conn->head);
	osmo_stream_server_conn_destroy(ipa_conn->oml);
	osmo_stream_server_conn_destroy(ipa_conn->rsl);
	talloc_free(ipa_conn);
}

static int
abis_ipa_server_rcvmsg(struct osmo_chan *c,
		       struct osmo_stream_server_conn *conn,
		       struct msgb *msg, int type)
{
	struct tlv_parsed tlvp;
	uint8_t msg_type = *(msg->l2h);
	struct osmo_fd *ofd = osmo_stream_server_conn_get_ofd(conn);
	char *unitid;
	int len, ret;

	/* Handle IPA PING, PONG and ID_ACK messages. */
	if (osmo_ipa_rcvmsg_base(msg, ofd))
		return 0;

	if (msg_type == IPAC_MSGT_ID_RESP) {
		struct ipa_unit *unit;
		struct ipa_conn *ipa_conn;
		struct ipaccess_unit unit_data;

		DEBUGP(DLMI, "ID_RESP\n");
		/* parse tags, search for Unit ID */
		ret = osmo_ipa_idtag_parse(&tlvp, (uint8_t *)msg->l2h + 2,
						msgb_l2len(msg)-2);
		DEBUGP(DLMI, "\n");
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"with malformed TLVs\n");
			ret = -EINVAL;
			goto err;
		}
		if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"without unit ID\n");
			ret = -EINVAL;
			goto err;

		}
		len = TLVP_LEN(&tlvp, IPAC_IDTAG_UNIT);
		if (len < 1) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"with too small unit ID\n");
			ret = -EINVAL;
			goto err;
		}
		unitid = (char *) TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT);
		unitid[len - 1] = '\0';
		osmo_ipa_parse_unitid(unitid, &unit_data);

		unit = osmo_ipa_unit_find(c, unit_data.site_id,
					  unit_data.bts_id);
		if (unit == NULL) {
			LOGP(DLINP, LOGL_ERROR, "Unable to find BTS "
				"configuration for %u/%u/%u, disconnecting\n",
				unit_data.site_id, unit_data.bts_id,
				unit_data.trx_id);
			return 0;
		}
		DEBUGP(DLINP, "Identified BTS %u/%u/%u\n",
			unit_data.site_id, unit_data.bts_id,
			unit_data.trx_id);

		ipa_conn = osmo_ipa_conn_find(unit, c);
		if (ipa_conn == NULL) {
			ipa_conn = osmo_ipa_conn_add(unit, c);
			if (ipa_conn == NULL) {
				LOGP(DLINP, LOGL_ERROR, "OOM\n");
				return 0;
			}
			osmo_stream_server_conn_set_data(conn, ipa_conn);
		}

		if (type == CHAN_SIGN_OML) {
			if (ipa_conn->oml) {
				/* link already exists, kill it. */
				osmo_stream_server_conn_destroy(ipa_conn->oml);
				return 0;
			}
			ipa_conn->oml = conn;
		} else if (type == CHAN_SIGN_RSL) {
			if (!ipa_conn->oml) {
				/* no OML link? Restart from scratch. */
				osmo_ipa_conn_put(ipa_conn);
				return 0;
			}
			if (ipa_conn->rsl) {
				/* RSL link already exists, kill it. */
				osmo_stream_server_conn_destroy(ipa_conn->rsl);
				return 0;
			}
			ipa_conn->rsl = conn;
		}
		ret = 0;
	} else {
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		ret = -EINVAL;
	}
err:
	return ret;
}

static int read_cb(struct osmo_stream_server_conn *conn, int type)
{
	int ret;
	struct msgb *msg;
	struct osmo_fd *ofd = osmo_stream_server_conn_get_ofd(conn);
	struct ipa_conn *ipa_conn = osmo_stream_server_conn_get_data(conn);
	struct chan_abis_ipa_server *s;
	struct ipa_head *hh;

	LOGP(DLINP, LOGL_DEBUG, "received message from stream\n");

	msg = osmo_ipa_msg_alloc(0);
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	ret = osmo_ipa_msg_recv(ofd->fd, msg);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot receive message\n");
		msgb_free(msg);
		/* not the dummy connection, release it. */
		if (ipa_conn->unit != NULL)
			osmo_ipa_conn_put(ipa_conn);
		return 0;
	} else if (ret == 0) {
		/* link has vanished, dead socket. */
		LOGP(DLINP, LOGL_ERROR, "closed connection\n");
		msgb_free(msg);
		if (ipa_conn->unit != NULL)
			osmo_ipa_conn_put(ipa_conn);
		return 0;
	}

	hh = (struct ipa_head *) msg->data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		abis_ipa_server_rcvmsg(ipa_conn->chan, conn, msg, type);
		msgb_free(msg);
		return -EIO;
	}

	ipa_conn = osmo_stream_server_conn_get_data(conn);
	if (ipa_conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "no matching signalling link\n");
		msgb_free(msg);
		return -EIO;
	}
	if (hh->proto != IPAC_PROTO_OML && hh->proto != IPAC_PROTO_RSL) {
		LOGP(DLINP, LOGL_ERROR, "wrong protocol\n");
		return -EIO;
	}
	msg->dst = ipa_conn;

	s = (struct chan_abis_ipa_server *)ipa_conn->chan->data;
	s->signal_msg(msg, type);

	return 0;
}

static int oml_read_cb(struct osmo_stream_server_conn *conn)
{
	return read_cb(conn, CHAN_SIGN_OML);
}

static int rsl_read_cb(struct osmo_stream_server_conn *conn)
{
	return read_cb(conn, CHAN_SIGN_RSL);
}

struct osmo_chan_type chan_abis_ipa_server = {
	.type		= CHAN_ABIS_IPA_SERVER,
	.datasiz	= sizeof(struct chan_abis_ipa_server),
	.create		= chan_abis_ipa_server_create,
	.destroy	= chan_abis_ipa_server_destroy,
	.open		= chan_abis_ipa_server_open,
	.close		= chan_abis_ipa_server_close,
	.enqueue	= chan_abis_ipa_server_enqueue,
};
