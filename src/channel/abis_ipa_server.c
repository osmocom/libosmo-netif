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

/* default IPA srv ports. */
#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

static void *abis_ipa_srv_tall;

static int oml_accept_cb(struct osmo_stream_srv_link *srv, int fd);
static int rsl_accept_cb(struct osmo_stream_srv_link *srv, int fd);

struct chan_abis_ipa_srv {
	struct osmo_stream_srv_link *oml;
	struct osmo_stream_srv_link *rsl;

	struct llist_head bts_list;
	struct llist_head conn_list;

	void (*signal_msg)(struct msgb *msg, int type);
};

struct ipa_unit {
	struct llist_head	head;
	uint16_t		site_id;
	uint16_t		bts_id;
};

struct ipa {
	struct llist_head		head;
	struct ipa_unit 		*unit;
	struct osmo_chan		*chan;
	struct osmo_stream_srv	*oml;
	struct osmo_stream_srv	*rsl;
};

static int chan_abis_ipa_srv_create(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c =
		(struct chan_abis_ipa_srv *)chan->data;
	struct ipa *ipa;

	/* dummy connection. */
	ipa = talloc_zero(chan->ctx, struct ipa);
	if (ipa == NULL)
		goto err;

	ipa->chan = chan;

	c->oml = osmo_stream_srv_link_create(abis_ipa_srv_tall);
	if (c->oml == NULL)
		goto err_oml;

	/* default address and port for OML. */
	osmo_stream_srv_link_set_addr(c->oml, "0.0.0.0");
	osmo_stream_srv_link_set_port(c->oml, IPA_TCP_PORT_OML);
	osmo_stream_srv_link_set_accept_cb(c->oml, oml_accept_cb);
	osmo_stream_srv_link_set_data(c->oml, ipa);

	c->rsl = osmo_stream_srv_link_create(abis_ipa_srv_tall);
	if (c->rsl == NULL)
		goto err_rsl;

	/* default address and port for RSL. */
	osmo_stream_srv_link_set_addr(c->rsl, "0.0.0.0");
	osmo_stream_srv_link_set_port(c->rsl, IPA_TCP_PORT_RSL);
	osmo_stream_srv_link_set_accept_cb(c->rsl, rsl_accept_cb);
	osmo_stream_srv_link_set_data(c->rsl, ipa);

	INIT_LLIST_HEAD(&c->bts_list);
	INIT_LLIST_HEAD(&c->conn_list);

	return 0;
err_rsl:
	osmo_stream_srv_link_destroy(c->oml);
err_oml:
	talloc_free(ipa);
err:
	return -1;
}

static void chan_abis_ipa_srv_destroy(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c =
		(struct chan_abis_ipa_srv *)chan->data;
	struct ipa *ipa =
		osmo_stream_srv_link_get_data(c->oml);

	talloc_free(ipa);
	talloc_free(c->rsl);
	talloc_free(c->oml);
}

static int chan_abis_ipa_srv_open(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c =
		(struct chan_abis_ipa_srv *)chan->data;
	struct osmo_fd *ofd;
	int ret, on = 1;

	if (osmo_stream_srv_link_open(c->oml) < 0)
		goto err;

	ofd = osmo_stream_srv_link_get_ofd(c->oml);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_oml;

	if (osmo_stream_srv_link_open(c->rsl) < 0)
		goto err_oml;

	ofd = osmo_stream_srv_link_get_ofd(c->rsl);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_rsl;

	return 0;

err_rsl:
	osmo_stream_srv_link_close(c->rsl);
err_oml:
	osmo_stream_srv_link_close(c->oml);
err:
	return -1;
}

static void chan_abis_ipa_srv_close(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c =
		(struct chan_abis_ipa_srv *)chan->data;

	osmo_stream_srv_link_close(c->oml);
	osmo_stream_srv_link_close(c->rsl);
}

static int chan_abis_ipa_srv_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	osmo_stream_srv_send(msg->dst, msg);
	return 0;
}

void
osmo_abis_ipa_srv_set_oml_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_addr(s->oml, addr);
}

void
osmo_abis_ipa_srv_set_oml_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_port(s->oml, port);
}

void
osmo_abis_ipa_srv_set_rsl_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_addr(s->rsl, addr);
}

void
osmo_abis_ipa_srv_set_rsl_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_port(s->rsl, port);
}

void
osmo_abis_ipa_srv_set_cb_signalmsg(struct osmo_chan *c,
	void (*signal_msg)(struct msgb *msg, int type))
{
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)&c->data;

	s->signal_msg = signal_msg;
}

static int oml_read_cb(struct osmo_stream_srv *conn);

static int oml_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct osmo_stream_srv *conn;
	struct ipa *ipa = osmo_stream_srv_link_get_data(srv);
	struct osmo_fd *ofd;

	conn = osmo_stream_srv_create(abis_ipa_srv_tall,
					      srv, fd,
					      oml_read_cb, NULL, ipa);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_srv_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_srv_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static int rsl_read_cb(struct osmo_stream_srv *conn);

static int rsl_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct osmo_stream_srv *conn;
	struct ipa *ipa = osmo_stream_srv_link_get_data(srv);
	struct osmo_fd *ofd;

	conn = osmo_stream_srv_create(abis_ipa_srv_tall, srv, fd,
				      rsl_read_cb, NULL, ipa);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_srv_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_srv_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static struct ipa_unit *
osmo_abis_ipa_unit_find(struct osmo_chan *c, uint16_t site_id, uint16_t bts_id)
{
	struct ipa_unit *unit;
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)c->data;

	llist_for_each_entry(unit, &s->bts_list, head) {
		if (unit->site_id == site_id &&
		    unit->bts_id == bts_id)
			return unit;
	}
	return NULL;
}

int
osmo_abis_ipa_unit_add(struct osmo_chan *c,
			    uint16_t site_id, uint16_t bts_id)
{
	struct ipa_unit *unit;
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)c->data;

	unit = talloc_zero(c->ctx, struct ipa_unit);
	if (unit == NULL)
		return -1;

	unit->site_id = site_id;
	unit->bts_id = bts_id;
	llist_add(&unit->head, &s->bts_list);

	return 0;
}

static struct ipa *
osmo_abis_ipa_alloc(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa *ipa;

	ipa = talloc_zero(chan->ctx, struct ipa);
	if (ipa == NULL)
		return NULL;

	ipa->unit = unit;
	ipa->chan = chan;

	return ipa;
}

static struct ipa *
osmo_abis_ipa_add(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa *ipa;
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)chan->data;

	ipa = osmo_abis_ipa_alloc(unit, chan);
	if (ipa == NULL)
		return NULL;

	llist_add(&ipa->head, &s->conn_list);

	return ipa;
}

static struct ipa *
osmo_abis_ipa_find(struct ipa_unit *unit, struct osmo_chan *chan)
{
	struct ipa *ipa;
	struct chan_abis_ipa_srv *s =
		(struct chan_abis_ipa_srv *)chan->data;

	llist_for_each_entry(ipa, &s->conn_list, head) {
		if (ipa->unit->site_id == unit->site_id &&
		    ipa->unit->bts_id == unit->bts_id) {
			return ipa;
		}
	}
	return NULL;
}

static void abis_ipa_put(struct ipa *ipa)
{
	llist_del(&ipa->head);
	osmo_stream_srv_destroy(ipa->oml);
	osmo_stream_srv_destroy(ipa->rsl);
	talloc_free(ipa);
}

static int
abis_ipa_srv_rcvmsg(struct osmo_chan *c,
		       struct osmo_stream_srv *conn,
		       struct msgb *msg, int type)
{
	struct tlv_parsed tlvp;
	uint8_t msg_type = *(msg->l2h);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	char *unitid;
	int len, ret;

	/* Handle IPA PING, PONG and ID_ACK messages. */
	if (osmo_ipa_rcvmsg_base(msg, ofd))
		return 0;

	if (msg_type == IPAC_MSGT_ID_RESP) {
		struct ipa_unit *unit;
		struct ipa *ipa;
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

		unit = osmo_abis_ipa_unit_find(c, unit_data.site_id,
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

		ipa = osmo_abis_ipa_find(unit, c);
		if (ipa == NULL) {
			ipa = osmo_abis_ipa_add(unit, c);
			if (ipa == NULL) {
				LOGP(DLINP, LOGL_ERROR, "OOM\n");
				return 0;
			}
			osmo_stream_srv_set_data(conn, ipa);
		}

		if (type == CHAN_SIGN_OML) {
			if (ipa->oml) {
				/* link already exists, kill it. */
				osmo_stream_srv_destroy(ipa->oml);
				return 0;
			}
			ipa->oml = conn;
		} else if (type == CHAN_SIGN_RSL) {
			if (!ipa->oml) {
				/* no OML link? Restart from scratch. */
				abis_ipa_put(ipa);
				return 0;
			}
			if (ipa->rsl) {
				/* RSL link already exists, kill it. */
				osmo_stream_srv_destroy(ipa->rsl);
				return 0;
			}
			ipa->rsl = conn;
		}
		ret = 0;
	} else {
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		ret = -EINVAL;
	}
err:
	return ret;
}

static int read_cb(struct osmo_stream_srv *conn, int type)
{
	int ret;
	struct msgb *msg;
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct ipa *ipa = osmo_stream_srv_get_data(conn);
	struct chan_abis_ipa_srv *s;
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
		if (ipa->unit != NULL)
			abis_ipa_put(ipa);
		return 0;
	} else if (ret == 0) {
		/* link has vanished, dead socket. */
		LOGP(DLINP, LOGL_ERROR, "closed connection\n");
		msgb_free(msg);
		if (ipa->unit != NULL)
			abis_ipa_put(ipa);
		return 0;
	}

	hh = (struct ipa_head *) msg->data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		abis_ipa_srv_rcvmsg(ipa->chan, conn, msg, type);
		msgb_free(msg);
		return -EIO;
	}

	ipa = osmo_stream_srv_get_data(conn);
	if (ipa == NULL) {
		LOGP(DLINP, LOGL_ERROR, "no matching signalling link\n");
		msgb_free(msg);
		return -EIO;
	}
	if (hh->proto != IPAC_PROTO_OML && hh->proto != IPAC_PROTO_RSL) {
		LOGP(DLINP, LOGL_ERROR, "wrong protocol\n");
		return -EIO;
	}
	msg->dst = ipa;

	s = (struct chan_abis_ipa_srv *)ipa->chan->data;
	s->signal_msg(msg, type);

	return 0;
}

static int oml_read_cb(struct osmo_stream_srv *conn)
{
	return read_cb(conn, CHAN_SIGN_OML);
}

static int rsl_read_cb(struct osmo_stream_srv *conn)
{
	return read_cb(conn, CHAN_SIGN_RSL);
}

struct osmo_chan_type chan_abis_ipa_srv = {
	.type		= CHAN_ABIS_IPA_SRV,
	.datasiz	= sizeof(struct chan_abis_ipa_srv),
	.create		= chan_abis_ipa_srv_create,
	.destroy	= chan_abis_ipa_srv_destroy,
	.open		= chan_abis_ipa_srv_open,
	.close		= chan_abis_ipa_srv_close,
	.enqueue	= chan_abis_ipa_srv_enqueue,
};
