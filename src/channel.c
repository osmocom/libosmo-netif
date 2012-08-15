#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/channel.h>

extern struct osmo_chan_type chan_abis_ipa_srv;
extern struct osmo_chan_type chan_abis_ipa_cli;

static struct osmo_chan_type *chan_type[CHAN_MAX] = {
	[CHAN_ABIS_IPA_SRV]	= &chan_abis_ipa_srv,
	[CHAN_ABIS_IPA_CLI]	= &chan_abis_ipa_cli,
};

struct osmo_chan *osmo_chan_create(void *ctx, int type_id)
{
	struct osmo_chan *c;

	if (type_id >= CHAN_MAX) {
		LOGP(DLINP, LOGL_ERROR, "unsupported channel type `%u'\n",
			type_id);
		return NULL;
	}

	c = talloc_zero_size(ctx, sizeof(struct osmo_chan) +
			     chan_type[type_id]->datasiz);
	if (c == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate channel data\n");
		return NULL;
	}

	c->ops = chan_type[type_id];

	if (c->ops->create(c) < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot create channel\n");
		talloc_free(c);
		return NULL;
	}
	return c;
}

void osmo_chan_destroy(struct osmo_chan *c)
{
	c->ops->destroy(c);
	talloc_free(c);
}

int osmo_chan_open(struct osmo_chan *c)
{
	return c->ops->open(c);
}

void osmo_chan_close(struct osmo_chan *c)
{
	c->ops->close(c);
}

int osmo_chan_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	return c->ops->enqueue(c, msg);
}
