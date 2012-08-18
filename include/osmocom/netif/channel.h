#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <stdint.h>

/* channel types */
enum {
	OSMO_CHAN_NONE,
	OSMO_CHAN_ABIS_IPA_SRV,
	OSMO_CHAN_ABIS_IPA_CLI,
	OSMO_CHAN_MAX,
};

struct osmo_chan;
struct msgb;

struct osmo_chan_type {
	struct llist_head head;

	char	*name;
	int	type;
	int	datasiz;

	int	(*create)(struct osmo_chan *chan);
	void	(*destroy)(struct osmo_chan *chan);
	int	(*open)(struct osmo_chan *chan);
	void	(*close)(struct osmo_chan *chan);
	int	(*enqueue)(struct osmo_chan *chan, struct msgb *msg);
};

struct osmo_chan {
	void			*ctx;
	struct osmo_chan_type	*ops;
	char			data[0];
};

void osmo_chan_init(void);

struct osmo_chan *osmo_chan_create(void *ctx, int type);
void osmo_chan_destroy(struct osmo_chan *c);

int osmo_chan_open(struct osmo_chan *c);
void osmo_chan_close(struct osmo_chan *c);

int osmo_chan_enqueue(struct osmo_chan *c, struct msgb *msg);

#endif /* _CHANNEL_H_ */
