#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <stdint.h>

#define CHAN_SIGN_OML	0
#define CHAN_SIGN_RSL	1

enum {
	CHAN_NONE,
	CHAN_ABIS_IPA_SRV,
	CHAN_MAX,
};

#define CHAN_F_DEFAULT		(1 << 0)
#define CHAN_F_BUFFERED		(1 << 1)
#define CHAN_F_STREAM		(1 << 2)
#define CHAN_F_ERRORS		(1 << 3)
#define CHAN_F_MAX		(1 << 4)

struct osmo_chan;
struct msgb;

struct osmo_chan_type {
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

struct osmo_chan *osmo_chan_create(void *ctx, int type);
void osmo_chan_destroy(struct osmo_chan *c);

int osmo_chan_open(struct osmo_chan *c);
void osmo_chan_close(struct osmo_chan *c);

int osmo_chan_enqueue(struct osmo_chan *c, struct msgb *msg);

#endif /* _CHANNEL_H_ */
