#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/netif/ipa.h>

#define IPA_ALLOC_SIZE 1200

struct msgb *osmo_ipa_msg_alloc(int headroom)
{
	struct msgb *msg;

	headroom += sizeof(struct ipa_head);

	msg = msgb_alloc_headroom(IPA_ALLOC_SIZE + headroom, headroom, "IPA");
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	return msg;
}

void osmo_ipa_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipa_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipa_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

int osmo_ipa_msg_recv(int fd, struct msgb *msg)
{
	struct ipa_head *hh;
	int len, ret;

	/* first read our 3-byte header */
	hh = (struct ipa_head *) msg->data;
	ret = recv(fd, msg->data, sizeof(*hh), 0);
	if (ret <= 0) {
		return ret;
	} else if (ret != sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "too small message received\n");
		return -EIO;
	}
	msgb_put(msg, ret);

	/* then read the length as specified in header */
	msg->l2h = msg->data + sizeof(*hh);
	len = ntohs(hh->len);

	if (len < 0 || IPA_ALLOC_SIZE < len + sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "bad message length of %d bytes, "
					"received %d bytes\n", len, ret);
		msgb_free(msg);
		return -EIO;
	}

	ret = recv(fd, msg->l2h, len, 0);
	if (ret <= 0) {
		msgb_free(msg);
		return ret;
	} else if (ret < len) {
		LOGP(DLINP, LOGL_ERROR, "trunked message received\n");
		msgb_free(msg);
		return -EIO;
	}
	msgb_put(msg, ret);
	return ret;
}
