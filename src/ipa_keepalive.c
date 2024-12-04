/* IPA keep-alive FSM; Periodically transmit IPA_PING and expect IPA_PONG in return.
 *
 * (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <osmocom/core/fsm.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/protocol/ipaccess.h>

#include <osmocom/netif/ipa.h>

#define KA_FI_DEFAULT_PING_INTERVAL 30 /* seconds */
#define KA_FI_DEFAULT_PONG_TIMEOUT 10 /* seconds */

enum osmo_ipa_keepalive_event {
	OSMO_IPA_KA_E_START,
	OSMO_IPA_KA_E_STOP,
	OSMO_IPA_KA_E_PONG,
};

static const struct value_string ipa_keepalive_event_names[] = {
	OSMO_VALUE_STRING(OSMO_IPA_KA_E_START),
	OSMO_VALUE_STRING(OSMO_IPA_KA_E_STOP),
	OSMO_VALUE_STRING(OSMO_IPA_KA_E_PONG),
	{ 0, NULL }
};

struct osmo_ipa_ka_fsm_inst {
	struct osmo_fsm_inst *fi;
	/*! interval in which to send IPA CCM PING requests to the peer. */
	unsigned int ping_interval;
	/*! time to wait for an IPA CCM PONG in response to a IPA CCM PING before giving up. */
	unsigned int pong_timeout;
	osmo_ipa_ka_fsm_send_cb_t send_cb;
	osmo_ipa_ka_fsm_timeout_cb_t timeout_cb;
	void *cb_data;
};

/* generate a msgb containing an IPA CCM PING message */
static struct msgb *gen_ipa_ping(void)
{
	struct msgb *msg = msgb_alloc_headroom(64, 32, "IPA PING");
	if (!msg)
		return NULL;

	msgb_put_u8(msg, IPAC_MSGT_PING);
	ipa_prepend_header(msg, IPAC_PROTO_IPACCESS);

	return msg;
}

/********
 * FSM:
 *******/

#define S(x)	(1 << (x))

enum osmo_ipa_keepalive_state {
	OSMO_IPA_KA_S_INIT,
	OSMO_IPA_KA_S_IDLE,		/* waiting for next interval */
	OSMO_IPA_KA_S_WAIT_RESP,	/* waiting for response to keepalive */
};

enum ipa_fsm_timer {
	T_SEND_NEXT_PING = 1,
	T_PONG_NOT_RECEIVED = 2,
};

static void ipa_ka_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_ipa_ka_fsm_inst *ka_fi = fi->priv;

	switch (event) {
	case OSMO_IPA_KA_E_START:
		osmo_fsm_inst_state_chg(fi, OSMO_IPA_KA_S_WAIT_RESP,
					ka_fi->pong_timeout, T_PONG_NOT_RECEIVED);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void ipa_ka_wait_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_ipa_ka_fsm_inst *ka_fi = fi->priv;
	struct msgb *msg;

	if (!ka_fi->send_cb)
		osmo_panic("osmo_ipa_ka_fsm_inst running without send_cb, fix your code!");

	/* Send an IPA PING to the peer */
	msg = gen_ipa_ping();
	OSMO_ASSERT(msg);

	ka_fi->send_cb(ka_fi, msg, ka_fi->cb_data);
}

static void ipa_ka_wait_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_ipa_ka_fsm_inst *ka_fi = fi->priv;

	switch (event) {
	case OSMO_IPA_KA_E_PONG:
		osmo_fsm_inst_state_chg(fi, OSMO_IPA_KA_S_IDLE,
					ka_fi->ping_interval, T_SEND_NEXT_PING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int ipa_ka_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct osmo_ipa_ka_fsm_inst *ka_fi = fi->priv;

	switch (fi->T) {
	case T_SEND_NEXT_PING:
		/* send another PING */
		osmo_fsm_inst_state_chg(fi, OSMO_IPA_KA_S_WAIT_RESP,
					ka_fi->pong_timeout, T_PONG_NOT_RECEIVED);
		return 0;
	case T_PONG_NOT_RECEIVED:
		/* PONG not received within time */
		LOGPFSML(fi, LOGL_NOTICE, "IPA keep-alive FSM timed out: PONG not received\n");
		/* Keep FSM alive, move to INIT state */
		osmo_fsm_inst_state_chg(fi, OSMO_IPA_KA_S_INIT, 0, 0);
		if (ka_fi->timeout_cb)
			ka_fi->timeout_cb(ka_fi, ka_fi->cb_data);
		return 0;
	default:
		OSMO_ASSERT(0);
	}
}

static void ipa_ka_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case OSMO_IPA_KA_E_STOP:
		osmo_fsm_inst_state_chg(fi, OSMO_IPA_KA_S_INIT, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static const struct osmo_fsm_state ipa_keepalive_states[] = {
	[OSMO_IPA_KA_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(OSMO_IPA_KA_E_START),
		.out_state_mask = S(OSMO_IPA_KA_S_WAIT_RESP) | S(OSMO_IPA_KA_S_INIT),
		.action = ipa_ka_init,
	},
	[OSMO_IPA_KA_S_IDLE] = {
		.name = "IDLE",
		.out_state_mask = S(OSMO_IPA_KA_S_WAIT_RESP) | S(OSMO_IPA_KA_S_INIT),
		/* no permitted events aside from E_STOP, which is handled in allstate_events */
	},
	[OSMO_IPA_KA_S_WAIT_RESP] = {
		.name = "WAIT_RESP",
		.in_event_mask = S(OSMO_IPA_KA_E_PONG),
		.out_state_mask = S(OSMO_IPA_KA_S_IDLE) | S(OSMO_IPA_KA_S_INIT),
		.action = ipa_ka_wait_resp,
		.onenter = ipa_ka_wait_resp_onenter,
	},
};

static struct osmo_fsm ipa_keepalive_fsm = {
	.name = "IPA-KA",
	.states = ipa_keepalive_states,
	.num_states = ARRAY_SIZE(ipa_keepalive_states),
	.log_subsys = DLINP,
	.allstate_event_mask = S(OSMO_IPA_KA_E_STOP),
	.allstate_action = ipa_ka_allstate_action,
	.event_names = ipa_keepalive_event_names,
	.timer_cb = ipa_ka_fsm_timer_cb,
};

static __attribute__((constructor)) void on_dso_load(void)
{
	OSMO_ASSERT(osmo_fsm_register(&ipa_keepalive_fsm) == 0);
}


/*****************************
 * osmo_ipa_ka_fsm_inst APIS
******************************/

/*! Create a new instance of an IPA keepalive FSM: Periodically transmit PING and expect PONG.
 *  \param[in] ctx Talloc context.
 *  \param[in] id String used as identifier for the FSM.
 *  \returns pointer to the newly-created FSM instance; NULL in case of error.
 *
 *   Must be freed with \ref osmo_ipa_ka_fsm_free()
 */
struct osmo_ipa_ka_fsm_inst *osmo_ipa_ka_fsm_alloc(void *ctx, const char *id)
{
	struct osmo_ipa_ka_fsm_inst *ka_fi;

	ka_fi = talloc_zero(ctx, struct osmo_ipa_ka_fsm_inst);
	if (!ka_fi)
		goto ret_free;

	ka_fi->fi = osmo_fsm_inst_alloc(&ipa_keepalive_fsm, ka_fi, NULL, LOGL_DEBUG, id);
	if (!ka_fi->fi)
		goto ret_free;
	ka_fi->fi->priv = ka_fi;

	ka_fi->ping_interval = KA_FI_DEFAULT_PING_INTERVAL;
	ka_fi->pong_timeout = KA_FI_DEFAULT_PONG_TIMEOUT;

	return ka_fi;

ret_free:
	talloc_free(ka_fi);
	return NULL;
}

/*! Free object allocated through \ref osmo_ipa_ka_fsm_alloc().
 *  \param[in] ka_fi IPA keepalive FSM instance.
 *
 *  Does nothing if NULL is passed.
 */
void osmo_ipa_ka_fsm_free(struct osmo_ipa_ka_fsm_inst *ka_fi)
{
	if (!ka_fi)
		return;

	osmo_fsm_inst_free(ka_fi->fi);
	ka_fi->fi = NULL;

	talloc_free(ka_fi);
}

/*! Set name id of the IPA keepalive FSM instance.
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] id Name used during logging.
 * \returns zero on success, negative on error.
 */
int osmo_ipa_ka_fsm_set_id(struct osmo_ipa_ka_fsm_inst *ka_fi, const char *id)
{
	return osmo_fsm_inst_update_id(ka_fi->fi, id);
}

/*! Set PING interval value.
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] interval PING interval value, in seconds.
 * \returns zero on success, negative on error.
 */
int osmo_ipa_ka_fsm_set_ping_interval(struct osmo_ipa_ka_fsm_inst *ka_fi,  unsigned int interval)
{
	ka_fi->ping_interval = interval;
	return 0;
}

/*! Set PONG timeout value.
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] timeout PONG timeout value, in seconds.
 * \returns zero on success, negative on error.
 */
int osmo_ipa_ka_fsm_set_pong_timeout(struct osmo_ipa_ka_fsm_inst *ka_fi, unsigned int timeout)
{
	ka_fi->pong_timeout = timeout;
	return 0;
}

/*! Set user private data which can be used by user of osmo_ipa_ka_fsm.
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] cb_data User private data pointer.
 */
void osmo_ipa_ka_fsm_set_data(struct osmo_ipa_ka_fsm_inst *ka_fi, void *cb_data)
{
	ka_fi->cb_data = cb_data;
}

/*! Get user private data set previously throuhg \ref osmo_ipa_ka_fsm_set_data.
 * \param[in] ka_fi IPA keepalive FSM instance.
 */
void *osmo_ipa_ka_fsm_get_data(const struct osmo_ipa_ka_fsm_inst *ka_fi)
{
	return ka_fi->cb_data;
}

/*! Set a custom send callback for sending pings
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] send_cb Function to call whenever a PING needs to be sent (present in msgb param).
 */
void osmo_ipa_ka_fsm_set_send_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, osmo_ipa_ka_fsm_send_cb_t send_cb)
{
	ka_fi->send_cb = send_cb;
}

/*! Set a timeout call-back which is to be called once the peer doesn't respond anymore.
 * \param[in] ka_fi IPA keepalive FSM instance.
 * \param[in] timeout_cb Function to call whenever PONG timeout occurs.
 *
 * When the PONG timeout occurs, the FSM will stop and transition to INITIAL
 * state prior to triggering the timeout_cb(). This lets the user either destroy
 * the FSM (|ref osmo_ipa_ka_fsm_free()) or restart it (\ref osmo_ipa_ka_fsm_start()).
 */
void osmo_ipa_ka_fsm_set_timeout_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, osmo_ipa_ka_fsm_timeout_cb_t timeout_cb)
{
	ka_fi->timeout_cb = timeout_cb;
}

/*! Start the ping/pong procedure of the IPA Keepalive FSM.
 * \param[in] ka_fi IPA keepalive FSM instance.
 */
void osmo_ipa_ka_fsm_start(struct osmo_ipa_ka_fsm_inst *ka_fi)
{
	struct osmo_fsm_inst *fi = ka_fi->fi;
	LOGPFSML(fi, LOGL_INFO, "Starting IPA keep-alive FSM (interval=%us wait=%us)\n",
		 ka_fi->ping_interval, ka_fi->pong_timeout);
	osmo_fsm_inst_dispatch(fi, OSMO_IPA_KA_E_START, NULL);
}

/*! Inform IPA Keepalive FSM that a PONG has been received.
 * \param[in] ka_fi IPA keepalive FSM instance.
 */
void osmo_ipa_ka_fsm_pong_received(struct osmo_ipa_ka_fsm_inst *ka_fi)
{
	osmo_fsm_inst_dispatch(ka_fi->fi, OSMO_IPA_KA_E_PONG, NULL);
}

/*! Stop the ping/pong procedure of the IPA Keepalive FSM.
 *  \param[in] ka_fi IPA keepalive FSM instance.
 */
void osmo_ipa_ka_fsm_stop(struct osmo_ipa_ka_fsm_inst *ka_fi)
{
	struct osmo_fsm_inst *fi = ka_fi->fi;
	LOGPFSML(fi, LOGL_INFO, "Stopping IPA keep-alive FSM\n");
	osmo_fsm_inst_dispatch(fi, OSMO_IPA_KA_E_STOP, NULL);
}
