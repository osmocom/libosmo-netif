#include <netinet/sctp.h>
#include <osmocom/netif/sctp.h>

const struct value_string osmo_sctp_assoc_chg_strs[] = {
	{ SCTP_COMM_UP,		"COMM_UP" },
	{ SCTP_COMM_LOST,	"COMM_LOST" },
	{ SCTP_RESTART,		"RESTART" },
	{ SCTP_SHUTDOWN_COMP,	"SHUTDOWN_COMP" },
	{ SCTP_CANT_STR_ASSOC,	"CANT_STR_ASSOC" },
	{ 0, NULL }
};

const struct value_string osmo_sctp_sn_type_strs[] = {
	{ SCTP_ASSOC_CHANGE,		"ASSOC_CHANGE" },
	{ SCTP_PEER_ADDR_CHANGE,	"PEER_ADDR_CHANGE" },
	{ SCTP_SHUTDOWN_EVENT, 		"SHUTDOWN_EVENT" },
	{ SCTP_SEND_FAILED,		"SEND_FAILED" },
	{ SCTP_REMOTE_ERROR,		"REMOTE_ERROR" },
	{ SCTP_PARTIAL_DELIVERY_EVENT,	"PARTIAL_DELIVERY_EVENT" },
	{ SCTP_ADAPTATION_INDICATION,	"ADAPTATION_INDICATION" },
#ifdef SCTP_AUTHENTICATION_INDICATION
	{ SCTP_AUTHENTICATION_INDICATION, "AUTHENTICATION_INDICATION" },
#endif
#ifdef SCTP_SENDER_DRY_EVENT
	{ SCTP_SENDER_DRY_EVENT,	"SENDER_DRY_EVENT" },
#endif
	{ 0, NULL }
};
