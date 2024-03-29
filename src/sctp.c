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

const struct value_string osmo_sctp_paddr_chg_strs[] = {
	{ SCTP_ADDR_AVAILABLE,		"ADDR_AVAILABLE" },
	{ SCTP_ADDR_UNREACHABLE,	"ADDR_UNREACHABLE" },
	{ SCTP_ADDR_REMOVED,		"ADDR_REMOVED" },
	{ SCTP_ADDR_ADDED,		"ADDR_ADDED" },
	{ SCTP_ADDR_MADE_PRIM,		"ADDR_MADE_PRIM" },
	{ SCTP_ADDR_CONFIRMED,		"ADDR_CONFIRMED" },
#ifdef SCTP_ADDR_PF
	{ SCTP_ADDR_PF,	"ADDR_POTENTIALLY_FAILED" },
#endif
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


const struct value_string osmo_sctp_sn_error_strs[] = {
	{ SCTP_FAILED_THRESHOLD,	"FAILED_THRESHOLD" },
	{ SCTP_RECEIVED_SACK,		"RECEIVED_SACK" },
	{ SCTP_HEARTBEAT_SUCCESS,	"HEARTBEAT_SUCCESS" },
	{ SCTP_RESPONSE_TO_USER_REQ,	"RESPONSE_TO_USER_REQ" },
	{ SCTP_INTERNAL_ERROR,		"INTERNAL_ERROR" },
	{ SCTP_SHUTDOWN_GUARD_EXPIRES,	"SHUTDOWN_GUARD_EXPIRES" },
	{ SCTP_PEER_FAULTY,		"PEER_FAULTY" },
	{ 0, NULL }
};

/* rfc4960 section 3.3.10 "Operation Error", in host byte order */
const struct value_string osmo_sctp_op_error_strs[] = {
	{ OSMO_SCTP_OP_ERR_INVALID_STREAM_ID,	"Invalid Stream Identifier" },
	{ OSMO_SCTP_OP_ERR_MISS_MAND_PARAM,	"Missing Mandatory Parameter" },
	{ OSMO_SCTP_OP_ERR_STALE_COOKIE,	"Stale Cookie Error" },
	{ OSMO_SCTP_OP_ERR_NO_RESOURCES,	"Out of Resource" },
	{ OSMO_SCTP_OP_ERR_UNRESOLV_ADDR,	"Unresolvable Address" },
	{ OSMO_SCTP_OP_ERR_UNKN_CHUNK_TYPE,	"Unrecognized Chunk Type" },
	{ OSMO_SCTP_OP_ERR_INVALID_MAND_PARAM,	"Invalid Mandatory Parameter" },
	{ OSMO_SCTP_OP_ERR_UNKN_PARAM,		"Unrecognized Parameters" },
	{ OSMO_SCTP_OP_ERR_NO_USER_DATA,	"No User Data" },
	{ OSMO_SCTP_OP_ERR_COOKIE_RX_WHILE_SHUTDOWN,	"Cookie Received While Shutting Down" },
	{ OSMO_SCTP_OP_ERR_RESTART_ASSC_NEW_ADDR,	"Restart of an Association with New Addresses" },
	{ OSMO_SCTP_OP_ERR_UNER_INITED_ABORT,	"User Initiated Abort" },
	{ OSMO_SCTP_OP_ERR_PROTO_VERSION,	"Protocol Violation" },
	{ 0, NULL }
};

/* linux/sctp.h enum sctp_spinfo_state */
const struct value_string osmo_sctp_spinfo_state_strs[] = {
	{ SCTP_INACTIVE,	"INACTIVE" },
	{ SCTP_PF,		"POTENTIALLY_FAILED" },
	{ SCTP_ACTIVE,		"ACTIVE" },
	{ SCTP_UNCONFIRMED,	"UNCONFIRMED" },
	{ SCTP_UNKNOWN,		"UNKNOWN" },
	{ 0, NULL }
};

/* linux/sctp.h enum sctp_sstat_state */
const struct value_string osmo_sctp_sstat_state_strs[] = {
	{ SCTP_EMPTY,			"EMPTY" },
	{ SCTP_CLOSED,			"CLOSED" },
	{ SCTP_COOKIE_WAIT,		"COOKIE_WAIT" },
	{ SCTP_COOKIE_ECHOED,		"COOKIE_ECHOED" },
	{ SCTP_ESTABLISHED,		"ESTABLISHED" },
	{ SCTP_SHUTDOWN_PENDING,	"SHUTDOWN_PENDING" },
	{ SCTP_SHUTDOWN_SENT,		"SHUTDOWN_SENT" },
	{ SCTP_SHUTDOWN_RECEIVED,	"SHUTDOWN_RECEIVED" },
	{ SCTP_SHUTDOWN_ACK_SENT,	"SHUTDOWN_ACK_SENT" },
	{ 0, NULL }
};
