#pragma once

#include <osmocom/core/utils.h>

/* Relevant SCTP RFCs:
 * rfc9260 (obsoletes rfc4960): SCTP protocol
 * rfc5061: SCTP Dynamic Address Reconfiguration
 * rfc6458: SCTP Sockets API Extensions
 */

enum sctp_sac_state;
extern const struct value_string osmo_sctp_assoc_chg_strs[];
static inline const char *osmo_sctp_assoc_chg_str(enum sctp_sac_state val)
{ return get_value_string(osmo_sctp_assoc_chg_strs, val); }

enum sctp_spc_state;
extern const struct value_string osmo_sctp_paddr_chg_strs[];
static inline const char *osmo_sctp_paddr_chg_str(enum sctp_spc_state val)
{ return get_value_string(osmo_sctp_paddr_chg_strs, val); }

enum sctp_sn_type;
extern const struct value_string osmo_sctp_sn_type_strs[];
static inline const char *osmo_sctp_sn_type_str(enum sctp_sn_type val)
{ return get_value_string(osmo_sctp_sn_type_strs, val); }

enum sctp_sn_error;
extern const struct value_string osmo_sctp_sn_error_strs[];
static inline const char *osmo_sctp_sn_error_str(enum sctp_sn_error val)
{ return get_value_string(osmo_sctp_sn_error_strs, val); }

enum osmo_sctp_op_error {
	OSMO_SCTP_OP_ERR_INVALID_STREAM_ID =  1,
	OSMO_SCTP_OP_ERR_MISS_MAND_PARAM =  2,
	OSMO_SCTP_OP_ERR_STALE_COOKIE =  3,
	OSMO_SCTP_OP_ERR_NO_RESOURCES =  4,
	OSMO_SCTP_OP_ERR_UNRESOLV_ADDR =  5,
	OSMO_SCTP_OP_ERR_UNKN_CHUNK_TYPE =  6,
	OSMO_SCTP_OP_ERR_INVALID_MAND_PARAM =  7,
	OSMO_SCTP_OP_ERR_UNKN_PARAM =  8,
	OSMO_SCTP_OP_ERR_NO_USER_DATA =  9,
	OSMO_SCTP_OP_ERR_COOKIE_RX_WHILE_SHUTDOWN = 10,
	OSMO_SCTP_OP_ERR_RESTART_ASSC_NEW_ADDR = 11,
	OSMO_SCTP_OP_ERR_UNER_INITED_ABORT = 12,
	OSMO_SCTP_OP_ERR_PROTO_VERSION = 13,
};


extern const struct value_string osmo_sctp_op_error_strs[];
static inline const char *osmo_sctp_op_error_str(enum osmo_sctp_op_error val)
{ return get_value_string(osmo_sctp_op_error_strs, val); }

enum sctp_spinfo_state;
extern const struct value_string osmo_sctp_spinfo_state_strs[];
static inline const char *osmo_sctp_spinfo_state_str(enum sctp_spinfo_state val)
{ return get_value_string(osmo_sctp_spinfo_state_strs, val); }

enum sctp_sstat_state;
extern const struct value_string osmo_sctp_sstat_state_strs[];
static inline const char *osmo_sctp_sstat_state_str(enum sctp_sstat_state val)
{ return get_value_string(osmo_sctp_sstat_state_strs, val); }
