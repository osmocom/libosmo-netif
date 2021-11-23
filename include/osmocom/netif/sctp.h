#pragma once

#include <osmocom/core/utils.h>

enum sctp_sac_state;
extern const struct value_string osmo_sctp_assoc_chg_strs[];
static inline const char *osmo_sctp_assoc_chg_str(enum sctp_sac_state val)
{ return get_value_string(osmo_sctp_assoc_chg_strs, val); }

enum sctp_sn_type;
extern const struct value_string osmo_sctp_sn_type_strs[];
static inline const char *osmo_sctp_sn_type_str(enum sctp_sn_type val)
{ return get_value_string(osmo_sctp_sn_type_strs, val); }
