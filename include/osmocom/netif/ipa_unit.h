#ifndef _IPA_UNIT_H_
#define _IPA_UNIT_H_

struct ipaccess_unit;

struct ipaccess_unit *osmo_ipa_unit_alloc();
void osmo_ipa_unit_free(struct ipaccess_unit *unit);

void osmo_ipa_unit_set_site_id(struct ipaccess_unit *unit, uint16_t site_id);
void osmo_ipa_unit_set_bts_id(struct ipaccess_unit *unit, uint16_t bts_id);
void osmo_ipa_unit_set_trx_id(struct ipaccess_unit *unit, uint16_t trx_id);
void osmo_ipa_unit_set_unit_name(struct ipaccess_unit *unit, const char *name);
void osmo_ipa_unit_set_unit_hwvers(struct ipaccess_unit *unit, const char *vers);
void osmo_ipa_unit_set_unit_swvers(struct ipaccess_unit *unit, const char *vers);
void osmo_ipa_unit_set_unit_mac_addr(struct ipaccess_unit *unit, uint8_t *addr);
void osmo_ipa_unit_set_unit_loc1(struct ipaccess_unit *unit, const char *loc);
void osmo_ipa_unit_set_unit_loc2(struct ipaccess_unit *unit, const char *loc);
void osmo_ipa_unit_set_unit_serno(struct ipaccess_unit *unit, const char *serno);

#endif	/* _IPA_UNIT_H_ */
