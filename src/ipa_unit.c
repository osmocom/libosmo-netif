#include <osmocom/core/talloc.h>

#include <stdint.h>
#include <string.h>

struct ipaccess_unit {
	uint16_t	site_id;
	uint16_t	bts_id;
	uint16_t	trx_id;
	char		*name;
	char		*hwvers;
	char		*swvers;
	uint8_t		mac_addr[6];
	char		*location1;
	char		*location2;
	char		*serno;
};

struct ipaccess_unit *osmo_ipa_unit_alloc()
{
	struct ipaccess_unit *unit;

	unit = talloc_zero(NULL, struct ipaccess_unit);
	if (unit == NULL)
		return NULL;

	unit->name = strdup("");
	unit->hwvers = strdup("");
	unit->swvers = strdup("");
	unit->location1 = strdup("");
	unit->location2 = strdup("");
	unit->serno = strdup("");

	return unit;
}

void osmo_ipa_unit_free(struct ipaccess_unit *unit)
{
	if (unit->name)
		free(unit->name);
	if (unit->hwvers)
		free(unit->hwvers);
	if (unit->swvers)
		free(unit->swvers);
	if (unit->location1)
		free(unit->location1);
	if (unit->location2)
		free(unit->location2);
	if (unit->serno)
		free(unit->serno);

	talloc_free(unit);
}

void osmo_ipa_unit_set_site_id(struct ipaccess_unit *unit, uint16_t site_id)
{
	unit->site_id = site_id;
}

void osmo_ipa_unit_set_bts_id(struct ipaccess_unit *unit, uint16_t bts_id)
{
	unit->bts_id = bts_id;
}

void osmo_ipa_unit_set_trx_id(struct ipaccess_unit *unit, uint16_t trx_id)
{
	unit->trx_id = trx_id;
}

void osmo_ipa_unit_set_unit_name(struct ipaccess_unit *unit, const char *name)
{
	if (unit->name)
		free(unit->name);

	unit->name = strdup(name);
}

void osmo_ipa_unit_set_unit_hwvers(struct ipaccess_unit *unit, const char *vers)
{
	if (unit->hwvers)
		free(unit->hwvers);

	unit->hwvers = strdup(vers);
}

void osmo_ipa_unit_set_unit_swvers(struct ipaccess_unit *unit, const char *vers)
{
	if (unit->swvers)
		free(unit->swvers);

	unit->swvers = strdup(vers);
}

void osmo_ipa_unit_set_unit_mac_addr(struct ipaccess_unit *unit, uint8_t *addr)
{
	memcpy(unit->mac_addr, addr, sizeof(unit->mac_addr));
}

void osmo_ipa_unit_set_unit_loc1(struct ipaccess_unit *unit, const char *loc)
{
	if (unit->location1)
		free(unit->location1);

	unit->location1 = strdup(loc);
}

void osmo_ipa_unit_set_unit_loc2(struct ipaccess_unit *unit, const char *loc)
{
	if (unit->location2)
		free(unit->location2);

	unit->location2 = strdup(loc);
}

void osmo_ipa_unit_set_unit_serno(struct ipaccess_unit *unit, const char *serno)
{
	unit->serno = strdup(serno);
}
