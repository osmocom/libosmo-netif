/*
 * Themyscira Wireless RTP jitter buffer implementation:
 * configuration by vty or otherwise.
 *
 * This code was contributed to Osmocom Cellular Network Infrastructure
 * project by Mother Mychaela N. Falconia of Themyscira Wireless.
 * Mother Mychaela's contributions are NOT subject to copyright:
 * no rights reserved, all rights relinquished.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include <osmocom/netif/twjit.h>
#include <osmocom/netif/twjit_private.h>

/*! \addgroup twjit
 *  @{
 */

/*! Allocate and initialize twjit config structure
 *
 * \param[in] ctx Parent talloc context under which struct osmo_twjit_config
 * should be allocated.
 * \returns pointer to the newly created twjit config instance, or NULL on
 * errors.
 *
 * A typical application will have a struct osmo_twjit_config somewhere
 * in the application config data structures, editable via vty.
 * More complex applications may even have several such twjit config
 * structures, to be used in different contexts such as GSM vs PSTN.
 * However, in the present Osmocom-integrated version of twjit, this config
 * structure has been made opaque for ABI reasons - hence config instances
 * now have to be allocated by the library, rather than merely initialized
 * in content.
 */
struct osmo_twjit_config *osmo_twjit_config_alloc(void *ctx)
{
	struct osmo_twjit_config *config;

	config = talloc_zero(ctx, struct osmo_twjit_config);
	if (!config)
		return NULL;

	/* Initialize defaults, corresponding to twna_twjit_config_init()
	 * in twrtp-native version. */

	/* While the theoretical minimum starting fill level is 1, the
	 * practically useful minimum (achieving lowest latency, but not
	 * incurring underruns in normal healthy operation) is 2 for typical
	 * network configurations that combine elements with "perfect" 20 ms
	 * timing (T1/E1 interfaces, external IP-PSTN links, software
	 * transcoders timed by system clock etc) and GSM-to-IP OsmoBTS
	 * whose 20 ms timing contains the small inherent jitter of TDMA. */
	config->bd_start = 2;

	/* The high water mark setting determines when the standing queue
	 * thinning mechanism kicks in.  A standing queue that is longer
	 * than the starting fill level will occur when the flow starts
	 * during a network latency spike, but then the network latency
	 * goes down.  If this setting is too high, deep standing queues
	 * will persist, adding needless latency to speech or CSD.
	 * If this setting is too low, the thinning mechanism will be
	 * too invasive, needlessly and perhaps frequently deleting a quantum
	 * of speech or data from the stream and incurring a phase shift.
	 * Starting fill level plus 2 seems like a good default. */
	config->bd_hiwat = 4;

	/* When the standing queue thinning mechanism does kick in,
	 * it drops every Nth packet, where N is the thinning interval.
	 * Given that this mechanism forcibly deletes a quantum of speech
	 * or data from the stream, these induced disruptions should be
	 * spaced out, and the managing operator should also keep in mind
	 * that the incurred phase shift may be a problem for some
	 * applications, particularly CSD.  Our current default is
	 * a prime number, reducing the probability that the thinning
	 * mechanism will interfere badly with intrinsic features of the
	 * stream being thinned.  17 quantum units at 20 ms per quantum
	 * is 340 ms, which should be sufficiently long spacing to make
	 * speech quantum deletions tolerable. */
	config->thinning_int = 17;

	/* Guard against time traveler packets,
	 * see document section 2.3.4.3. */
	config->max_future_sec = 10;

	return config;
}

/*! Free a twjit config instance
 *
 * \param[in] conf Instance to be freed
 */
void osmo_twjit_config_free(struct osmo_twjit_config *conf)
{
	if (!conf)
		return;
	talloc_free(conf);
}

/*! Write out vty form of twjit config structure
 *
 * \param[in] vty The vty instance to which vty_out() calls should be made
 * \param[in] conf The config structure to write out
 * \param[in] prefix Additional indent prefix to be prepended to each output
 * line, defaults to "" if NULL
 * \returns CMD_SUCCESS for vty system
 */
int osmo_twjit_config_write(struct vty *vty,
			    const struct osmo_twjit_config *conf,
			    const char *prefix)
{
	if (!prefix)
		prefix = "";
	vty_out(vty, "%s buffer-depth %u %u%s", prefix, conf->bd_start,
		conf->bd_hiwat, VTY_NEWLINE);
	vty_out(vty, "%s thinning-interval %u%s", prefix, conf->thinning_int,
		VTY_NEWLINE);
	vty_out(vty, "%s max-future-sec %u%s", prefix, conf->max_future_sec,
		VTY_NEWLINE);

	if (conf->start_min_delta) {
		vty_out(vty, "%s start-min-delta %u%s", prefix,
			conf->start_min_delta, VTY_NEWLINE);
	}
	if (conf->start_max_delta) {
		vty_out(vty, "%s start-max-delta %u%s", prefix,
			conf->start_max_delta, VTY_NEWLINE);
	}

	vty_out(vty, "%s marker-handling %s%s", prefix,
		conf->handover_on_marker ? "handover" : "ignore", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_buffer_depth, cfg_buffer_depth_cmd,
      "buffer-depth <1-65535> <1-65535>",
      "Buffer depth configuration\n"
      "Minimum fill required to start flow\n"
      "High water mark fill level\n")
{
	struct osmo_twjit_config *conf = vty->index;
	unsigned bd_start = atoi(argv[0]);
	unsigned bd_hiwat = atoi(argv[1]);

	if (bd_hiwat < bd_start) {
		vty_out(vty, "%% Error: high water mark cannot be less than starting level%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	conf->bd_start = bd_start;
	conf->bd_hiwat = bd_hiwat;

	return CMD_SUCCESS;
}

DEFUN(cfg_thinning, cfg_thinning_cmd,
      "thinning-interval <2-65535>",
      "Standing queue thinning configuration\n"
      "Drop every Nth packet\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->thinning_int = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_max_future, cfg_max_future_cmd,
      "max-future-sec <1-65535>",
      "Guard against time traveler packets\n"
      "Maximum permissible number of seconds into the future\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->max_future_sec = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_start_min_delta, cfg_start_min_delta_cmd,
      "start-min-delta <1-65535>",
      "Minimum required delta in time-of-arrival to start flow\n"
      "Time delta value in ms\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->start_min_delta = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_start_min_delta, cfg_no_start_min_delta_cmd,
      "no start-min-delta",
      NO_STR "Minimum required delta in time-of-arrival to start flow\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->start_min_delta = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_start_max_delta, cfg_start_max_delta_cmd,
      "start-max-delta <1-65535>",
      "Maximum permitted gap in time-of-arrival in starting state\n"
      "Time delta value in ms\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->start_max_delta = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_start_max_delta, cfg_no_start_max_delta_cmd,
      "no start-max-delta",
      NO_STR "Maximum permitted gap in time-of-arrival in starting state\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->start_max_delta = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_marker_handling, cfg_marker_handling_cmd,
      "marker-handling (handover|ignore)",
      "How to handle RTP packets with marker bit set\n"
      "Invoke handover handling, same as SSRC change\n"
      "Ignore marker bit\n")
{
	struct osmo_twjit_config *conf = vty->index;
	conf->handover_on_marker = (strcmp(argv[0], "handover") == 0);
	return CMD_SUCCESS;
}

/* Install vty configuration elements for twjit
 *
 * \param[in] twjit_node The application-defined vty node ID for twjit
 */
void osmo_twjit_vty_init(int twjit_node)
{
	install_lib_element(twjit_node, &cfg_buffer_depth_cmd);
	install_lib_element(twjit_node, &cfg_thinning_cmd);
	install_lib_element(twjit_node, &cfg_max_future_cmd);
	install_lib_element(twjit_node, &cfg_start_min_delta_cmd);
	install_lib_element(twjit_node, &cfg_no_start_min_delta_cmd);
	install_lib_element(twjit_node, &cfg_start_max_delta_cmd);
	install_lib_element(twjit_node, &cfg_no_start_max_delta_cmd);
	install_lib_element(twjit_node, &cfg_marker_handling_cmd);
}

/* config setter functions for non-vty users */

/*! Non-vty function for buffer-depth setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] bd_start Flow-starting fill level, document section 2.3.3.
 * \param[in] bd_hiwat High water mark fill level, document section 2.3.4.2.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_buffer_depth(struct osmo_twjit_config *conf,
					uint16_t bd_start, uint16_t bd_hiwat)
{
	if (bd_start < 1)
		return -EINVAL;
	if (bd_hiwat < bd_start)
		return -EINVAL;
	conf->bd_start = bd_start;
	conf->bd_hiwat = bd_hiwat;
	return 0;
}

/*! Non-vty function for thinning-interval setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] thinning_int Thinning interval setting, document section 2.3.4.2.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_thinning_int(struct osmo_twjit_config *conf,
					uint16_t thinning_int)
{
	if (thinning_int < 2)
		return -EINVAL;
	conf->thinning_int = thinning_int;
	return 0;
}

/*! Non-vty function for max-future-sec setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] max_future_sec Maximum number of seconds into the future,
 * document section 2.3.4.3.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_max_future_sec(struct osmo_twjit_config *conf,
					 uint16_t max_future_sec)
{
	if (max_future_sec < 1)
		return -EINVAL;
	conf->max_future_sec = max_future_sec;
	return 0;
}

/*! Non-vty function for start-min-delta setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] delta_ms Minimum required ToA delta in ms, or 0 to disable
 * this check; document section 2.3.3.2.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_start_min_delta(struct osmo_twjit_config *conf,
					  uint16_t delta_ms)
{
	conf->start_min_delta = delta_ms;
	return 0;
}

/*! Non-vty function for start-max-delta setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] delta_ms Maximum permitted ToA gap in ms, or 0 to disable
 * this check; document section 2.3.3.2.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_start_max_delta(struct osmo_twjit_config *conf,
					  uint16_t delta_ms)
{
	conf->start_max_delta = delta_ms;
	return 0;
}

/*! Non-vty function for marker-handling setting
 *
 * \param[in] conf twjit config instance to operate on.
 * \param[in] hom Handover on marker if true, ignore marker bit if false.
 * \returns 0 if successful, negative on errors.
 */
int osmo_twjit_config_set_handover_on_marker(struct osmo_twjit_config *conf,
					     bool hom)
{
	conf->handover_on_marker = hom;
	return 0;
}

/*! @} */
