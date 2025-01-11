EXTRA_DIST = twrtp-guide-docinfo.xml twrtp-guide.adoc

if BUILD_MANUALS
  ASCIIDOC = twrtp-guide.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  OSMO_REPOSITORY = libosmo-netif
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
