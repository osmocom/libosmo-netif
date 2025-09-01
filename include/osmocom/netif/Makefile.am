noinst_HEADERS = \
	rtcp_defs.h \
	stream_private.h \
	twjit_private.h \
	$(NULL)

version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

osmonetif_HEADERS = \
	amr.h \
	datagram.h \
	ipa.h \
	ipa_unit.h \
	jibuf.h \
	osmux.h \
	prim.h \
	rs232.h \
	rtp.h \
	stream.h \
	twjit.h \
	twrtp.h \
	version.h \
	$(NULL)

if ENABLE_LIBSCTP
osmonetif_HEADERS += sctp.h
endif

osmonetifdir = $(includedir)/osmocom/netif
