AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) -g
AM_LDFLAGS = $(LIBOSMOCORE_LDFLAGS) -no-install

LDADD = \
	$(top_builddir)/src/libosmonetif.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

check_PROGRAMS = \
	osmux/osmux_test \
	osmux/osmux_output_test \
	osmux/osmux_input_test \
	stream/stream_test \
	jibuf/jibuf_test \
	amr/amr_test \
	$(NULL)
check_HEADERS =

osmux_osmux_test_SOURCES = osmux/osmux_test.c
osmux_osmux_output_test_SOURCES = osmux/osmux_output_test.c
osmux_osmux_input_test_SOURCES = osmux/osmux_input_test.c
stream_stream_test_SOURCES = stream/stream_test.c
jibuf_jibuf_test_SOURCES = jibuf/jibuf_test.c
amr_amr_test_SOURCES = amr/amr_test.c

if HAVE_PCAP
check_PROGRAMS += jibuf/jibuf_tool
check_HEADERS += \
		osmo-pcap-test/osmo_pcap.h \
		osmo-pcap-test/proto.h

jibuf_jibuf_tool_SOURCES = \
	jibuf/jibuf_tool.c \
	osmo-pcap-test/proto.c \
	osmo-pcap-test/l2_eth.c \
	osmo-pcap-test/l2_sll.c \
	osmo-pcap-test/l3_ipv4.c \
	osmo-pcap-test/l4_tcp.c \
	osmo-pcap-test/l4_udp.c \
	osmo-pcap-test/pcap.c

jibuf_jibuf_tool_LDADD = $(LDADD) -lpcap
endif

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
	       echo '# Signature of the current package.' && \
	       echo 'm4_define([AT_PACKAGE_NAME],' && \
	       echo '  [$(PACKAGE_NAME)])' && \
	       echo 'm4_define([AT_PACKAGE_TARNAME],' && \
	       echo '  [$(PACKAGE_TARNAME)])' && \
	       echo 'm4_define([AT_PACKAGE_VERSION],' && \
	       echo '  [$(PACKAGE_VERSION)])' && \
	       echo 'm4_define([AT_PACKAGE_STRING],' && \
	       echo '  [$(PACKAGE_STRING)])' && \
	       echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
	       echo '  [$(PACKAGE_BUGREPORT)])'; \
	       echo 'm4_define([AT_PACKAGE_URL],' && \
	       echo '  [$(PACKAGE_URL)])'; \
	     } >'$(srcdir)/package.m4'

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE)		\
	     osmux/osmux_test.ok \
	     osmux/osmux_output_test.ok \
	     osmux/osmux_input_test.ok \
	     stream/stream_test.ok \
	     stream/stream_test.err \
	     jibuf/jibuf_test.ok \
	     amr/amr_test.ok


DISTCLEANFILES = atconfig

TESTSUITE = $(srcdir)/testsuite

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
