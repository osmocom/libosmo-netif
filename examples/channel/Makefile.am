INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_PROGRAMS = abis_ipa_server	\
		  abis_ipa_client

abis_ipa_server_SOURCES = abis_ipa_server.c
abis_ipa_server_LDADD = $(top_builddir)/src/libosmonetif.la 	\
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

abis_ipa_client_SOURCES = abis_ipa_client.c
abis_ipa_client_LDADD = $(top_builddir)/src/libosmonetif.la 	\
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
