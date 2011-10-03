INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_PROGRAMS = lapd-over-stream-client	\
		  lapd-over-stream-server

lapd_over_stream_client_SOURCES = lapd-over-stream-client.c
lapd_over_stream_client_LDADD = $(top_builddir)/src/libosmonetif.la \
				$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				$(LIBOSMOABIS_LIBS)

lapd_over_stream_server_SOURCES = lapd-over-stream-server.c
lapd_over_stream_server_LDADD = $(top_builddir)/src/libosmonetif.la \
				$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				$(LIBOSMOABIS_LIBS)
