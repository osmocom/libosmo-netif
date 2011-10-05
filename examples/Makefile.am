INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_PROGRAMS = lapd-over-datagram-user	\
		  lapd-over-datagram-network

lapd_over_datagram_user_SOURCES = lapd-over-datagram-user.c
lapd_over_datagram_user_LDADD = $(top_builddir)/src/libosmonetif.la \
				  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				  $(LIBOSMOABIS_LIBS)

lapd_over_datagram_network_SOURCES = lapd-over-datagram-network.c
lapd_over_datagram_network_LDADD = $(top_builddir)/src/libosmonetif.la \
				  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				  $(LIBOSMOABIS_LIBS)
