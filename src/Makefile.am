# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=4:0:1

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS= -fPIC -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS) $(LIBSCTP_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

SUBDIRS = channel

lib_LTLIBRARIES = libosmonetif.la

libosmonetif_la_LIBADD = channel/abis/libosmonetif-abis.la $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBSCTP_LIBS)
libosmonetif_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined

libosmonetif_la_SOURCES = amr.c			\
			  channel.c		\
			  datagram.c		\
			  ipa.c			\
			  ipa_unit.c		\
			  osmux.c		\
			  rs232.c		\
			  rtp.c			\
			  stream.c
