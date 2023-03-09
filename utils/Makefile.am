AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = \
        -Wall \
        $(LIBOSMOCORE_CFLAGS) \
        $(LIBOSMOCODEC_CFLAGS) \
        $(LIBOSMOGSM_CFLAGS) \
        $(TALLOC_CFLAGS) \
        $(NULL)

LDADD = \
        $(top_builddir)/src/libosmonetif.la \
        $(LIBOSMOCORE_LIBS) \
        $(LIBOSMOCODEC_LIBS) \
        $(LIBOSMOGSM_LIBS) \
        $(NULL)

noinst_PROGRAMS = osmo-amr-inspect

osmo_amr_inspect_SOURCES = osmo-amr-inspect.c
