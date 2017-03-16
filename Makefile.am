AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src examples tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-netif.pc

EXTRA_DIST = .version README.md

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
