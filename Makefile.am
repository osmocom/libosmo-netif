AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src examples utils tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-netif.pc

EXTRA_DIST = \
	     .version \
	     README.md \
	     debian \
	     git-version-gen \
	     $(NULL)

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version


if HAVE_DOXYGEN

html_DATA = $(top_builddir)/doc/html.tar

$(html_DATA): $(top_builddir)/doc/html/index.html
	cd $(top_builddir)/doc && tar cf html.tar html

$(top_builddir)/doc/html/index.html: $(top_srcdir)/src/*.c $(top_srcdir)/include/osmocom/netif/*.h Doxyfile
	@rm -rf doc
	mkdir -p doc
	$(DOXYGEN) Doxyfile

install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	rm -rf $(DESTDIR)$(htmldir)

DX_CLEAN = doc/html/search/* doc/{html,latex}/* doc/html.tar doc/doxygen_sqlite3.db doc/*.tag

endif

MOSTLYCLEANFILES = $(DX_CLEAN)
