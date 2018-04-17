AC_INIT([libosmo-netif],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([subdir-objects dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

CFLAGS="$CFLAGS -Wall"
CPPFLAGS="$CPPFLAGS -Wall"

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(execinfo.h sys/select.h sys/socket.h syslog.h ctype.h)

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

dnl Generate the output
AM_CONFIG_HEADER(config.h)

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.10.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.10.0)
dnl FIXME: We depend on libosmoabis by now until we can move LAPD code here
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.0.7)

old_LIBS=$LIBS
AC_SEARCH_LIBS([sctp_send], [sctp], [
	AC_DEFINE(HAVE_LIBSCTP, 1, [Define 1 to enable SCTP support])
	AC_SUBST(HAVE_LIBSCTP, [1])
	if test -n "$ac_lib"; then
		AC_SUBST(LIBSCTP_LIBS, [-l$ac_lib])
	fi
	], [
	AC_MSG_ERROR([sctp_send not found in searched libs])])
LIBS=$old_LIBS

AC_CHECK_HEADERS(dahdi/user.h,,AC_MSG_WARN(DAHDI input driver will not be built))

found_pcap=yes
AC_CHECK_HEADERS(pcap.h,,found_pcap=no)
AM_CONDITIONAL(HAVE_PCAP, test "$found_pcap" = yes)

AC_ARG_ENABLE(doxygen,
	[AS_HELP_STRING(
		[--disable-doxygen],
		[Disable generation of documentation using doxygen],
	)],
	[doxygen=$enableval], [doxygen="yes"])
AC_PATH_PROG(DOXYGEN,doxygen,false)
AM_CONDITIONAL(HAVE_DOXYGEN, test $DOXYGEN != false && test "x$doxygen" = "xyes")

AC_OUTPUT(
	libosmo-netif.pc
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/netif/Makefile
	include/osmocom/netif/channel/Makefile
	src/Makefile
	src/channel/Makefile
	src/channel/abis/Makefile
	examples/Makefile
	examples/channel/Makefile
	tests/Makefile
	Doxyfile
	Makefile)
