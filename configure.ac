AC_INIT([libosmo-netif],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([subdir-objects dist-bzip2])
AC_CONFIG_TESTDIR(tests)

CFLAGS="$CFLAGS -std=gnu11"

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

dnl patching ${archive_cmds} to affect generation of file "libtool" to fix linking with clang
AS_CASE(["$LD"],[*clang*],
  [AS_CASE(["${host_os}"],
     [*linux*],[archive_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'])])

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

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOCODEC, libosmocodec >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 1.12.0)

AC_ARG_ENABLE([libsctp], [AS_HELP_STRING([--disable-libsctp], [Do not enable socket multiaddr APIs requiring libsctp])],
	[ENABLE_LIBSCTP=$enableval], [ENABLE_LIBSCTP="yes"])
AM_CONDITIONAL(ENABLE_LIBSCTP, test x"$ENABLE_LIBSCTP" = x"yes")
AS_IF([test "x$ENABLE_LIBSCTP" = "xyes"], [
	AC_CHECK_HEADERS(netinet/sctp.h,,AC_MSG_ERROR(netinet/sctp.h not found))
	old_LIBS=$LIBS
	AC_CHECK_LIB(osmocore, osmo_sock_init2_multiaddr,, AC_MSG_ERROR(libosmocore built without libsctp support), $LIBOSMOCORE_LIBS)
	LIBS=$old_LIBS
	AC_SEARCH_LIBS([sctp_send], [sctp], [
		AC_DEFINE(HAVE_LIBSCTP, 1, [Define 1 to enable SCTP support])
		AC_SUBST(HAVE_LIBSCTP, [1])
		if test -n "$ac_lib"; then
			AC_SUBST(LIBSCTP_LIBS, [-l$ac_lib])
		fi
		], [
		AC_MSG_ERROR([sctp_send not found in searched libs])])
	LIBS=$old_LIBS
])

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
	src/Makefile
	examples/Makefile
	utils/Makefile
	tests/Makefile
	Doxyfile
	Makefile
	contrib/libosmo-netif.spec)
