AC_INIT([libosmo-netif],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

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

AC_CHECK_HEADER([endian.h], [], [AC_MSG_ERROR([endian.h not found!]) ])

dnl Generate the output
AM_CONFIG_HEADER(config.h)

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.3.0)
dnl FIXME: We depend on libosmoabis by now until we can move LAPD code here
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.0.7)
PKG_CHECK_MODULES(ORTP, ortp >= 0.15.0)

AC_CHECK_HEADERS(dahdi/user.h,,AC_MSG_WARN(DAHDI input driver will not be built))

AC_OUTPUT(
	libosmonetif.pc
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/netif/Makefile
	include/osmocom/netif/channel/Makefile
	src/Makefile
	src/channel/Makefile
	examples/Makefile
	examples/channel/Makefile
	Makefile)
