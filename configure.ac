AC_INIT([libpam-freerdp], [0.2.0])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 -Wno-portability])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_LIBTOOL

LT_INIT([disable-static])

###########################
# PAM
###########################

have_pam=no
AC_CHECK_LIB(pam, pam_getenv, have_pam=yes)
if test "x$have_pam" = "xno"; then
  AC_MSG_ERROR([Required library PAM was not found])
fi

###########################
# FreeRDP
###########################

PKG_CHECK_MODULES(FREERDP, freerdp)

###########################
# Local Install
###########################

with_localinstall="no"
AC_ARG_ENABLE(localinstall, AS_HELP_STRING([--enable-localinstall],
                                           [install all files locally (for distcheck)]),
              with_localinstall=$enableval,
              with_localinstall=no)

###########################
# PAM Module dir
###########################

if test "x$with_localinstall" = "xyes"; then
	PAMMODULEDIR="${libdir}/security/"
else
	PAMMODULEDIR="/lib/security"
fi
AC_SUBST(PAMMODULEDIR)


AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
