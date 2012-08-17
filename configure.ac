AC_INIT([pam-freerdp], [0.0.1])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 -Wno-portability])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_LIBTOOL

have_pam=no
AC_CHECK_LIB(pam, pam_getenv, have_pam=yes)
if test "x$have_pam" = "xno"; then
  AC_MSG_ERROR([Required library PAM was not found])
fi

AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
