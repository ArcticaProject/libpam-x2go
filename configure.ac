AC_INIT([libpam-x2go], [0.0.2.0])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([-Wno-portability subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
# the Google Test targets are cpp
AC_PROG_CXX
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
# LIBSSH
###########################

PKG_CHECK_MODULES(LIBSSH, libssh)

###########################
# PAM Module dir
###########################

PAMMODULEDIR="/lib/security"
AC_SUBST(PAMMODULEDIR)

###########################
# Google Test Dependencies
###########################

m4_include([m4/gtest.m4])
CHECK_GTEST
if test "x$have_gtest" != "xyes"; then
   AC_MSG_WARN([tests were requested but gtest is not installed.])
fi
AM_CONDITIONAL([HAVE_GTEST], [test "$have_gtest" != "no"])

###########################
# gcov coverage reporting
###########################

m4_include([m4/gcov.m4])
AC_TDD_GCOV
AM_CONDITIONAL([HAVE_GCOV], [test "x$ac_cv_check_gcov" = xyes])
AM_CONDITIONAL([HAVE_LCOV], [test "x$ac_cv_check_lcov" = xyes])
AM_CONDITIONAL([HAVE_GCOVR], [test "x$ac_cv_check_gcovr" = xyes])
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_CXXFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)



AC_CONFIG_FILES([
  Makefile
  src/Makefile
  tests/Makefile
])
AC_OUTPUT
