CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

TESTS = \
	test-pyhoca-wrapper

check_PROGRAMS = \
	test-x2go-auth \
	$(TESTS)

AM_CPPFLAGS = $(GTEST_CPPFLAGS) \
	$(REMOTE_APPS_MANAGER_CFLAGS) \
	-I${top_srcdir}/src -Wall -Werror
AM_CXXFLAGS = $(GTEST_CXXFLAGS) \
	$(REMOTE_APPS_MANAGER_CFLAGS)

AM_CFLAGS = \
	 -Wall \
	 -g

##########################
# Google Test Test Suite #
##########################

check_LIBRARIES = libgtest.a

nodist_libgtest_a_SOURCES = \
  $(GTEST_SOURCE)/src/gtest-all.cc \
  $(GTEST_SOURCE)/src/gtest_main.cc

libgtest_a_CPPFLAGS = \
	$(GTEST_CPPFLAGS) -w \
	$(AM_CPPFLAGS)
libgtest_a_CXXFLAGS = \
	$(AM_CXXFLAGS)

##########################
# Wrapper
##########################

test_x2go_wrapper: test-x2go-auth

test_pyhoca_wrapper_SOURCES = \
	mock_pam.c mock_pam.h \
	mock_guest.c mock_guest.h \
	test-x2go-wrapper.cc

test_pyhoca_wrapper_LDADD = \
	$(top_builddir)/src/libx2gocore.la \
	libgtest.a

test_pyhoca_wrapper_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-DAUTH_CHECK="\"$(abs_builddir)/test-x2go-auth\"" \
	-I${top_srcdir}/src

test_pyhoca_wrapper_LDFLAGS = \
	-pthread

##########################
# Auth tool
##########################

test_x2go_auth_SOURCES = \
	test-x2go-auth.c

