CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

TESTS = \
	test-freerdpclient-wrapper

check_PROGRAMS = \
	test-freerdp-auth \
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

test_freerdp_wrapper: test-freerdp-auth

test_freerdpclient_wrapper_SOURCES = \
	mock_pam.c mock_pam.h \
	mock_guest.c mock_guest.h \
	test-freerdp-wrapper.cc

test_freerdpclient_wrapper_LDADD = \
	$(top_builddir)/src/libfreerdpcore.la \
	libgtest.a

test_freerdpclient_wrapper_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-DAUTH_CHECK="\"$(abs_builddir)/test-freerdp-auth\"" \
	-I${top_srcdir}/src

test_freerdpclient_wrapper_LDFLAGS = \
	-pthread

##########################
# Auth tool
##########################

test_freerdp_auth_SOURCES = \
	test-freerdp-auth.c

