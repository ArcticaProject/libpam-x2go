CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

TESTS = \
  test-auth-check \
  test-icaclient-wrapper

check_PROGRAMS = $(TESTS)

##########################
# Google Test Test Suite #
##########################
check_LIBRARIES = libgtest.a

AM_CPPFLAGS = $(GTEST_CPPFLAGS) \
	$(REMOTE_APPS_MANAGER_CFLAGS) \
	-I${top_srcdir}/src -Wall -Werror
AM_CXXFLAGS = $(GTEST_CXXFLAGS) \
	$(REMOTE_APPS_MANAGER_CFLAGS)

AM_CFLAGS = \
	 -Wall \
	 -g

nodist_libgtest_a_SOURCES = \
  $(GTEST_SOURCE)/src/gtest-all.cc \
  $(GTEST_SOURCE)/src/gtest_main.cc

libgtest_a_CPPFLAGS = \
	$(GTEST_CPPFLAGS) -w \
	$(AM_CPPFLAGS)
libgtest_a_CXXFLAGS = \
	$(AM_CXXFLAGS)

test_auth_check_SOURCES = \
	test-auth-check.cc

test_auth_check_LDADD = \
	$(top_builddir)/src/pam_ica.la \
	libgtest.a

test_auth_check_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-I${top_srcdir}/src

test_auth_check_LDFLAGS = \
	-pthread

test_icaclient_wrapper_SOURCES = \
	mock_pam.c \
	mock_guest.c \
	test-icaclient-wrapper.cc

test_icaclient_wrapper_LDADD = \
	$(top_builddir)/src/pam_ica.la \
	libgtest.a

test_icaclient_wrapper_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-I${top_srcdir}/src

test_icaclient_wrapper_LDFLAGS = \
	-pthread

