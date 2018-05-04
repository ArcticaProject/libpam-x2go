NULL =

CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

TESTS =								\
        test-x2go-wrapper					\
        $(NULL)

check_PROGRAMS =						\
        test-x2go-auth						\
        $(TESTS)						\
        $(NULL)

AM_CPPFLAGS = $(GTEST_CPPFLAGS)					\
        $(REMOTE_APPS_MANAGER_CFLAGS)				\
        -I${top_srcdir}/src -Wall -Werror			\
        $(NULL)

AM_CXXFLAGS = $(GTEST_CXXFLAGS)					\
        $(REMOTE_APPS_MANAGER_CFLAGS)				\
        $(NULL)

AM_CFLAGS =							\
        -Wall							\
        -g							\
        $(NULL)

##########################
# Google Test Test Suite #
##########################

check_LIBRARIES = libgtest.a

nodist_libgtest_a_SOURCES =					\
        $(GTEST_SOURCE)/src/gtest-all.cc			\
        $(GTEST_SOURCE)/src/gtest_main.cc			\
        $(NULL)

libgtest_a_CPPFLAGS =						\
        $(GTEST_CPPFLAGS) -w					\
        $(AM_CPPFLAGS)						\
        $(NULL)
libgtest_a_CXXFLAGS =						\
        $(AM_CXXFLAGS)						\
        $(NULL)

##########################
# Wrapper
##########################

test_x2go_wrapper: test-x2go-auth

test_x2go_wrapper_SOURCES =					\
        mock_pam.c mock_pam.h					\
        mock_guest.c mock_guest.h				\
        test-x2go-wrapper.cc					\
        $(NULL)

test_x2go_wrapper_LDADD =					\
        $(top_builddir)/src/libssh.la				\
        libgtest.a						\
        $(NULL)

test_x2go_wrapper_CXXFLAGS =					\
        $(AM_CXXFLAGS)						\
        -DAUTH_CHECK="\"$(abs_builddir)/test-x2go-auth\""	\
        -I${top_srcdir}/src					\
        $(NULL)

test_x2go_wrapper_LDFLAGS =					\
        -pthread						\
        $(NULL)

##########################
# Auth tool
##########################

test_x2go_auth_SOURCES =					\
        test-x2go-auth.c					\
        $(NULL)

