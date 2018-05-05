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

CLEANFILES +=							\
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

check_LIBRARIES = libgtest.a libgtest_main.a

gtest-all.cc:
	cp $(GTEST_SOURCE)/src/gtest-all.cc .

gtest_main.cc:
	cp $(GTEST_SOURCE)/src/gtest_main.cc .

CLEANFILES +=							\
        gtest-all.cc						\
        gtest_main.cc						\
        $(NULL)

nodist_libgtest_a_SOURCES =					\
        gtest-all.cc						\
        $(NULL)
nodist_libgtest_main_a_SOURCES =				\
        gtest_main.cc						\
        $(NULL)

libgtest_a_CPPFLAGS =						\
        $(GTEST_CPPFLAGS) -w					\
        $(AM_CPPFLAGS)						\
        $(NULL)
libgtest_main_a_CPPFLAGS =					\
        $(GTEST_CPPFLAGS) -w					\
        $(AM_CPPFLAGS)						\
        $(NULL)

libgtest_a_CXXFLAGS =						\
        $(AM_CXXFLAGS)						\
        $(NULL)
libgtest_main_a_CXXFLAGS =					\
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
        libgtest.a libgtest_main.a				\
        ${top_srcdir}/src/pam_x2go.la				\
        $(LIBSSH_LIBS)						\
        $(NULL)

test_x2go_wrapper_CPPFLAGS =					\
        $(AM_CPPFLAGS)						\
        -I${top_srcdir}/include					\
        -I${top_srcdir}/src					\
        $(GTEST_CPPFLAGS)					\
        $(LIBSSH_CPPFLAGS)					\
        $(NULL)

test_x2go_wrapper_CXXFLAGS =					\
        $(AM_CXXFLAGS)						\
        -DAUTH_CHECK="\"$(abs_builddir)/test-x2go-auth\""	\
        $(GTEST_CXXFLAGS)					\
        $(LIBSSH_CXXFLAGS)					\
        $(NULL)

test_x2go_wrapper_LDFLAGS =					\
        $(GTEST_LDFLAGS)					\
        $(LIBSSH_LDFLAGS)					\
        -pthread						\
        $(NULL)

##########################
# Auth tool
##########################

test_x2go_auth_SOURCES =					\
        test-x2go-auth.c					\
        $(NULL)
