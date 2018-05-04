NULL =

pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_x2go.la

pam_x2go_la_SOURCES =						\
        auth-check-path.c auth-check-path.h			\
        pam-x2go.c						\
        pam-x2go-children.c					\
        $(NULL)

pam_x2go_la_LDFLAGS =						\
        -no-undefined						\
        -module							\
        -avoid-version						\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)

pam_x2go_la_CFLAGS =						\
        -Wall -Werror						\
        -DAUTH_CHECK="\"$(libexecdir)/x2go-auth-check\""	\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

pam_x2go_la_CPPFLAGS =						\
        -I$(top_srcdir)/include					\
        $(NULL)

pam_x2go_la_LIBADD =						\
	-lpam							\
        $(NULL)

pam_x2goincludedir = $(includedir)/security/
pam_x2goinclude_HEADERS =					\
        $(top_srcdir)/include/pam-x2go.h			\
        $(NULL)

libexec_PROGRAMS =						\
        x2go-auth-check						\
        $(NULL)

x2go_auth_check_SOURCES =					\
        x2go-auth-check.c					\
        $(NULL)

x2go_auth_check_CFLAGS =					\
        $(LIBSSH_CFLAGS)					\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

x2go_auth_check_LDADD =						\
        $(LIBSSH_LIBS)						\
        $(NULL)

x2go_auth_check_LDFLAGS =					\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)
