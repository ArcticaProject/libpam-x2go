pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_x2go.la

pam_x2go_la_SOURCES = \
	auth-check-path.c auth-check-path.h

pam_x2go_la_LDFLAGS = \
	-no-undefined \
	-module \
	-avoid-version \
	$(COVERAGE_LDFLAGS)

pam_x2go_la_CFLAGS = \
	-Wall -Werror \
	-DAUTH_CHECK="\"$(pkglibexecdir)/x2go-auth-check\"" \
	$(COVERAGE_CFLAGS)

pam_x2go_la_LIBADD = \
	$(builddir)/libssh.a

noinst_LTLIBRARIES = \
	libssh.a

libx2gocore_la_SOURCES = \
	pam-x2go.c \
	pam-x2go-children.c
libx2gocore_la_CFLAGS = \
	-Wall -Werror \
	$(COVERAGE_CFLAGS)
libx2gocore_la_LIBADD = \
	-lpam
libx2gocore_la_LDFLAGS = \
	$(COVERAGE_LDFLAGS)

pkglibexec_PROGRAMS = \
	x2go-auth-check

x2go_auth_check_SOURCES = \
	x2go-auth-check.c
x2go_auth_check_CFLAGS = \
	$(x2go_CFLAGS) \
	$(COVERAGE_CFLAGS)
x2go_auth_check_LDADD = \
	$(x2go_LIBS)
x2go_auth_check_LDFLAGS = \
	$(COVERAGE_LDFLAGS)
