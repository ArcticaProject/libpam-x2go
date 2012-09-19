
pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_freerdp.la

pam_freerdp_la_SOURCES = \
	pam-freerdp.c

pam_freerdp_la_LDFLAGS = \
	-no-undefined \
	-module \
	-avoid-version \
	$(COVERAGE_LDFLAGS)

pam_freerdp_la_LIBADD = \
	-lpam

pam_freerdp_la_CFLAGS = \
	-Wall -Werror \
	-DAUTH_CHECK="\"$(pkglibexecdir)/freerdp-auth-check\"" \
	$(COVERAGE_CFLAGS)

pkglibexec_PROGRAMS = \
	freerdp-auth-check

freerdp_auth_check_SOURCES = \
	freerdp-auth-check.c
freerdp_auth_check_CFLAGS = \
	$(FREERDP_CFLAGS) \
	$(COVERAGE_CFLAGS)
freerdp_auth_check_LDADD = \
	$(FREERDP_LIBS)
freerdp_auth_check_LDFLAGS = \
	$(COVERAGE_LDFLAGS)
