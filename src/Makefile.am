
pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_freerdp.la

pam_freerdp_la_SOURCES = \
	pam-freerdp.c

pam_freerdp_la_LDFLAGS = \
	-no-undefined \
	-module \
	-avoid-version

pam_freerdp_la_LIBADD = \
	-lpam

pam_freerdp_la_CFLAGS = \
	-Wall -Werror
