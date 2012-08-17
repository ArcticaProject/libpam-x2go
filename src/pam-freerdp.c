#include <stdlib.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>

/* Authenticate.  We need to make sure we have a user account, that
   there are remote accounts and then verify them with FreeRDP */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char * username = NULL;
	const char * password = NULL;
	const char * ruser = NULL;
	const char * rhost = NULL;
	//const char * rdomain = NULL;

	if (pam_get_item(pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS || username == NULL) {
		/* If we don't have a local username then bah, we don't want
		   to deal with this and we're going to fail.  This means that
		   the pam-local-account failed.

		   NOTE: We're not using pam_get_user() here because we don't want
		   to prompt, we want to only work in the case where the username is
		   built for us. */
		return PAM_AUTH_ERR;
	}

	if (pam_get_item(pamh, PAM_RUSER, (const void **)&ruser) != PAM_SUCCESS || ruser == NULL) {
		return PAM_AUTH_ERR;
	}

	if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) != PAM_SUCCESS || rhost == NULL) {
		return PAM_AUTH_ERR;
	}

	if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS || password == NULL) {
		return PAM_AUTH_ERR;
	}

	return PAM_IGNORE;
}

/* Open Session.  Here we need to fork a little process so that we can
   give the credentials to the session itself so that it can startup the
   xfreerdp viewer for the login */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
     return PAM_IGNORE;
}

/* Close Session.  Make sure our little guy has died so he doesn't become
   a zombie and eat things. */
PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

struct pam_module _pam_temp_account_modstruct = {
     "pam-freerdp",
     pam_sm_authenticate,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif
