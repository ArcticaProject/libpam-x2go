#include <security/pam_modules.h>
#include <security/pam_modutil.h>

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
     return PAM_IGNORE;
}

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
