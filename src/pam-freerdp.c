#include <stdlib.h>
#include <string.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#define PAM_TYPE_DOMAIN  1234

/* Either grab a value or prompt for it */
static char *
get_item (pam_handle_t * pamh, int type)
{
	/* Check to see if we just have the value.  If we do, great
	   let's dup it some we're consitently allocating memory */
	if (type != PAM_TYPE_DOMAIN) {
		char * value;
		if (pam_get_item(pamh, type, (const void **)&value) == PAM_SUCCESS) {
			return strdup(value);
		}
	}
	/* Now we need to prompt */

	/* Build up the message we're prompting for */
	struct pam_message message[1];
	message[0].msg_style = PAM_PROMPT_ECHO_ON;

	switch (type) {
	case PAM_USER:
		message[0].msg = "login:";
		break;
	case PAM_RUSER:
		message[0].msg = "remote login:";
		break;
	case PAM_RHOST:
		message[0].msg = "remote host:";
		break;
	case PAM_AUTHTOK:
		message[0].msg = "password:";
		message[0].msg_style = PAM_PROMPT_ECHO_OFF;
		break;
	case PAM_TYPE_DOMAIN:
		message[0].msg = "remote domain:";
		break;
	default:
		return NULL;
	}

	struct pam_conv conv;
	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
		return NULL;
	}

	struct pam_response * responses = NULL;
	if (conv.conv(1, (const struct pam_message **)&message, &responses, conv.appdata_ptr) != PAM_SUCCESS) {
		return NULL;
	}

	char * retval = responses->resp;
	free(responses);
	return retval;
}

#define GET_ITEM(val, type) \
	if ((val = get_item(pamh, type)) == NULL) { \
		retval = PAM_AUTH_ERR; \
		goto done; \
	}

/* Authenticate.  We need to make sure we have a user account, that
   there are remote accounts and then verify them with FreeRDP */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char * username = NULL;
	char * password = NULL;
	char * ruser = NULL;
	char * rhost = NULL;
	char * rdomain = NULL;
	int retval = PAM_IGNORE;

	GET_ITEM(username, PAM_USER);
	GET_ITEM(ruser,    PAM_RUSER);
	GET_ITEM(rhost,    PAM_RHOST);
	GET_ITEM(rdomain,  PAM_TYPE_DOMAIN);
	GET_ITEM(password, PAM_AUTHTOK);

done:
	if (username != NULL) { free(username); }
	if (password != NULL) { free(password); }
	if (ruser != NULL)    { free(ruser); }
	if (rhost != NULL)    { free(rhost); }
	if (rdomain != NULL)  { free(rdomain); }

	return retval;
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
