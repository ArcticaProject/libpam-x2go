#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>

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
		char * value = NULL;
		if (pam_get_item(pamh, type, (const void **)&value) == PAM_SUCCESS && value != NULL) {
			return strdup(value);
		}
	}
	/* Now we need to prompt */

	/* Build up the message we're prompting for */
	struct pam_message message;
	const struct pam_message * pmessage = &message;

	message.msg = NULL;
	message.msg_style = PAM_PROMPT_ECHO_ON;

	switch (type) {
	case PAM_USER:
		message.msg = "login:";
		break;
	case PAM_RUSER:
		message.msg = "remote login:";
		break;
	case PAM_RHOST:
		message.msg = "remote host:";
		break;
	case PAM_AUTHTOK:
		message.msg = "password:";
		message.msg_style = PAM_PROMPT_ECHO_OFF;
		break;
	case PAM_TYPE_DOMAIN:
		message.msg = "domain:";
		break;
	default:
		return NULL;
	}

	struct pam_conv * conv = NULL;
	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
		return NULL;
	}

	struct pam_response * responses = NULL;
	if (conv->conv(1, &pmessage, &responses, conv->appdata_ptr) != PAM_SUCCESS) {
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

/* TODO: Make this a build thing */
#define XFREERDP "/usr/bin/xfreerdp"

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

	/* Get all the values, or prompt for them, or return with
	   an auth error */
	GET_ITEM(username, PAM_USER);
	GET_ITEM(ruser,    PAM_RUSER);
	GET_ITEM(rhost,    PAM_RHOST);
	GET_ITEM(rdomain,  PAM_TYPE_DOMAIN);
	GET_ITEM(password, PAM_AUTHTOK);

	int stdinpipe[2];
	if (pipe(stdinpipe) != 0) {
		retval = PAM_SYSTEM_ERR;
		goto done;
	}

	/* At this point we should have the values, let's check the auth */
	pid_t pid;
	switch (pid = fork()) {
	case 0: { /* child */
		dup2(stdinpipe[0], 0);

		char * args[7];

		args[0] = XFREERDP;
		args[1] = "--plugin";
		args[2] = "rdpsnd.so";
		args[3] = "--no-nla";
		args[4] = "-f";
		args[5] = "--from-stdin";
		args[6] = NULL;

		struct passwd * pwdent = getpwnam(username);
		if (pwdent == NULL) {
			_exit(EXIT_FAILURE);
		}

		if (setgid(pwdent->pw_gid) < 0 || setuid(pwdent->pw_uid) < 0 ||
				setegid(pwdent->pw_gid) < 0 || seteuid(pwdent->pw_uid) < 0) {
			_exit(EXIT_FAILURE);
		}

		setenv("HOME", pwdent->pw_dir, 1);

		execvp(args[0], args);
		_exit(EXIT_FAILURE);
		break;
	}
	case -1: { /* fork'n error! */
		retval = PAM_SYSTEM_ERR;
		break;
	}
	default: {
		int forkret = 0;
		int bytesout = 0;

		bytesout += write(stdinpipe[1], ruser, strlen(ruser));
		bytesout += write(stdinpipe[1], " ", 1);
		bytesout += write(stdinpipe[1], password, strlen(password));
		bytesout += write(stdinpipe[1], " ", 1);
		bytesout += write(stdinpipe[1], rdomain, strlen(rdomain));
		bytesout += write(stdinpipe[1], " ", 1);
		bytesout += write(stdinpipe[1], rhost, strlen(rhost));
		bytesout += write(stdinpipe[1], " ", 1);

		close(stdinpipe[1]);

		if (waitpid(pid, &forkret, 0) < 0 || bytesout == 0) {
			retval = PAM_SYSTEM_ERR;
		} else if (forkret == 0) {
			retval = PAM_SUCCESS;
		} else {
			retval = PAM_AUTH_ERR;
		}
	}
	}

	/* Free Memory and return our status */
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

struct pam_module _pam_freerdp_modstruct = {
     "pam-freerdp",
     pam_sm_authenticate,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif
