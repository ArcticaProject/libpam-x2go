/*
 * Copyright © 2012-2013 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
 * Copyright © 2012 Canonical Ltd.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
 * Author libpam-freerdp (where we forked from): Ted Gould <ted@canonical.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include "pam-x2go.h"

#include "pam-x2go-children.h"
#include "auth-check-path.h"

static int unpriveleged_kill (struct passwd * pwdent);

static char * global_x2go_user = NULL;
static char * global_x2go_server = NULL;
static char * global_x2go_command = NULL;
/* FIXME? This is a work around to the fact that PAM seems to be clearing
   the auth token between authorize and open_session.  Which then requires
   us to save it.  Seems like we're the wrong people to do it, but we have
   no choice */
static char * global_password = NULL;

/* Either grab a value or prompt for it */
static char *
get_item (pam_handle_t * pamh, int type)
{
	/* Check to see if we just have the value.  If we do, great
	   let's dup it some we're consistently allocating memory */
	if ((type == PAM_USER) || (type == PAM_AUTHTOK)) {
		/* If it's not an X2Go parameter type we can use the PAM functions because the PAM
		   functions don't support X2Go parameters */
		char * value = NULL;
		if (pam_get_item(pamh, type, (const void **)&value) == PAM_SUCCESS && value != NULL) {
			return value;
		}
		if (type == PAM_AUTHTOK && global_password != NULL) {
			/* If we're looking for a password, we didn't get one, before
			   prompting see if we've got a global one. */
			return global_password;
		}
	} else {
		/* Here we deal with all X2Go specific parameters */
		if ((type == PAM_TYPE_X2GO_USER) && (global_x2go_user != NULL)) {
			return global_x2go_user;
		}
		if ((type == PAM_TYPE_X2GO_SERVER) && (global_x2go_server != NULL)) {
			return global_x2go_server;
		}
		if ((type == PAM_TYPE_X2GO_COMMAND) && (global_x2go_command != NULL)) {
			return global_x2go_command;
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
		message.msg = PAM_X2GO_PROMPT_GUESTLOGIN;
		break;
	case PAM_TYPE_X2GO_USER:
		message.msg = PAM_X2GO_PROMPT_USER;
		break;
	case PAM_TYPE_X2GO_SERVER:
		message.msg = PAM_X2GO_PROMPT_HOST;;
		break;
	case PAM_AUTHTOK:
		message.msg = PAM_X2GO_PROMPT_PASSWORD;
		message.msg_style = PAM_PROMPT_ECHO_OFF;
		break;
	case PAM_TYPE_X2GO_COMMAND:
		message.msg = PAM_X2GO_PROMPT_COMMAND;
		break;
	default:
		return NULL;
	}

	struct pam_conv * conv = NULL;
	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
		return NULL;
	}

	struct pam_response * responses = NULL;
	if (conv->conv(1, &pmessage, &responses, conv->appdata_ptr) != PAM_SUCCESS || responses == NULL) {
		return NULL;
	}

	char * promptval = responses->resp;
	free(responses);

	/* If we didn't get anything, just move on */
	if (promptval == NULL) {
		return NULL;
	}

	if (type == PAM_AUTHTOK) {
		if (mlock(promptval, strlen(promptval) + 1) != 0) {
			free(promptval);
			return NULL;
		}
	}

	if (type == PAM_TYPE_X2GO_SERVER) {
		char * subloc = strstr(promptval, "://");
		if (subloc != NULL) {
			char * original = promptval;
			char * newish = subloc + strlen("://");
			char * endslash = strstr(newish, "/");

			if (endslash != NULL) {
				endslash[0] = '\0';
			}

			promptval = strdup(newish);
			free(original);
		}
	}

	char * retval = NULL;
	if (promptval != NULL) { /* Can't believe it really would be at this point, but let's be sure */
		if ((type == PAM_USER) || (type == PAM_AUTHTOK)) {
			/* We can only use the PAM functions for types supported by PAM */
			pam_set_item(pamh, type, (const void *)promptval);
			/* We're returning the value saved by PAM so we can clear promptval */
			pam_get_item(pamh, type, (const void **)&retval);
		}
		/* Here we deal with all X2Go specific parameter types */
		if (type == PAM_TYPE_X2GO_USER) {
			/* The remote user can be saved globally */
			if (global_x2go_user != NULL) {
				free(global_x2go_user);
			}
			global_x2go_user = strdup(promptval);
			retval = global_x2go_user;
		}
		if (type == PAM_TYPE_X2GO_SERVER) {
			/* The remote server can be saved globally */
			if (global_x2go_server != NULL) {
				free(global_x2go_server);
			}
			global_x2go_server = strdup(promptval);
			retval = global_x2go_server;
		}
		if (type == PAM_TYPE_X2GO_COMMAND) {
			/* The remote command can be saved globally */
			if (global_x2go_command != NULL) {
				free(global_x2go_command);
			}
			global_x2go_command = strdup(promptval);
			retval = global_x2go_command;
		}
		if (type == PAM_AUTHTOK) {
			/* We also save the password globally if we've got one */
			if (global_password != NULL) {
				memset(global_password, 0, strlen(global_password));
				munlock(global_password, strlen(global_password) + 1);
				free(global_password);
			}
			global_password = strdup(promptval);
			if (mlock(global_password, strlen(global_password) + 1) != 0) {
				/* Woah, can't lock it.  Can't keep it. */
				free(global_password);
				global_password = NULL;
			} else {
				retval = global_password;
			}
		}

		if (type == PAM_AUTHTOK) {
			memset(promptval, 0, strlen(promptval) + 1);
			munlock(promptval, strlen(promptval) + 1);
		}

		free(promptval);
	}

	return retval;
}

#define GET_ITEM(val, type) \
	if ((val = get_item(pamh, type)) == NULL) { \
		retval = PAM_AUTH_ERR; \
		goto done; \
	}

/* Authenticate.  We need to make sure we have a user account, that
   there are remote accounts and then verify them with X2Go */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int __attribute__((unused)) flags, int __attribute__((unused)) argc, const char __attribute__((unused)) **argv)
{
	char * username = NULL;
	char * password = NULL;
	char * ruser = NULL;
	char * rhost = NULL;
	char * rcommand = NULL;
	int retval = PAM_IGNORE;

	/* Get all the values, or prompt for them, or return with
	   an auth error */
	GET_ITEM(username, PAM_USER);
	GET_ITEM(ruser,    PAM_TYPE_X2GO_USER);
	GET_ITEM(rhost,    PAM_TYPE_X2GO_SERVER);
	GET_ITEM(rcommand, PAM_TYPE_X2GO_COMMAND);
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
			pam_sm_authenticate_helper (stdinpipe, username, rhost, ruser, rcommand);
			break;
		}
		case -1: { /* fork'n error! */
			retval = PAM_SYSTEM_ERR;
			break;
		}
		default: {
			int forkret = 0;
			int bytesout = 0;

			bytesout += write(stdinpipe[1], password, strlen(password));
			bytesout += write(stdinpipe[1], "\n", 1);

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

	/* Return our status */
done:
	return retval;
}



pid_t session_pid = 0;
/* Open Session.  Here we need to fork a little process so that we can
   give the credentials to the session itself so that it can startup the
   PyHoca (X2Go) client for the login */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int __attribute__((unused)) flags, int __attribute__((unused)) argc, const char __attribute__((unused)) **argv)
{
	char * username = NULL;
	char * password = NULL;
	char * ruser = NULL;
	char * rhost = NULL;
	char * rcommand = NULL;
	int retval = PAM_SUCCESS;

	/* Get all the values, or prompt for them, or return with
	   an auth error */
	GET_ITEM(username, PAM_USER);
	GET_ITEM(ruser,    PAM_TYPE_X2GO_USER);
	GET_ITEM(rhost,    PAM_TYPE_X2GO_SERVER);
	GET_ITEM(rcommand, PAM_TYPE_X2GO_COMMAND);
	GET_ITEM(password, PAM_AUTHTOK);

	struct passwd * pwdent = getpwnam(username);
	if (pwdent == NULL) {
		retval = PAM_SYSTEM_ERR;
		goto done;
	}

	if (session_pid != 0) {
		unpriveleged_kill(pwdent);
	}

	int sessionready[2];
	if (pipe(sessionready) != 0) {
		retval = PAM_SYSTEM_ERR;
		goto done;
	}

	pid_t pid = fork();
	if (pid == 0) {

		int ret = session_socket_handler(pwdent, sessionready[1], ruser, rhost, rcommand, password);

		close(sessionready[1]);
		_exit(ret);
	} else if (pid < 0) {
		close(sessionready[0]);
		close(sessionready[1]);

		retval = PAM_SYSTEM_ERR;
	} else {
		char readbuffer[strlen(ALL_GOOD_SIGNAL) + 1];
		int readlen = 0;

		readlen = read(sessionready[0], readbuffer, strlen(ALL_GOOD_SIGNAL) + 1);

		close(sessionready[0]);

		if (readlen == strlen(ALL_GOOD_SIGNAL) + 1) {
			session_pid = pid;
		} else {
			retval = PAM_SYSTEM_ERR;
		}
	}

done:
    return retval;
}

/* Close Session.  Make sure our little guy has died so he doesn't become
   a zombie and eat things. */
PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int __attribute__((unused)) flags, int __attribute__((unused)) argc, const char __attribute__((unused)) **argv)
{
	if (session_pid == 0) {
		return PAM_IGNORE;
	}

	char * username = NULL;
	int retval = PAM_SUCCESS;

	GET_ITEM(username, PAM_USER);

	struct passwd * pwdent = getpwnam(username);
	if (pwdent == NULL) {
		retval = PAM_SYSTEM_ERR;
		goto done;
	}

	retval = unpriveleged_kill(pwdent);

done:
	return retval;
}

/* Drop privs and try to kill the process with the PID of session_pid.
   This ensures that we don't kill something important if there is PID wrap
   around.  */
static int
unpriveleged_kill (struct passwd * pwdent)
{
	int retval = PAM_SUCCESS;

	pid_t pid = fork();
	if (pid == 0) {
		/* Setting groups, but allowing EPERM as if we're not 100% root
		   we might not be able to do this */
		if (setgroups(1, &pwdent->pw_gid) != 0 && errno != EPERM) {
			_exit(EXIT_FAILURE);
		}

		if (setgid(pwdent->pw_gid) < 0 || setuid(pwdent->pw_uid) < 0 ||
				setegid(pwdent->pw_gid) < 0 || seteuid(pwdent->pw_uid) < 0) {
			_exit(EXIT_FAILURE);
		}

		if (clearenv() != 0) {
			_exit(EXIT_FAILURE);
		}

		int killval = kill(session_pid, SIGKILL);
		session_pid = 0;

		if (killval != 0) {
			printf("Unable to kill\n");
		}

		/* NOTE: We're ignoring whether we could kill it or not.  It'd be nice to
		   track that but there are a lot of reason that we could fail there and
		   it's not a bad thing.  Really we're attempting a best effort to clean up
		   we won't be able to guarantee it. */
		_exit(EXIT_SUCCESS);
	} else if (pid < 0) {
		retval = PAM_SYSTEM_ERR;
	} else {
		int forkret = 0;

		if (waitpid(pid, &forkret, 0) < 0) {
			retval = PAM_SYSTEM_ERR;
		}
	}

	/* We reset this no matter.  If we error'd trying to do it, we don't
	   want to try again.  We'll just return the error for this time. */
	session_pid = 0;

	return retval;
}

/* LightDM likes to have this function around, but we don't need it as we
   don't have a token hanging around. */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t __attribute__((unused)) *pamh, int __attribute__((unused)) flags, int __attribute__((unused)) argc, const char __attribute__((unused)) **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_x2go_modstruct = {
     "pam_x2go",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif
