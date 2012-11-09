/*
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
 * Author: Ted Gould <ted@canonical.com>
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

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include "pam-freerdp-children.h"
#include "auth-check-path.h"

void
pam_sm_authenticate_helper (int *stdinpipe, const char* username, const char* rhost, const char* ruser, const char* rdomain)
{

	dup2(stdinpipe[0], 0);

	char * args[5];

	args[0] = (char *)auth_check_path;
	args[1] = (char *)rhost;
	args[2] = (char *)ruser;
	args[3] = (char *)rdomain;
	args[4] = NULL;

	struct passwd * pwdent = getpwnam(username);
	if (pwdent == NULL) {
		_exit(EXIT_FAILURE);
	}

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

	if (chdir(pwdent->pw_dir) != 0) {
		_exit(EXIT_FAILURE);
	}

	setenv("HOME", pwdent->pw_dir, 1);

	execvp(args[0], args);
	_exit(0);
}

int
session_socket_handler (struct passwd * pwdent, int readypipe, const char * ruser, const char * rhost, const char * rdomain, const char * password)
{
	/* Socket stuff */
	int socketfd = 0;
	struct sockaddr_un socket_addr;

	/* Connected user */
	socklen_t connected_addr_size;
	int connectfd = 0;
	struct sockaddr_un connected_addr;

	/* Our buffer */
	char * buffer = NULL;
	int buffer_len = 0;
	int buffer_fill = 0;

	/* Track write out */
	int writedata = 0;

	/* Track ready writing */
	int readywrite = 0;

	/* Setting groups, but allowing EPERM as if we're not 100% root
	   we might not be able to do this */
	if (setgroups(1, &pwdent->pw_gid) != 0 && errno != EPERM) {
		_exit(EXIT_FAILURE);
	}

	if (setgid(pwdent->pw_gid) < 0 || setuid(pwdent->pw_uid) < 0 ||
			setegid(pwdent->pw_gid) < 0 || seteuid(pwdent->pw_uid) < 0) {
		/* Don't need to clean up yet */
		return EXIT_FAILURE;
	}

	if (clearenv() != 0) {
		/* Don't need to clean up yet */
		return EXIT_FAILURE;
	}

	if (chdir(pwdent->pw_dir) != 0) {
		/* Don't need to clean up yet */
		return EXIT_FAILURE;
	}

	if (rdomain[0] == '\0') {
		rdomain = ".";
	}

	/* Build this up as a buffer so we can just write it and see that
	   very, very clearly */
	buffer_len += strlen(ruser) + 1;    /* Add one for the space */
	buffer_len += strlen(rhost) + 1;    /* Add one for the space */
	buffer_len += strlen(rdomain) + 1;  /* Add one for the space */
	buffer_len += strlen(password) + 1; /* Add one for the NULL */

	if (buffer_len < 5) {
		/* Don't need to clean up yet */
		return EXIT_FAILURE;
	}

	buffer = malloc(buffer_len);

	if (buffer == NULL) {
		/* Don't need to clean up yet */
		return EXIT_FAILURE;
	}

	/* Lock the buffer before writing */
	if (mlock(buffer, buffer_len) != 0) {
		/* We can't lock, we go home */
		goto cleanup;
	}

	buffer_fill = snprintf(buffer, buffer_len, "%s %s %s %s", ruser, password, rdomain, rhost);
	if (buffer_fill > buffer_len) {
		/* This really shouldn't happen, but if for some reason we have an
		   difference between they way that the lengths are calculated we want
		   to catch that. */
		goto cleanup;
	}

	/* Make our socket and bind it */
	socketfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socketfd < 0) {
		goto cleanup;
	}

	memset(&socket_addr, 0, sizeof(struct sockaddr_un));
	socket_addr.sun_family = AF_UNIX;
	strncpy(socket_addr.sun_path, pwdent->pw_dir, sizeof(socket_addr.sun_path) - 1);
	strncpy(socket_addr.sun_path + strlen(pwdent->pw_dir), "/.freerdp-socket", (sizeof(socket_addr.sun_path) - strlen(pwdent->pw_dir)) - 1);

	/* We bind the socket before forking so that we ensure that
	   there isn't a race condition to get to it.  Things will block
	   otherwise. */
	if (bind(socketfd, (struct sockaddr *)&socket_addr, sizeof(struct sockaddr_un)) < 0) {
		goto cleanup;
	}

	/* Set the socket file permissions to be 600 and the user and group
	   to be the guest user.  NOTE: This won't protect on BSD */
	if (chmod(socket_addr.sun_path, S_IRUSR | S_IWUSR) != 0 ||
			chown(socket_addr.sun_path, pwdent->pw_uid, pwdent->pw_gid) != 0) {
		goto cleanup;
	}

	if (listen(socketfd, 1) < 0) {
		goto cleanup;
	}

	readywrite = write(readypipe, ALL_GOOD_SIGNAL, strlen(ALL_GOOD_SIGNAL) + 1);
	if (readywrite != strlen(ALL_GOOD_SIGNAL) + 1) {
		goto cleanup;
	}

	connected_addr_size = sizeof(struct sockaddr_un);
	connectfd = accept(socketfd, (struct sockaddr *)&connected_addr, &connected_addr_size);
	if (connectfd < 0) {
		goto cleanup;
	}

	writedata = write(connectfd, buffer, buffer_len);

cleanup:
	if (socketfd != 0) {
		close(socketfd);
	}
	if (connectfd != 0) {
		close(connectfd);
	}

	if (buffer != NULL) {
		memset(buffer, 0, buffer_len);
		munlock(buffer, buffer_len);
		free(buffer);
		buffer = NULL;
	}

	/* This should be only true on the write, so we can use this to check
	   out as writedata is init to 0 */
	if (writedata == buffer_len) {
		_exit (0);
	}

	_exit(EXIT_FAILURE);
}

