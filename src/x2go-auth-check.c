/*
 * Copyright © 2012 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
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

#include <libssh/libssh.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>


int
main (int argc, char * argv[])
{
	int verbosity = SSH_LOG_NOLOG;

	char password[512];
	if (argc != 4) {
		printf("Not enough params");
		return -1;
	}

	if (scanf("%511s", password) != 1) {
		return -1;
	}

	if (mlock(password, sizeof(password)) != 0) {
		return -1;
	}

	ssh_session auth_check_ssh_session = ssh_new();

	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity );
	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_USER, argv[2] );

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;
		long port = strtoul(colonloc, NULL, 10);

		char *array[2];
		array[0] = strtok( argv[1], ":" );
		char *hostname = array[0];

		ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_HOST, hostname );

		ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_PORT, &port );
	} else {
		ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_HOST, argv[1] );
	}

	int rc;
	rc = ssh_connect ( auth_check_ssh_session );
	if ( rc != SSH_OK ) {
		fprintf ( stderr, "Error connecting to via SSH: %s\n", ssh_get_error ( auth_check_ssh_session ) );
		ssh_free(auth_check_ssh_session);
		return -1;
	}

	rc = ssh_userauth_password ( auth_check_ssh_session, NULL, password );
	if ( rc != SSH_AUTH_SUCCESS ) {
		fprintf ( stderr, "Error connecting to via SSH: %s\n", ssh_get_error ( auth_check_ssh_session ) );
		ssh_disconnect(auth_check_ssh_session);
		ssh_free(auth_check_ssh_session);
		return -1;
	}

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));

	return 0;
}
