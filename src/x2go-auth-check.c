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

#include <libssh/libssh.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>


int
main (int argc, char * argv[])
{
	char password[512];
	if (argc != 4) {
		printf("Not enough params");
		return -1;
	}

	printf ("1\n");

	if (scanf("%511s", password) != 1) {
		return -1;
	}

	printf ("2\n");

	if (mlock(password, sizeof(password)) != 0) {
		return -1;
	}

	printf ("3\n");

	ssh_session auth_check_ssh_session = ssh_new();

	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_HOST, &argv[1] );
	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_USER, &argv[2] );

	printf ("host: %s\n", argv[1]);
	printf ("user: %s\n", argv[2]);

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;

		long port = strtoul(colonloc, NULL, 10);
		ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_PORT, &port );
		printf ("port: %i\n", port);
	}

	printf ("4\n");

	int rc;
	rc = ssh_connect (auth_check_ssh_session);
	if ( rc != SSH_OK ) {
		ssh_free(auth_check_ssh_session);
		return -1;
	}

	rc = ssh_userauth_password ( auth_check_ssh_session, NULL, password );
	if ( rc != SSH_AUTH_SUCCESS ) {
		ssh_disconnect(auth_check_ssh_session);
		ssh_free(auth_check_ssh_session);
		return -1;
	}

	printf ("5\n");

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));

	return 0;
}
