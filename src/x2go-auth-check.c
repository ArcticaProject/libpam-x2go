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

int
main (int argc, char * argv[])
{
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

	auth_check_ssh_session = ssh_new();

	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_HOST, argv[1]; );
	ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_USER, argv[2]; );

	rc = ssh_connect (ssh_session);

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;

		ssh_options_set ( auth_check_ssh_session, SSH_OPTIONS_PORT, strtoul(colonloc, NULL, 10); );
	}

	if (ssh_connect (ssh_session)) {
		int rc = ssh_userauth_password ( auth_check_ssh_session, NULL, password );
		ssh_disconnect(ssh_session);
	}

	int retval = -1;
	if ( rc == SSH_AUTH_SUCCESS )
	{
		retval = 0;
	}

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));

	return retval;
}
