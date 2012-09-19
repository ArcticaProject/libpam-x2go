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

	/* Check username */
	if (strcmp(argv[2], "ruser")) {
		return -1;
	}

	/* Check password */
	if (strcmp(password, "password")) {
		return -1;
	}

	/* Check domain */
	if (strcmp(argv[3], "domain")) {
		return -1;
	}

	/* Check hostname */
	if (strcmp(argv[1], "rhost")) {
		return -1;
	}

	return 0;
}
