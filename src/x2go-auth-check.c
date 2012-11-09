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

#include <freerdp/freerdp.h>
#include <freerdp/channels/channels.h>
#include <string.h>

void
auth_context_new (freerdp * instance, rdpContext * context)
{
	context->channels = freerdp_channels_new();
	return;
}

void
auth_context_free (freerdp * instance, rdpContext * context)
{
	return;
}

boolean
auth_pre_connect (freerdp * instance)
{
	freerdp_channels_pre_connect(instance->context->channels, instance);
	return true;
}

boolean
auth_post_connect (freerdp * instance)
{
	freerdp_channels_post_connect(instance->context->channels, instance);
	return true;
}

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

	freerdp_channels_global_init();

	freerdp * instance = freerdp_new();

	instance->PreConnect = auth_pre_connect;
	instance->PostConnect = auth_post_connect;

	instance->context_size = sizeof(rdpContext);
	instance->ContextNew = auth_context_new;
	instance->ContextFree = auth_context_free;

	freerdp_context_new(instance);

	instance->settings->hostname = argv[1];
	instance->settings->username = argv[2];
	instance->settings->domain = argv[3];
	instance->settings->password = password;

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;

		instance->settings->port = strtoul(colonloc, NULL, 10);
	}

	int retval = -1;
	if (freerdp_connect(instance)) {
		freerdp_disconnect(instance);
		retval = 0;
	}

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));

	return retval;
}
