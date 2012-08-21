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
	instance->settings->ignore_certificate = true;

	if (freerdp_connect(instance)) {
		freerdp_disconnect(instance);
		return 0;
	} else {
		return -1;
	}
}
