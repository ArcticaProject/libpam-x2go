/*
 * Copyright © 2012 Canonical Ltd. All rights reserved.
 *
 * Author(s): David Barth <david.barth@canonical.com>
 *
 */

#include <stdlib.h>
#include <string.h>

#include "mock_pam.h"

struct pam_handle {
	void *item[PAM_NUM_ITEMS];

	struct pam_conv *conv;

	/* note: the other fields have been omitted */
};

int fake_conv (int num_msg, const struct pam_message **msg,
				struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *response = NULL;
	response = malloc (sizeof (struct pam_response));

	if (response == NULL)
		return PAM_BUF_ERR;

	response->resp_retcode = 0;

	if (strcmp((*msg)->msg, "login:") == 0)
		response->resp = strdup ("guest"); /* IMPORTANT: this needs to be in /etc/passwd */
	else if (strcmp((*msg)->msg, "remote login:") == 0)
		response->resp = strdup ("ruser");
	else if (strcmp((*msg)->msg, "remote host:") == 0)
		response->resp = strdup ("protocol://rhost/dummy");
	else if (strcmp((*msg)->msg, "password:") == 0)
		response->resp = strdup ("password");
	else if (strcmp((*msg)->msg, "domain:") == 0)
		response->resp = strdup ("domain");
	else
		return PAM_SYMBOL_ERR; /* leaks... */

	*resp = response;

	return PAM_SUCCESS;
}

struct pam_conv static_conv = { &fake_conv, (void *)NULL };

pam_handle_t *pam_handle_new (void)
{
	pam_handle_t *newh = malloc (sizeof (pam_handle_t));

	if (newh != NULL) {
		newh->conv = &static_conv;
		memset(newh->item, 0, sizeof(void *) * PAM_NUM_ITEMS);
	}

	return newh;
}

int pam_get_item (const pam_handle_t *pamh, int type, const void **value)
{
	if (pamh == NULL)
		return PAM_SYSTEM_ERR;

	if (type == PAM_CONV)
		*value = pamh->conv;
	else  if (pamh->item[type] != NULL)
		*value = pamh->item[type];
	else 
		*value = NULL; /* will result in a prompt conversation */

	return PAM_SUCCESS;
}

int pam_set_item (pam_handle_t *pamh, int type, const void *value)
{
	if (pamh == NULL)
		return PAM_SYSTEM_ERR;

	void **slot, *tmp;
	size_t nsize, osize;

	slot = &pamh->item[type];
	osize = nsize = 0;

	if (*slot != NULL)
		osize = strlen((const char *)*slot) + 1;
	if (value != NULL)
		nsize = strlen((const char *)value) + 1;

	if (*slot != NULL) {
		memset(*slot, 0xd0, osize);
		free(*slot);
	}

	if (value != NULL) {
		if ((tmp = malloc(nsize)) == NULL)
			return PAM_BUF_ERR;
		memcpy(tmp, value, nsize);
	} else {
		tmp = NULL;
	}
	*slot = tmp;

	return PAM_SUCCESS;
}
