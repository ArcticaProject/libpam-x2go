/*
 * Copyright © 2012 Canonical Ltd. All rights reserved.
 *
 * Author(s): David Barth <david.barth@canonical.com>
 *
 */

#ifndef __MOCK_PAM_H__
#define __MOCK_PAM_H__

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#define PAM_NUM_ITEMS PAM_AUTHTOK_TYPE

typedef struct pam_handle pam_handle_t;

pam_handle_t *pam_handle_new (void);
int pam_get_item (const pam_handle_t *pamh, int type, const void **value);
int pam_set_item (pam_handle_t *pamh, int type, const void *value);

#endif
