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

#ifndef _PAM_X2GO_H_
#define _PAM_X2GO_H_

static int unpriveleged_kill (struct passwd * pwdent);
static char * global_domain = NULL;
static char * global_password = NULL;
static char *
get_item (pam_handle_t * pamh, int type);

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv);

pid_t session_pid = 0;

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char ** argv);

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv);

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char ** argv);

#endif
