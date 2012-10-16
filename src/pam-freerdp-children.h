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

#ifndef _PAM_FREERDP_CHILDREN_H_
#define _PAM_FREERDP_CHILDREN_H_

#define PAM_TYPE_DOMAIN  1234
#define ALL_GOOD_SIGNAL  "Ar, ready to authenticate cap'n"

void
pam_sm_authenticate_helper (int *stdinpipe, const char* username, const char* rhost, const char* ruser, const char* rdomain);

int
session_socket_handler (struct passwd * pwdent, int readypipe, const char * ruser, const char * rhost, const char * rdomain, const char * password);
#endif //_PAM_FREERDP_CHILDREN_H_
