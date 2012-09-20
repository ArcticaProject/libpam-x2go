/*
 * Copyright © 2012 Canonical Ltd. All rights reserved.
 *
 * Author(s): David Barth <david.barth@canonical.com>
 *
 */

#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static struct passwd guest = { "guest",
							   "password",
							   500, 500,
							   "M. Guest",
							   "/tmp",
							   "/bin/true" };
struct passwd *
getpwnam (const char *username)
{ return &guest; }

int
setgroups(size_t size, const gid_t *list)
{
	errno = EPERM;
	return -1;
}

int
setgid(gid_t gid)
{ return 0; }

int
setuid(uid_t uid)
{ return 0; }

int
setegid(gid_t gid)
{ return 0; }

int
seteuid(uid_t uid)
{ return 0; }

int chmod(const char *path, mode_t mode)
{ return 0; }

int chown(const char *path, uid_t owner, gid_t group)
{ return 0; }

