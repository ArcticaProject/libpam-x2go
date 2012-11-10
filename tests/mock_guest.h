/*
 * Copyright © 2012 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>.
 * Copyright © 2012 Canonical Ltd. All rights reserved.
 *
 * Author(s): Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
 *            David Barth <david.barth@canonical.com>
 *
 */

#ifndef __MOCK_GUEST_H__
#define __MOCK_GUEST_H__

#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

struct passwd *getpwnam (const char *username);
int setgroups(size_t size, const gid_t *list);
int setgid(gid_t gid);
int setuid(uid_t uid);
int setegid(gid_t gid);
int seteuid(uid_t uid);
int chmod(const char *path, mode_t mode);
int chown(const char *path, uid_t owner, gid_t group);
int execvp(const char *file, char *const argv[]);
int socket_sucker();

#endif
