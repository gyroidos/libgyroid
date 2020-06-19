/*
 * This file is part of GyroidOS
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */


#ifndef _HANDLER_H_
#define _HANDLER_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <linux/limits.h>

#include "handler_chown.h"

static inline uint64_t creat_handler (char *path, mode_t mode) {
	int fd = -1;

	if(-1 == (fd = open(path, O_CREAT|O_WRONLY|O_TRUNC))) {
		return -1;
	}

	return chmod(path, mode);
}


static inline uint64_t execveat_handler(void * arg0, void * arg1, void * arg2, void * arg3, void * arg4)
{
	char *pathname = (char *) arg1;
	char **argv = (char **) arg2;
	char **envp = (char **) arg3;
	uint64_t flags = (uint64_t) arg4;
	unsigned int fd_reg = (unsigned int) arg0;
	int fd = 0;
	int pathlen = 0;

	fd = (uint32_t) fd_reg;

	char *completepath = pathname;

	// linux/fs/exec.c: do_execveat_common
	if (fd != AT_FDCWD && pathname[0] != '/') {
		if (pathname[0] == '\0')
			pathlen = asprintf(&completepath, "/dev/fd/%d", fd); 
		else {
			pathlen = asprintf(&completepath, "/dev/fd/%d/%s",
				fd, pathname);
		}

		if (pathname[0] != '\0') {
			struct stat stat;
			memset(&stat, 0, sizeof(struct stat));

			if (0 > lstat(completepath, &stat))
				return -1;

			if (S_ISLNK(stat.st_mode)) {
				return -1;
			}
		}

		if (0 > pathlen) {
			return -1;
		}
	}

	return execve(completepath, argv, envp);
}

#endif //end _HANDLER_H_
