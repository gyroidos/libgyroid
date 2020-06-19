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


#ifndef _HANDLER_CHOWN_H_
#define _HANDLER_CHOWN_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <stdint.h>

#include <linux/limits.h>

#include <stdio.h>

ssize_t do_alloc_readlink(char *pathname, char **buf) {
	ssize_t pathlen = 0;
	*buf = malloc(PATH_MAX + 1);

	pathlen = readlink(pathname, *buf, PATH_MAX + 1);

	if (pathlen < 1) {
		printf("Failed to readlink");

		return -1;
	}

	buf[pathlen] = 0;

	return pathlen;
}

static inline uint32_t do_lchown (char *pathname, uint32_t owner, uint32_t group, int resolve_link) {
	int scret = -1;
	char *pathbuf = NULL;

	struct stat stats;
	int res = lstat(pathname, &stats);

	if(res < 0) {
		return -1;
	}

	if (S_ISLNK(stats.st_mode) && resolve_link) {

		ssize_t pathlen = do_alloc_readlink(pathname, &pathbuf);

		if (pathlen < 1) {
			return -1;
		}
	} else {
		pathbuf = pathname;
	}


	lchown(pathbuf, owner, group);

	return scret;
}




static inline uint64_t chown_handler (void * arg0, void* arg1, void * arg2) {
	uint64_t scret = -1;
	char *pathname = NULL;
	uint32_t owner = -1, group = -1;

	pathname = (char *) arg0;
	owner = (uint32_t) arg1;
	group = (uint32_t) arg2;

	scret = do_lchown(pathname, owner, group, 1);

	return scret;
}

#endif // _HANDLER_CHOWN_H_
