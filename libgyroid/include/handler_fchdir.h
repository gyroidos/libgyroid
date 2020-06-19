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


#ifndef _HANDLER_FCHDIR_H_
#define _HANDLER_FCHDIR_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <limits.h>
#include <string.h>

#include "util.h"


static inline pid_t fchdir_handler(void){
	void *fd;
	char fd_link[PATH_MAX];
	char fd_real_link[PATH_MAX];

	__asm__ volatile (
		"mov %%rdi, %0\t\n"
		: "=r" (fd)
	);

	sprintf(fd_link,"/proc/self/fd/%ld",(int64_t) fd);

	if(readlink(fd_link,fd_real_link,PATH_MAX) == -1)
	{
		return -1;
	}

	chdir(fd_real_link);

}

#endif // _HANDLER_FCHDIR_H_
