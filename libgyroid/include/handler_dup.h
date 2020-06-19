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


#ifndef _HANDLER_DUP_H_
#define _HANDLER_DUP_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <syscall.h>

#include <signal.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <linux/limits.h>

int fd_is_valid(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

int dup_handler(void *arg0)
{
	int original_fd = 0;
	int dup_fd = 0;

	original_fd = (uintptr_t) arg0;

	for (size_t i = 0; i < 1619296/2; i++)
	{
		if(!fd_is_valid(i))
		{
			dup_fd = i;
			break;
		}

	}
	return dup2(original_fd,dup_fd);
}


#endif // _HANDLER_DUP_H_
