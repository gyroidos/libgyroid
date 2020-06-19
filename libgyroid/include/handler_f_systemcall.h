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


#ifndef _HANDLER_FSYSCALL_H_
#define _HANDLER_FSYSCALL_H_

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
#include <syscall.h>

#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>

#include "handler_truncate.h"


int get_path_from_fd(char *path, int fd)
{
	char fd_link[PATH_MAX];
	sprintf(fd_link,"/proc/self/fd/%d",fd);
	int ret = -1;
	ret = readlink(fd_link,path,PATH_MAX);
	if(ret < 0)
	{
		return -1;
	}
	path[ret] = 0;
	return ret;

}

uint64_t f_handler(int syscall_nr, void *arg0, void *arg1, void *arg2, void *arg3)
{
	char *path = (char *)malloc(PATH_MAX * sizeof(char));

	if(NULL == path)
	{
		return -1;
	}

	int ret_path_conversion = get_path_from_fd(path, (int) ((uintptr_t)arg0));

	if(ret_path_conversion == -1)
	{
		free(path);
		return -1;
	}


	uint64_t syscall_return = -1;
	switch (syscall_nr)
	{
	case SYS_fchdir:
		syscall_return = chdir(path);
		break;
	case SYS_ftruncate:
		syscall_return = truncate_execute(path,(off_t) arg1);
		break;
	case SYS_fchmod:
		syscall_return = chmod(path, (mode_t) ((uintptr_t)arg1));
		break;
	case SYS_removexattr:
		syscall_return = removexattr(path, (const char *) ((uintptr_t)arg1));
		errno = errno;
		break;
	case SYS_fstat:
		syscall_return = stat(path, (struct stat *) ((uintptr_t)arg1));
		break;
	case SYS_fchown:
		syscall_return = chown(path, (uid_t) ((uintptr_t)arg1), (gid_t) ((uintptr_t)arg2));
		break;
	case SYS_flistxattr:
		syscall_return = listxattr(path, (char *) ((uintptr_t)arg1), (size_t) arg2);
		errno = errno;
		break;
	case SYS_fgetxattr:
		syscall_return = getxattr(path, (const char *) ( (uintptr_t) arg1), (void *) ((uintptr_t)arg2), (size_t) arg3);
		errno = errno;
		break;
	default:
		break;
	}

	free(path);

	return syscall_return;
}

#endif // _HANDLER_FSYSCALL_H_
