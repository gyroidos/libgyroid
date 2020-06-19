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


#ifndef _HANDLER_TRUNCATE_H_
#define _HANDLER_TRUNCATE_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <stdint.h>
#include <time.h>

#include <linux/limits.h>

#include <stdio.h>

long get_file_size(char *path)
{
	int fd = open(path, O_RDONLY);
	long size = lseek(fd, 0 , SEEK_END);

	close(fd);
	return size;
}

int truncate_execute(char *path, long length)
{
	long original_size = get_file_size(path);

	if(original_size < 0)
	{
		return -1;
	}


	int read_ret = 1;

	unsigned char *new_content = (unsigned char*)malloc(length*sizeof(char));

	int fd_file = open(path, O_RDONLY);

	if(fd_file <0)
	{
		return -1;
	}


	if(original_size >= length)
	{
		read_ret = read(fd_file,new_content,length);

	}else
	{
		read(fd_file,new_content,original_size);
	}

	//close as old permissions
	int close_ret = close(fd_file);

	fd_file = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if(fd_file < 0)
	{
		return -1;
	}

	int write_ret = write(fd_file,new_content,length);

	close_ret |= close(fd_file);

	free(new_content);
	return (read_ret | write_ret | close_ret);
}


int truncate_handler(void *arg0, void *arg1)
{
	char *path = NULL;
	uint32_t length =-1;

	path = (char *) arg0;
	length = (uintptr_t) arg1;


	return truncate_execute(path,length);
}

#endif // _HANDLER_TRUNCATE_H_
