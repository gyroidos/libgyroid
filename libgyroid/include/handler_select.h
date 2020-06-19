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


#ifndef _HANDLER_SELECT_H_
#define _HANDLER_SELECT_H_

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

#include <sys/epoll.h>
#include <poll.h>
#include <sys/file.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>


int
poll_handler(void *arg0, void *arg1, void *arg2);

int
select_handler(void *arg0, void *arg1, void *arg2, void *arg3, void *arg4);

#endif //_HANDLER_SELECT_H_
