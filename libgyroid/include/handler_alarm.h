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


#ifndef _HANDLER_ALARM_H_
#define _HANDLER_ALARM_H_

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


struct itimerval *curr_value;

static inline uint64_t alarm_handler(void * arg0)
{
	void *seconds;
	struct itimerval old, new;

	seconds = arg0;

	new.it_interval.tv_usec = 0;
	new.it_interval.tv_sec = 0;
	new.it_value.tv_usec = 0;
	new.it_value.tv_sec = (long int) seconds;

	int setitimer_return = setitimer(ITIMER_REAL, &new, &old); 
	if ( setitimer_return < 0)
	{
		return setitimer_return;
	}
	else
	{
		return old.it_value.tv_sec;
	}
}

#endif //_HANDLER_ALARM_H_
