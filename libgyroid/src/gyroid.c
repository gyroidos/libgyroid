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


#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <alloca.h>
#include <string.h>

#include "handler_alarm.h"
#include "handler_chown.h"
#include "handler_dup.h"
#include "handler_execveat.h"
#include "handler_f_systemcall.h"
#include "handler_select.h"
#include "handler_truncate.h"


uint64_t
dispatch_sc()
{
	volatile void *arg0;
	volatile void *arg1;
	volatile void *arg2;
	volatile void *arg3;
	volatile void *arg4;
	volatile void *arg5;


#if defined(ARCH_x86_64)
	volatile unsigned long syscall_ret;
	volatile unsigned long syscall_no;
	register unsigned long rax asm ("rax");
	register void *rdi asm ("rdi");
	register void *rsi asm ("rsi");
	register void *rdx asm ("rdx");
	register void *r10 asm ("r10");
	register void *r8 asm ("r8");
	register void *r9 asm ("r9");

	syscall_no = rax;
	arg0 = rdi;
	arg1 = rsi;
	arg2 = rdx;
	arg3 = r10;
	arg4 = r8;
	arg5 = r9;
#elif defined(ARCH_aarch64)
	volatile unsigned long syscall_ret;
	volatile unsigned long syscall_no;
	register unsigned long x8 asm ("x8");
	register void *x0 asm ("x0");
	register void *x1 asm ("x1");
	register void *x2 asm ("x2");
	register void *x3 asm ("x3");
	register void *x4 asm ("x4");
	register void *x5 asm ("x5");

	syscall_no = x8;
	arg0 = x0;
	arg1 = x1;
	arg2 = x2;
	arg3 = x3;
	arg4 = x4;
	arg5 = x5;
#else

#error "Unknown ARCH"

#endif

	volatile char *msg;
	volatile char *args = NULL;

	switch(syscall_no)
	{

#if defined(ARCH_x86_64)
		case SYS_creat:
			syscall_ret = creat_handler((char *) arg0, (mode_t) arg1);
			break;
		case SYS_chown:
			syscall_ret = chown_handler((void *) arg0, (void *) arg1, (void *) arg2);
			break;
		case SYS_alarm:
			syscall_ret = alarm_handler((void *) arg0);
			break;
		case SYS_select:
			syscall_ret = select_handler((void *) arg0, (void *) arg1, (void *) arg2, (void *) arg3, (void *) arg4);
			break;
		case SYS_poll:
			syscall_ret = poll_handler((void *) arg0, (void *) arg1, (void *) arg2);
			break;
#endif
		case SYS_execveat:
			syscall_ret = execveat_handler((void *) arg0, (void *) arg1, (void *) arg2, (void *) arg3, (void *) arg4);
			break;
		case SYS_dup:
			syscall_ret = dup_handler((void *) arg0);
			break;
		case SYS_truncate:
			syscall_ret = truncate_handler((void *) arg0, (void *) arg1);
			break;

		case SYS_fchdir:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_ftruncate:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_fchmod:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_fremovexattr:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_fstat:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_fchown:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_flistxattr:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;
		case SYS_fgetxattr:
			syscall_ret = f_handler(syscall_no,(void *) arg0,(void *) arg1,(void *) arg2,(void *) arg3);
			break;

		default:
#if defined(ARCH_x86_64)
				__asm__ volatile (
					"mov %1, %%rax\t\n"
					"mov %2, %%rdi\t\n"
					"mov %3, %%rsi\t\n"
					"mov %4, %%rdx\t\n"
					"mov %5, %%r10\t\n"
					"mov %6, %%r8\t\n"
					"mov %7, %%r9\t\n"
					"syscall\t\n"
					"mov %%rax, %0"
					: "=&r" (syscall_ret)
					: "m" (syscall_no), "m" (arg0), "m" (arg1), "m" (arg2), "m" (arg3), "m" (arg4), "m" (arg5)
					: "%rax", "%rcx", "r11", "r9", "rdi", "rsi", "rdx", "r10", "r8"
				);
#elif defined(ARCH_aarch64)
				__asm__ volatile("ldr x8, %[syscall_id] \t\n"
					"ldr x0, %[arg0]       \t\n"
					"ldr x1, %[arg1]       \t\n"
					"ldr x2, %[arg2]       \t\n"
					"ldr x3, %[arg3]       \t\n"
					"ldr x4, %[arg4]       \t\n"
					"ldr x5, %[arg5]       \t\n"
					"svc 0         \t\n" \
					"str x0, %[retval]     \t\n" \
					: /*outputs*/[retval] "=m"(syscall_ret) \
					: /*inputs*/[syscall_id] "m"(syscall_no), \
					  [arg0] "m"(arg0), [arg1] "m"(arg1), \
					  [arg2] "m"(arg2), [arg3] "m"(arg3), \
					  [arg4] "m"(arg4), [arg5] "m"(arg5) \
					: /*clobbers*/ "cc", "x8", "x0", "x1", "x2", \
					  "x3", "x4", "x5");
#else
	#error "Unknown ARCH"

#endif // x86_64 or aarch64

			break;
	}

	return syscall_ret;
}
