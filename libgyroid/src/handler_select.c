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

int add_poll_fds_to_epoll_intance(struct epoll_event *parsed_poll_events, int epfd, unsigned int number_of_parsed_fds)
{
	for (size_t i = 0; i < number_of_parsed_fds; i++)
	{
		int op = EPOLL_CTL_ADD;

		int epoll_ctl_return = epoll_ctl(epfd, op, parsed_poll_events[i].data.fd, &parsed_poll_events[i]);

		if(epoll_ctl_return <0) {
			return -1;
		}
	}

	return 0;
}


nfds_t parse_epoll_struct_from_poll(struct epoll_event* parsed_poll_events, struct pollfd *pollfd_argument, nfds_t nfds)
{
	int fdcount = 0;

	for (size_t i = 0; i < nfds; i++)
	{
		int temp_fd = pollfd_argument[i].fd;
		short events = pollfd_argument[i].events;
		uint32_t epoll_event = 0;

		if(events & POLLIN)
		{
			epoll_event |= EPOLLIN;
		}


		if(events & POLLOUT)
		{
			epoll_event |= EPOLLOUT;

		}


		if(events & POLLERR)
		{
			epoll_event |= EPOLLERR;

		}

		if(events & POLLPRI)
		{
			epoll_event |= EPOLLPRI;
		}

		if(events & POLLRDHUP)
		{
			epoll_event |= EPOLLRDHUP;
		}

		parsed_poll_events[i].events = epoll_event;
		parsed_poll_events[i].data.fd = temp_fd;

		fdcount++;
	}

	return fdcount;
}


int add_select_fds_to_epoll_intance(struct epoll_event *parsed_select_events, int epfd, unsigned int number_of_parsed_fds)
{

	int error_nr = 0;
	for (size_t i = 0; i < number_of_parsed_fds; i++)
	{
		int op = EPOLL_CTL_ADD;

		int epoll_ctl_return = epoll_ctl(epfd, op, parsed_select_events[i].data.fd, &parsed_select_events[i]);

		if(epoll_ctl_return <0)
		{
			error_nr = errno;
			break;
		}else
		{
		}
	}

	return error_nr;
}

int parse_epoll_struct_from_select(struct epoll_event *parsed_select_events, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,int epfd)
{

	int poll_cnt = 0;
	int epoll_target_fd = 0;
	uint32_t event_mask = 0;

	for (int i = 0; i < nfds; i++)
	{
		event_mask = 0;

		if(readfds != NULL && FD_ISSET(i, readfds) )
		{
			event_mask |= EPOLLIN;

			epoll_target_fd = i;

		}

		if (writefds != NULL && FD_ISSET(i, writefds))
		{
			event_mask |= EPOLLOUT;

			epoll_target_fd = i;

		}
		if (exceptfds != NULL && FD_ISSET(i, exceptfds))
		{
			event_mask |= EPOLLERR;

			epoll_target_fd = i;

		}

		if(event_mask >0)
		{

			parsed_select_events[poll_cnt].events = event_mask;
			parsed_select_events[poll_cnt].data.fd = epoll_target_fd;

			poll_cnt++;

		}
	}

	return poll_cnt;
}

void
set_poll_return_value(struct pollfd *fds,nfds_t nfds, struct epoll_event *event_array_poll, int epoll_return)
{
	for (int i = 0; i < epoll_return; i++)
	{
		short revents = event_array_poll[i].events;


		for (size_t j = 0; j < nfds; j++)
		{
			if (fds[j].fd == event_array_poll[i].data.fd)
			{
				fds[j].revents = revents;
				break;
			}

		}

	}

}

int poll_handler(void *arg0, void *arg1, void *arg2)
{
	struct pollfd *fds = (struct pollfd *) arg0;
	volatile nfds_t nfds = (uintptr_t) arg1;
	volatile int timeout = (uintptr_t) arg2;

	struct epoll_event *parsed_poll_events = malloc(sizeof(struct epoll_event) *FOPEN_MAX);
	struct epoll_event* event_array_poll = malloc(sizeof(struct epoll_event) *FOPEN_MAX);


	// Create epoll instance in kernel
	int epfd = -1;
	if (-1 == (epfd = epoll_create(1))) {
		raise(SIGINT);
		return -1;
	}

	nfds_t cnt_pollfds = parse_epoll_struct_from_poll(parsed_poll_events, fds,nfds);

	if (cnt_pollfds < nfds) {
		goto error;
	}

	if(-1 == add_poll_fds_to_epoll_intance(parsed_poll_events, epfd,nfds)) {
		goto error;
	}


	int epoll_wait_return = epoll_wait(epfd,event_array_poll,cnt_pollfds,timeout);

	if(epoll_wait_return <0)
	{
		goto error;
	}



	if (epoll_wait_return >= 0)
	{
		set_poll_return_value(fds, nfds, event_array_poll, epoll_wait_return);
	}

	if (parsed_poll_events)
		free(parsed_poll_events);

	if (event_array_poll)
		free(event_array_poll);

	close(epfd);


	if(0 > epoll_wait_return) {
		raise(SIGINT);
	}

	return epoll_wait_return;

error:
	close(epfd);

	if (parsed_poll_events)
		free(parsed_poll_events);

	if (event_array_poll)
		free(event_array_poll);

	raise(SIGINT);

	return -1;
}



int select_handler(void * arg0, void *arg1,void * arg2,void * arg3, void *arg4)
{
	struct epoll_event *parsed_select_events = malloc(sizeof(struct epoll_event) *FOPEN_MAX);



	volatile int fd_count;
	fd_set *fds_read,*fds_write,*fds_exception;
	volatile struct timeval *tv;

	struct epoll_event *event_array = (struct epoll_event*) malloc(FOPEN_MAX * sizeof(struct epoll_event));

	if(! event_array) {
		goto error;
	}

	fd_count = (uintptr_t) arg0;
	fds_read = (fd_set*) arg1;
	fds_write = (fd_set*) arg2;
	fds_exception = (fd_set*) arg3;
	tv = (struct timeval *) arg4;

	// Create epoll instance in kernel
	int epfd = epoll_create(1);
	if (-1 == epfd) {
		return -1;
	}

	int cnt_pollfds = parse_epoll_struct_from_select(parsed_select_events, fd_count, fds_read, fds_write,fds_exception, epfd);

	int add_return = add_select_fds_to_epoll_intance(parsed_select_events, epfd,cnt_pollfds);

	int timeout;
	if (tv) {
		timeout = tv->tv_sec*1000 + 0.001*tv->tv_usec;
	} else {
		timeout = -1;
	}

	int epoll_wait_return = epoll_wait(epfd,event_array, FOPEN_MAX,timeout);

	if(epoll_wait_return <0)
	{
		goto error;
	}

	if (epoll_wait_return >= 0)
	{
		// 0 or more fds are now ready
		for (int i = 0; i < epoll_wait_return; i++)
		{
			if (event_array[i].events & EPOLLIN)
			{
				FD_SET(event_array[i].data.fd, fds_read);
			}

			if (event_array[i].events & EPOLLOUT)
			{
				FD_SET(event_array[i].data.fd, fds_write);
			}

			if (event_array[i].events & EPOLLERR)
			{
				FD_SET(event_array[i].data.fd, fds_exception);
			}



		}

	}

	if(close(epfd))
		epoll_wait_return = -1;

	if(parsed_select_events)
		free(parsed_select_events);

	if (event_array) {
		free(event_array);
	}


	if (epoll_wait_return < 0) {
		raise(SIGINT);
	}

	return epoll_wait_return;

error:
	if(parsed_select_events)
		free(parsed_select_events);

	if (event_array) {
		free(event_array);
	}


	return -1;
}
