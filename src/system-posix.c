/* system-posix.c - System support functions.
 * Copyright (C) 2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
/* Solaris 8 needs sys/types.h before time.h.  */
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#ifdef HAVE_GETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif /*HAVE_GETRLIMIT*/
#if __linux__
# include <dirent.h>
#endif /*__linux__ */


#include "assuan-defs.h"
#include "debug.h"




assuan_fd_t
assuan_fdopen (int fd)
{
  return dup (fd);
}



/* Sleep for the given number of microseconds.  Default
   implementation.  */
void
__assuan_usleep (assuan_context_t ctx, unsigned int usec)
{
  if (! usec)
    return;

#ifdef HAVE_NANOSLEEP
  {
    struct timespec req;
    struct timespec rem;

    req.tv_sec  = usec / 1000000;
    req.tv_nsec = (usec % 1000000) * 1000;
    while (nanosleep (&req, &rem) < 0 && errno == EINTR)
      req = rem;
  }
#else
  {
    struct timeval tv;

    tv.tv_sec  = usec / 1000000;
    tv.tv_usec = usec % 1000000;
    select (0, NULL, NULL, NULL, &tv);
  }
#endif
}



/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  Easy for Posix.  */
int
__assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  return close (fd);
}



ssize_t
__assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
  return read (fd, buffer, size);
}



ssize_t
__assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
		size_t size)
{
  return write (fd, buffer, size);
}



int
__assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  int ret;

  do
    ret = recvmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
}



int
__assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  int ret;

  do
    ret = sendmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
}



int
__assuan_socketpair (assuan_context_t ctx, int namespace, int style,
		     int protocol, assuan_fd_t filedes[2])
{
  return socketpair (namespace, style, protocol, filedes);
}


int
__assuan_socket (assuan_context_t ctx, int namespace, int style, int protocol)
{
  return socket (namespace, style, protocol);
}


int
__assuan_connect (assuan_context_t ctx, int sock, struct sockaddr *addr,
		  socklen_t length)
{
  return connect (sock, addr, length);
}
