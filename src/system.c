/* system.c - System support functions.
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#ifdef HAVE_SYS_TYPES_H
  /* Solaris 8 needs sys/types.h before time.h.  */
# include <sys/types.h>
#endif
#include <time.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <gpg-error.h>

#include "assuan-defs.h"
#include "debug.h"

#define DEBUG_SYSIO 0




/* Manage memory specific to a context.  */

void *
_assuan_malloc (assuan_context_t ctx, size_t cnt)
{
  return ctx->malloc_hooks.malloc (cnt);
}

void *
_assuan_realloc (assuan_context_t ctx, void *ptr, size_t cnt)
{
  return ctx->malloc_hooks.realloc (ptr, cnt);
}

void *
_assuan_calloc (assuan_context_t ctx, size_t cnt, size_t elsize)
{
  void *ptr;
  size_t nbytes;

  nbytes = cnt * elsize;

  /* Check for overflow.  */
  if (elsize && nbytes / elsize != cnt)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }

  ptr = ctx->malloc_hooks.malloc (nbytes);
  if (ptr)
    memset (ptr, 0, nbytes);
  return ptr;
}

void
_assuan_free (assuan_context_t ctx, void *ptr)
{
  if (ptr)
    ctx->malloc_hooks.free (ptr);
}


/* Release the memory at PTR using the allocation handler of the
   context CTX.  This is a convenience function.  */
void
assuan_free (assuan_context_t ctx, void *ptr)
{
  _assuan_free (ctx, ptr);
}



/* Sleep for the given number of microseconds.  */
void
_assuan_usleep (assuan_context_t ctx, unsigned int usec)
{
  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "_assuan_usleep", ctx,
	  "usec=%u", usec);

  _assuan_pre_syscall ();
  __assuan_usleep (ctx, usec);
  _assuan_post_syscall ();
}



/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  */
int
_assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  int res;

  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "_assuan_close", ctx,
	  "fd=0x%x", fd);

  _assuan_pre_syscall ();
  res = __assuan_close (ctx, fd);
  _assuan_post_syscall ();
  return res;
}


/* Same as assuan_close but used for the inheritable end of a
   pipe.  */
int
_assuan_close_inheritable (assuan_context_t ctx, assuan_fd_t fd)
{
  int res;

  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "_assuan_close_inheritable", ctx,
	  "fd=0x%x", fd);

  _assuan_pre_syscall ();
  res = __assuan_close (ctx, fd);
  _assuan_post_syscall ();
  return res;
}



ssize_t
_assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
#if DEBUG_SYSIO
  ssize_t res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_read", ctx,
	      "fd=0x%x, buffer=%p, size=%i", fd, buffer, size);
  _assuan_pre_syscall ();
  res = __assuan_read (ctx, fd, buffer, size);
  _assuan_post_syscall ();
  return TRACE_SYSRES (res);
#else
  ssize_t res;
  _assuan_pre_syscall ();
  res = __assuan_read (ctx, fd, buffer, size);
  _assuan_post_syscall ();
  return res;
#endif
}



ssize_t
_assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
	       size_t size)
{
#if DEBUG_SYSIO
  ssize_t res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_write", ctx,
	      "fd=0x%x, buffer=%p, size=%i", fd, buffer, size);
  _assuan_pre_syscall ();
  res = __assuan_write (ctx, fd, buffer, size);
  _assuan_post_syscall ();
  return TRACE_SYSRES (res);
#else
  ssize_t res;
  _assuan_pre_syscall ();
  res =  __assuan_write (ctx, fd, buffer, size);
  _assuan_post_syscall ();
  return res;
#endif
}



int
_assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		 int flags)
{
#if DEBUG_SYSIO
  int res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_recvmsg", ctx,
	      "fd=0x%x, msg=%p, flags=0x%x", fd, msg, flags);
  _assuan_pre_syscall ();
  res = __assuan_recvmsg (ctx, fd, msg, flags);
  _assuan_post_syscall ();
  if (res > 0)
    {
      struct cmsghdr *cmptr;

      TRACE_LOG2 ("msg->msg_iov[0] = { iov_base=%p, iov_len=%i }",
		  msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
      TRACE_LOGBUF (msg->msg_iov[0].iov_base, res);

      cmptr = CMSG_FIRSTHDR (msg);
      if (cmptr)
	{
	  void *data = CMSG_DATA (cmptr);
	  TRACE_LOG5 ("cmsg_len=0x%x (0x%x data), cmsg_level=0x%x, "
		      "cmsg_type=0x%x, first data int=0x%x", cmptr->cmsg_len,
		      cmptr->cmsg_len - (((char *)data) - ((char *)cmptr)),
		      cmptr->cmsg_level, cmptr->cmsg_type, *(int *)data);
	}
    }
  return TRACE_SYSRES (res);
#else
  int res;
  _assuan_pre_syscall ();
  res = __assuan_recvmsg (ctx, fd, msg, flags);
  _assuan_post_syscall ();
  return res;
#endif
}



int
_assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		 int flags)
{
#if DEBUG_SYSIO
  int res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_sendmsg", ctx,
	      "fd=0x%x, msg=%p, flags=0x%x", fd, msg, flags);
  {
    struct cmsghdr *cmptr;

    TRACE_LOG2 ("msg->iov[0] = { iov_base=%p, iov_len=%i }",
		msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
    TRACE_LOGBUF (msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);

    cmptr = CMSG_FIRSTHDR (msg);
    if (cmptr)
      {
	void *data = CMSG_DATA (cmptr);
	TRACE_LOG5 ("cmsg_len=0x%x (0x%x data), cmsg_level=0x%x, "
		    "cmsg_type=0x%x, first data int=0x%x", cmptr->cmsg_len,
		    cmptr->cmsg_len - (((char *)data) - ((char *)cmptr)),
		    cmptr->cmsg_level, cmptr->cmsg_type, *(int *)data);
      }
  }
  _assuan_pre_syscall ();
  res = __assuan_sendmsg (ctx, fd, msg, flags);
  _assuan_post_syscall ();
  return TRACE_SYSRES (res);
#else
  int res;
  _assuan_pre_syscall ();
  res = __assuan_sendmsg (ctx, fd, msg, flags);
  _assuan_post_syscall ();
  return res;
#endif
}

int
_assuan_socketpair (assuan_context_t ctx, int namespace, int style,
		    int protocol, assuan_fd_t filedes[2])
{
  int res;
  TRACE_BEG4 (ctx, ASSUAN_LOG_SYSIO, "_assuan_socketpair", ctx,
	      "namespace=%i,style=%i,protocol=%i,filedes=%p",
	      namespace, style, protocol, filedes);

  res = __assuan_socketpair (ctx, namespace, style, protocol, filedes);
  if (res == 0)
    TRACE_LOG2 ("filedes = { 0x%x, 0x%x }", filedes[0], filedes[1]);

  return TRACE_SYSERR (res);
}



assuan_fd_t
_assuan_socket (assuan_context_t ctx, int namespace, int style, int protocol)
{
  assuan_fd_t res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_socket", ctx,
	      "namespace=%i,style=%i,protocol=%i",
	      namespace, style, protocol);

  res = __assuan_socket (ctx, namespace, style, protocol);
  return TRACE_SYSRES (res);
}


int
_assuan_connect (assuan_context_t ctx, assuan_fd_t sock,
                 struct sockaddr *addr, socklen_t length)
{
  int res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_connect", ctx,
	      "socket=%i,addr=%p,length=%i", sock, addr, length);

  _assuan_pre_syscall ();
  res = __assuan_connect (ctx, sock, addr, length);
  _assuan_post_syscall ();
  return TRACE_SYSRES (res);
}
