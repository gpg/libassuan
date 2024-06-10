/* system-w32.c - System support functions for Windows.
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
#include <time.h>
#include <fcntl.h>

#include "assuan-defs.h"
#include "debug.h"



assuan_fd_t
assuan_fdopen (int fd)
{
  assuan_fd_t ifd = (assuan_fd_t) _get_osfhandle (fd);
  assuan_fd_t ofd;

  if (! DuplicateHandle(GetCurrentProcess(), ifd,
			GetCurrentProcess(), &ofd, 0,
			TRUE, DUPLICATE_SAME_ACCESS))
    {
      gpg_err_set_errno (EIO);
      return ASSUAN_INVALID_FD;
    }
  return ofd;
}



/* Sleep for the given number of microseconds.  Default
   implementation.  */
void
__assuan_usleep (assuan_context_t ctx, unsigned int usec)
{
  if (!usec)
    return;

  Sleep (usec / 1000);
}



/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  Default implementation.  */
int
__assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  int rc = closesocket (HANDLE2SOCKET(fd));
  if (rc)
    gpg_err_set_errno ( _assuan_sock_wsa2errno (WSAGetLastError ()) );
  if (rc && WSAGetLastError () == WSAENOTSOCK)
    {
      rc = CloseHandle (fd);
      if (rc)
        /* FIXME. */
        gpg_err_set_errno (EIO);
    }
  return rc;
}



/* Get a file HANDLE for other end to send, from MY_HANDLE.  */
static gpg_error_t
get_file_handle (assuan_context_t ctx, assuan_fd_t my_handle,
                 int process_id, HANDLE *r_handle)
{
  HANDLE prochandle, newhandle;

  prochandle = OpenProcess (PROCESS_DUP_HANDLE, FALSE, process_id);
  if (!prochandle)
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "assuan_sendfd", ctx,
	      "OpenProcess failed: %s", _assuan_w32_strerror (ctx, -1));
      return _assuan_error (ctx, gpg_err_code_from_errno (EIO));
    }

  if (!DuplicateHandle (GetCurrentProcess (), my_handle, prochandle, &newhandle,
                        0, TRUE, DUPLICATE_SAME_ACCESS))
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "assuan_sendfd", ctx,
	      "DuplicateHandle failed: %s", _assuan_w32_strerror (ctx, -1));
      CloseHandle (prochandle);
      return _assuan_error (ctx, GPG_ERR_ASS_PARAMETER);
    }
  CloseHandle (prochandle);
  *r_handle = newhandle;
  return 0;
}


/* Send an FD (which means Windows HANDLE) to the peer.  */
gpg_error_t
w32_fdpass_send (assuan_context_t ctx, assuan_fd_t fd)
{
  char fdpass_msg[256];
  int res;
  HANDLE file_handle = INVALID_HANDLE_VALUE;
  gpg_error_t err;

  if (ctx->process_id == -1)
    return _assuan_error (ctx, GPG_ERR_SERVER_FAILED);

  err = get_file_handle (ctx, fd, ctx->process_id, &file_handle);
  if (err)
    return err;

  res = snprintf (fdpass_msg, sizeof (fdpass_msg), "SENDFD %p", file_handle);
  if (res < 0)
    {
      CloseHandle (file_handle);
      return _assuan_error (ctx, GPG_ERR_ASS_PARAMETER);
    }

  err = assuan_transact (ctx, fdpass_msg, NULL, NULL, NULL, NULL, NULL, NULL);
  return err;
}


/* Receive a HANDLE from the peer and turn it into an FD.  */
gpg_error_t
w32_fdpass_recv (assuan_context_t ctx, assuan_fd_t *fd)
{
  int i;

  if (!ctx->uds.pendingfdscount)
    {
      TRACE0 (ctx, ASSUAN_LOG_SYSIO, "w32_receivefd", ctx,
	      "no pending file descriptors");
      return _assuan_error (ctx, GPG_ERR_ASS_GENERAL);
    }

  *fd = ctx->uds.pendingfds[0];
  for (i=1; i < ctx->uds.pendingfdscount; i++)
    ctx->uds.pendingfds[i-1] = ctx->uds.pendingfds[i];
  ctx->uds.pendingfdscount--;

  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "w32_fdpass_recv", ctx,
          "received fd: %p", ctx->uds.pendingfds[0]);
  return 0;
}

ssize_t
__assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
  int res;
  int ec = 0;

  if (ctx->flags.is_socket)
    {
      int tries = 3;

    again:
      ec = 0;
      res = recv (HANDLE2SOCKET (fd), buffer, size, 0);
      if (res == -1)
        ec = WSAGetLastError ();
      if (ec == WSAEWOULDBLOCK && tries--)
        {
          /* EAGAIN: Use select to wait for resources and try again.
             We do this 3 times and then give up.  The higher level
             layer then needs to take care of EAGAIN.  No need to
             specify a timeout - the socket is not expected to be in
             blocking mode.  */
          fd_set fds;

          FD_ZERO (&fds);
          FD_SET (HANDLE2SOCKET (fd), &fds);
          select (0, &fds, NULL, NULL, NULL);
          goto again;
        }
    }
  else
    {
       DWORD nread = 0;
       if (!ReadFile (fd, buffer, size, &nread, NULL))
         {
           res = -1;
           ec = GetLastError ();
         }
      else
        res = nread;
    }
  if (res == -1)
    {
      switch (ec)
        {
        case WSAENOTSOCK:
	  gpg_err_set_errno (EBADF);
          break;

        case WSAEWOULDBLOCK:
	  gpg_err_set_errno (EAGAIN);
	  break;

        case WSAECONNRESET: /* Due to the use of recv.  */
        case ERROR_BROKEN_PIPE:
	  gpg_err_set_errno (EPIPE);
	  break;

        default:
	  gpg_err_set_errno (EIO);
	  break;
        }
    }
  return res;
}



ssize_t
__assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
		size_t size)
{
  int res;
  int ec = 0;

  if (ctx->flags.is_socket)
    {
      int tries = 3;

    again:
      ec = 0;
      res = send (HANDLE2SOCKET (fd), buffer, size, 0);
      if (res == -1)
        ec = WSAGetLastError ();
      if (ec == WSAEWOULDBLOCK && tries--)
        {
          /* EAGAIN: Use select to wait for resources and try again.
             We do this 3 times and then give up.  The higher level
             layer then needs to take care of EAGAIN.  No need to
             specify a timeout - the socket is not expected to be in
             blocking mode.  */
          fd_set fds;

          FD_ZERO (&fds);
          FD_SET (HANDLE2SOCKET (fd), &fds);
          select (0, NULL, &fds, NULL, NULL);
          goto again;
        }
    }
  else
    {
      DWORD nwrite;

      if (!WriteFile (fd, buffer, size, &nwrite, NULL))
        {
          res = -1;
          ec = GetLastError ();
        }
      else
        res = (int)nwrite;
    }
  if (res == -1)
    {
      switch (ec)
        {
        case WSAENOTSOCK:
	  gpg_err_set_errno (EBADF);
          break;

        case WSAEWOULDBLOCK:
	  gpg_err_set_errno (EAGAIN);
	  break;

        case ERROR_BROKEN_PIPE:
        case ERROR_NO_DATA:
	  gpg_err_set_errno (EPIPE);
	  break;

        default:
	  gpg_err_set_errno (EIO);
	  break;
        }

    }
  return res;
}



int
__assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  gpg_err_set_errno (ENOSYS);
  return -1;
}




int
__assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  gpg_err_set_errno (ENOSYS);
  return -1;
}

int
__assuan_socketpair (assuan_context_t ctx, int namespace, int style,
		     int protocol, assuan_fd_t filedes[2])
{
  gpg_err_set_errno (ENOSYS);
  return -1;
}


assuan_fd_t
__assuan_socket (assuan_context_t ctx, int domain, int type, int proto)
{
  assuan_fd_t res;

  res = SOCKET2HANDLE (socket (domain, type, proto));
  if (res == SOCKET2HANDLE (INVALID_SOCKET))
    gpg_err_set_errno (_assuan_sock_wsa2errno (WSAGetLastError ()));
  return res;
}


int
__assuan_connect (assuan_context_t ctx, assuan_fd_t sock,
                  struct sockaddr *addr, socklen_t length)
{
  int res;

  res = connect (HANDLE2SOCKET (sock), addr, length);
  if (res < 0)
    gpg_err_set_errno (_assuan_sock_wsa2errno (WSAGetLastError ()));
  return res;
}
