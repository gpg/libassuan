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



/* Three simple wrappers, only used because thes function are named in
   the def file.  */
HANDLE
_assuan_w32ce_prepare_pipe (int *r_rvid, int write_end)
{
  (void)r_rvid;
  (void)write_end;
  return INVALID_HANDLE_VALUE;
}

HANDLE
_assuan_w32ce_finish_pipe (int rvid, int write_end)
{
  (void)rvid;
  (void)write_end;
  return INVALID_HANDLE_VALUE;
}

DWORD
_assuan_w32ce_create_pipe (HANDLE *read_hd, HANDLE *write_hd,
                           LPSECURITY_ATTRIBUTES sec_attr, DWORD size)
{
  return CreatePipe (read_hd, write_hd, sec_attr, size);
}



/* Create a pipe with one inheritable end.  Default implementation.  */
int
__assuan_pipe (assuan_context_t ctx, assuan_fd_t fd[2], int inherit_idx)
{
  HANDLE rh;
  HANDLE wh;
  HANDLE th;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = FALSE;

  if (!CreatePipe (&rh, &wh, &sec_attr, 0))
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_pipe", ctx,
	      "CreatePipe failed: %s", _assuan_w32_strerror (ctx, -1));
      gpg_err_set_errno (EIO);
      return -1;
    }

  if (! DuplicateHandle (GetCurrentProcess(), (inherit_idx == 0) ? rh : wh,
			 GetCurrentProcess(), &th, 0,
			 TRUE, DUPLICATE_SAME_ACCESS ))
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_pipe", ctx,
	      "DuplicateHandle failed: %s", _assuan_w32_strerror (ctx, -1));
      CloseHandle (rh);
      CloseHandle (wh);
      gpg_err_set_errno (EIO);
      return -1;
    }
  if (inherit_idx == 0)
    {
      CloseHandle (rh);
      rh = th;
    }
  else
    {
      CloseHandle (wh);
      wh = th;
    }

  fd[0] = rh;
  fd[1] = wh;

  return 0;
}



/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  Default implementation.  */
int
__assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  int rc;

  if (ctx->flags.is_socket)
    {
      rc = closesocket (HANDLE2SOCKET(fd));
      if (rc)
        gpg_err_set_errno ( _assuan_sock_wsa2errno (WSAGetLastError ()) );
    }
  else
    {
      rc = CloseHandle (fd);
      if (rc)
        /* FIXME. */
        gpg_err_set_errno (EIO);
    }
  return rc;
}



/* To encode/decode file HANDLE, we use FDPASS_FORMAT */
#define FDPASS_FORMAT "%p"
#define FDPASS_MSG_SIZE (sizeof (uintptr_t)*2 + 1)

/* Get a file HANDLE to send, from POSIX fd.  */
static gpg_error_t
get_file_handle (int fd, int server_pid, HANDLE *r_handle)
{
  HANDLE prochandle, handle, newhandle;

  handle = (void *)_get_osfhandle (fd);

  prochandle = OpenProcess (PROCESS_DUP_HANDLE, FALSE, server_pid);
  if (!prochandle)
    return gpg_error (GPG_ERR_ASS_PARAMETER);/*FIXME: error*/

  if (!DuplicateHandle (GetCurrentProcess (), handle, prochandle, &newhandle,
                        0, TRUE, DUPLICATE_SAME_ACCESS))
    {
      CloseHandle (prochandle);
      return gpg_error (GPG_ERR_ASS_PARAMETER);/*FIXME: error*/
    }
  CloseHandle (prochandle);
  *r_handle = newhandle;
  return 0;
}


/* Send a FD (which means POSIX fd) to the peer.  */
gpg_error_t
w32_fdpass_send (assuan_context_t ctx, assuan_fd_t fd)
{
  char fdpass_msg[256];
  int res;
  int fd0;                      /* POSIX fd */
  intptr_t fd_converted_to_integer;
  HANDLE file_handle;
  gpg_error_t err;

  fd_converted_to_integer = (intptr_t)fd;
  fd0 = (int)fd_converted_to_integer; /* Bit pattern is possibly truncated.  */

  err = get_file_handle (fd0, ctx->pid, &file_handle);
  if (err)
    return err;

  res = snprintf (fdpass_msg, sizeof (fdpass_msg), "SENDFD %p", file_handle);
  if (res < 0)
    {
      CloseHandle (file_handle);
      return gpg_error (GPG_ERR_ASS_PARAMETER);/*FIXME: error*/
    }

  err = assuan_transact (ctx, fdpass_msg, NULL, NULL, NULL, NULL, NULL, NULL);
  return err;
}

static int
process_fdpass_msg (const char *fdpass_msg, size_t msglen, int *r_fd)
{
  void *file_handle;
  int res;
  int fd;

  *r_fd = -1;

  res = sscanf (fdpass_msg, FDPASS_FORMAT, &file_handle);
  if (res != 1)
    return -1;

  fd = _open_osfhandle ((intptr_t)file_handle, _O_RDWR);
  if (fd < 0)
    {
      CloseHandle (file_handle);
      return -1;
    }

  *r_fd = fd;
  return 0;
}


/* Receive a HANDLE from the peer and turn it into a FD (POSIX fd).  */
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
      fd_set fds;
      int tries = 3;
      fd_set efds;

      FD_ZERO (&fds);
      FD_SET (HANDLE2SOCKET (fd), &fds);
      FD_ZERO (&efds);
      FD_SET (HANDLE2SOCKET (fd), &efds);
      res = select (0, &fds, NULL, &efds, NULL);
      if (res < 0)
        {
          gpg_err_set_errno (EIO);
          return -1;
        }
      else if (FD_ISSET (HANDLE2SOCKET (fd), &efds))
        {
          int fd_recv;
          char fdpass_msg[FDPASS_MSG_SIZE];

          /* the message of ! */
          res = recv (HANDLE2SOCKET (fd), fdpass_msg, sizeof (fdpass_msg), MSG_OOB);
          if (res < 0)
            {
              gpg_err_set_errno (EIO);
              return -1;
            }

          /* the body of message */
          res = recv (HANDLE2SOCKET (fd), fdpass_msg, sizeof (fdpass_msg), 0);
          if (res < 0)
            {
              gpg_err_set_errno (EIO);
              return -1;
            }

          res = process_fdpass_msg (fdpass_msg, res, &fd_recv);
          if (res < 0)
            {
              gpg_err_set_errno (EIO);
              return -1;
            }

          ctx->uds.pendingfds[ctx->uds.pendingfdscount++] = (assuan_fd_t)fd_recv;
	  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_read", ctx,
		  "received fd: %d", fd_recv);
          /* Fall through  */
        }

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




/* Build a command line for use with W32's CreateProcess.  On success
   CMDLINE gets the address of a newly allocated string.  */
static int
build_w32_commandline (assuan_context_t ctx, const char * const *argv,
		       char **cmdline)
{
  int i, n;
  const char *s;
  char *buf, *p;

  *cmdline = NULL;
  n = 0;
  for (i=0; (s = argv[i]); i++)
    {
      n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting */
      for (; *s; s++)
        if (*s == '\"')
          n++;  /* Need to double inner quotes.  */
    }
  n++;

  buf = p = _assuan_malloc (ctx, n);
  if (! buf)
    return -1;

  for (i = 0; argv[i]; i++)
    {
      if (i)
        p = stpcpy (p, " ");
      if (! *argv[i]) /* Empty string. */
        p = stpcpy (p, "\"\"");
      else if (strpbrk (argv[i], " \t\n\v\f\""))
        {
          p = stpcpy (p, "\"");
          for (s = argv[i]; *s; s++)
            {
              *p++ = *s;
              if (*s == '\"')
                *p++ = *s;
            }
          *p++ = '\"';
          *p = 0;
        }
      else
        p = stpcpy (p, argv[i]);
    }

  *cmdline= buf;
  return 0;
}


int
__assuan_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
		const char **argv,
		assuan_fd_t fd_in, assuan_fd_t fd_out,
		assuan_fd_t *fd_child_list,
		void (*atfork) (void *opaque, int reserved),
		void *atforkvalue, unsigned int flags)
{
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi =
    {
      NULL,      /* Returns process handle.  */
      0,         /* Returns primary thread handle.  */
      0,         /* Returns pid.  */
      0          /* Returns tid.  */
    };
  STARTUPINFOW si;
  assuan_fd_t fd;
  assuan_fd_t *fdp;
  char *cmdline;
  wchar_t *wcmdline = NULL;
  wchar_t *wname = NULL;
  HANDLE nullfd = INVALID_HANDLE_VALUE;
  int rc;

  /* fixme: Actually we should set the "_assuan_pipe_connect_pid" env
     variable.  However this requires us to write a full environment
     handler, because the strings are expected in sorted order.  The
     suggestion given in the MS Reference Library, to save the old
     value, change it, create process and restore it, is not thread
     safe.  */

  /* Build the command line.  */
  if (build_w32_commandline (ctx, argv, &cmdline))
    return -1;

  /* Start the process.  */
  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES;
  /* FIXME: Dup to nul if ASSUAN_INVALID_FD.  */
  si.hStdInput  = fd_in;
  si.hStdOutput = fd_out;

  /* Dup stderr to /dev/null unless it is in the list of FDs to be
     passed to the child. */
  fd = assuan_fd_from_posix_fd (fileno (stderr));
  fdp = fd_child_list;
  if (fdp)
    {
      for (; *fdp != ASSUAN_INVALID_FD && *fdp != fd; fdp++)
        ;
    }
  if (!fdp || *fdp == ASSUAN_INVALID_FD)
    {
      nullfd = CreateFileW (L"nul", GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
      if (nullfd == INVALID_HANDLE_VALUE)
        {
	  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		  "can't open `nul': %s", _assuan_w32_strerror (ctx, -1));
          _assuan_free (ctx, cmdline);
          gpg_err_set_errno (EIO);
          return -1;
        }
      si.hStdError = nullfd;
    }
  else
    si.hStdError = fd;

  /* Note: We inherit all handles flagged as inheritable.  This seems
     to be a security flaw but there seems to be no way of selecting
     handles to inherit.  A fix for this would be to use a helper
     process like we have in gpgme.
     Take care: CreateProcessW may modify wpgmname */
  /*   _assuan_log_printf ("CreateProcess, path=`%s' cmdline=`%s'\n", */
  /*                       name, cmdline); */
  if (name && !(wname = _assuan_utf8_to_wchar (name)))
    rc = 0;
  else if (!(wcmdline = _assuan_utf8_to_wchar (cmdline)))
    rc = 0;
  else
    rc = CreateProcessW (wname,              /* Program to start.  */
                         wcmdline,           /* Command line arguments.  */
                         &sec_attr,          /* Process security attributes.  */
                         &sec_attr,          /* Thread security attributes.  */
                         TRUE,               /* Inherit handles.  */
                         (CREATE_DEFAULT_ERROR_MODE
                          | ((flags & 128)? DETACHED_PROCESS : 0)
                          | GetPriorityClass (GetCurrentProcess ())
                          | CREATE_SUSPENDED), /* Creation flags.  */
                         NULL,               /* Environment.  */
                         NULL,               /* Use current drive/directory.  */
                         &si,                /* Startup information. */
                         &pi                 /* Returns process information.  */
                         );
  if (!rc)
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "pipe_connect_w32", ctx,
	      "CreateProcess failed%s: %s", _assuan_w32_strerror (ctx, -1));
      free (wname);
      free (wcmdline);
      _assuan_free (ctx, cmdline);
      if (nullfd != INVALID_HANDLE_VALUE)
        CloseHandle (nullfd);

      gpg_err_set_errno (EIO);
      return -1;
    }

  free (wname);
  free (wcmdline);
  _assuan_free (ctx, cmdline);
  if (nullfd != INVALID_HANDLE_VALUE)
    CloseHandle (nullfd);

  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);

  /*   _assuan_log_printf ("CreateProcess ready: hProcess=%p hThread=%p" */
  /*                       " dwProcessID=%d dwThreadId=%d\n", */
  /*                       pi.hProcess, pi.hThread, */
  /*                       (int) pi.dwProcessId, (int) pi.dwThreadId); */

  *r_pid = (pid_t) pi.hProcess;

  /* No need to modify peer process, as we don't change the handle
     names.  However this also means we are not safe, as we inherit
     too many handles.  Should use approach similar to gpgme and glib
     using a helper process.  */

  return 0;
}




/* FIXME: Add some sort of waitpid function that covers GPGME and
   gpg-agent's use of assuan.  */
pid_t
__assuan_waitpid (assuan_context_t ctx, pid_t pid, int nowait,
		  int *status, int options)
{
  CloseHandle ((HANDLE) pid);
  return 0;
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


/* The default system hooks for assuan contexts.  */
struct assuan_system_hooks _assuan_system_hooks =
  {
    0,
    __assuan_usleep,
    __assuan_pipe,
    __assuan_close,
    __assuan_read,
    __assuan_write,
    __assuan_recvmsg,
    __assuan_sendmsg,
    __assuan_spawn,
    __assuan_waitpid,
    __assuan_socketpair,
    __assuan_socket,
    __assuan_connect
  };
