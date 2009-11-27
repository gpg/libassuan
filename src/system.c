/* system.c - System support functions.
   Copyright (C) 2009 Free Software Foundation, Inc.

   This file is part of Assuan.

   Assuan is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Assuan is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
/* Solaris 8 needs sys/types.h before time.h.  */
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else
# include <sys/wait.h>
#endif

#include "assuan-defs.h"
#include "debug.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif


assuan_fd_t
assuan_fdopen (int fd)
{
#ifdef HAVE_W32_SYSTEM
  assuan_fd_t ifd = (assuan_fd_t) _get_osfhandle (fd);
  assuan_fd_t ofd;

  if (! DuplicateHandle(GetCurrentProcess(), hfd, 
			GetCurrentProcess(), &ofd, 0,
			TRUE, DUPLICATE_SAME_ACCESS))
    {
      errno = EIO;
      return ASSUAN_INVALID_FD:
    }
  return ofd;
#else
  return dup (fd);
#endif
}


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
      errno = ENOMEM;
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


/* Copy the system hooks struct, paying attention to version
   differences.  SRC is usually from the user, DST MUST be from the
   library.  */
void
_assuan_system_hooks_copy (assuan_system_hooks_t dst,
			   assuan_system_hooks_t src)

{
  memset (dst, '\0', sizeof (*dst));

  dst->version = ASSUAN_SYSTEM_HOOKS_VERSION;
  if (src->version >= 1)
    {
      dst->usleep = src->usleep;
      dst->pipe = src->pipe;
      dst->close = src->close;
      dst->read = src->read;
      dst->write = src->write;
      dst->sendmsg = src->sendmsg;
      dst->recvmsg = src->recvmsg;
      dst->spawn = src->spawn;
      dst->waitpid = src->waitpid;
      dst->socketpair = src->socketpair;
    }
  if (src->version > 1)
    /* FIXME.  Application uses newer version of the library.  What to
       do?  */
    ;
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
      
    req.tv_sec = 0;
    req.tv_nsec = usec * 1000;
  
    while (nanosleep (&req, &rem) < 0 && errno == EINTR)
      req = rem;
  }
#elif defined(HAVE_W32_SYSTEM)
  Sleep (usec / 1000);
#else
  {
    struct timeval tv;
  
    tv.tv_sec  = usec / 1000000;
    tv.tv_usec = usec % 1000000;
    select (0, NULL, NULL, NULL, &tv);
  }
#endif
}


/* Sleep for the given number of microseconds.  */
void
_assuan_usleep (assuan_context_t ctx, unsigned int usec)
{
  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "_assuan_usleep", ctx,
	  "usec=%u", usec);

  (ctx->system.usleep) (ctx, usec);
}


/* Create a pipe with one inheritable end.  Default implementation.  */
int
__assuan_pipe (assuan_context_t ctx, assuan_fd_t fd[2], int inherit_idx)
{
#ifdef HAVE_W32_SYSTEM
  HANDLE rh;
  HANDLE wh;
  HANDLE th;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = FALSE;

  if (! CreatePipe (&rh, &wh, &sec_attr, 0))
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_pipe", ctx,
	      "CreatePipe failed: %s", _assuan_w32_strerror (ctx, -1));
      errno = EIO;
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
      errno = EIO;
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
#else
  return pipe (fd);
#endif
}


/* Create a pipe with one inheritable end.  */
int
_assuan_pipe (assuan_context_t ctx, assuan_fd_t fd[2], int inherit_idx)
{
  int err;
  TRACE_BEG2 (ctx, ASSUAN_LOG_SYSIO, "_assuan_pipe", ctx,
	      "inherit_idx=%i (Assuan uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  err = (ctx->system.pipe) (ctx, fd, inherit_idx);
  if (err)
    return TRACE_SYSRES (err);

  return TRACE_SUC2 ("read=0x%x, write=0x%x", fd[0], fd[1]); 
}


/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  Default implementation.  */
int
__assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
#ifdef HAVE_W32_SYSTEM
  int rc = closesocket (HANDLE2SOCKET(fd));
  if (rc)
    errno = _assuan_sock_wsa2errno (WSAGetLastError ());
  if (rc && WSAGetLastError () == WSAENOTSOCK)
    {
      rc = CloseHandle (fd);
      if (rc)
        /* FIXME. */
        errno = EIO;
    }
  return rc;
#else
  return close (fd);
#endif
}


/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  */
int
_assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "_assuan_close", ctx,
	  "fd=0x%x", fd);

  return (ctx->system.close) (ctx, fd);
}


static ssize_t
__assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
#ifdef HAVE_W32_SYSTEM
  /* Due to the peculiarities of the W32 API we can't use read for a
     network socket and thus we try to use recv first and fallback to
     read if recv detects that it is not a network socket.  */
  int res;

  res = recv (HANDLE2SOCKET (fd), buffer, size, 0);
  if (res == -1)
    {
      switch (WSAGetLastError ())
        {
        case WSAENOTSOCK:
          {
            DWORD nread = 0;
            
            res = ReadFile (fd, buffer, size, &nread, NULL);
            if (! res)
              {
                switch (GetLastError ())
                  {
                  case ERROR_BROKEN_PIPE:
		    errno = EPIPE;
		    break;

                  default:
		    errno = EIO; 
                  }
                res = -1;
              }
            else
              res = (int) nread;
          }
          break;
          
        case WSAEWOULDBLOCK:
	  errno = EAGAIN;
	  break;

        case ERROR_BROKEN_PIPE:
	  errno = EPIPE;
	  break;

        default:
	  errno = EIO;
	  break;
        }
    }
  return res;
#else	/*!HAVE_W32_SYSTEM*/
  return read (fd, buffer, size);
#endif	/*!HAVE_W32_SYSTEM*/
}


ssize_t
_assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
#if 0
  ssize_t res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_read", ctx,
	      "fd=0x%x, buffer=%p, size=%i", fd, buffer, size);
  res = (ctx->system.read) (ctx, fd, buffer, size);
  return TRACE_SYSRES (res);
#else
  return (ctx->system.read) (ctx, fd, buffer, size);
#endif
}


static ssize_t
__assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
		size_t size)
{
#ifdef HAVE_W32_SYSTEM
  /* Due to the peculiarities of the W32 API we can't use write for a
     network socket and thus we try to use send first and fallback to
     write if send detects that it is not a network socket.  */
  int res;

  res = send (HANDLE2SOCKET (fd), buffer, size, 0);
  if (res == -1 && WSAGetLastError () == WSAENOTSOCK)
    {
      DWORD nwrite;

      res = WriteFile (fd, buffer, size, &nwrite, NULL);
      if (! res)
        {
          switch (GetLastError ())
            {
            case ERROR_BROKEN_PIPE: 
            case ERROR_NO_DATA:
	      errno = EPIPE;
	      break;
	      
            default:
	      errno = EIO;
	      break;
            }
          res = -1;
        }
      else
        res = (int) nwrite;
    }
  return res;
#else	/*!HAVE_W32_SYSTEM*/
  return write (fd, buffer, size);
#endif	/*!HAVE_W32_SYSTEM*/
}


ssize_t
_assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
	       size_t size)
{
#if 0
  ssize_t res;
  TRACE_BEG3 (ctx, ASSUAN_LOG_SYSIO, "_assuan_write", ctx,
	      "fd=0x%x, buffer=%p, size=%i", fd, buffer, size);
  res = (ctx->system.write) (ctx, fd, buffer, size);
  return TRACE_SYSRES (res);
#else
  return (ctx->system.write) (ctx, fd, buffer, size);
#endif
}


static int
__assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
#ifdef HAVE_W32_SYSTEM
  errno = ENOSYS;
  return -1;
#else
  int ret;
  do
    ret = recvmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
#endif
}


int
_assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		 int flags)
{
  return (ctx->system.recvmsg) (ctx, fd, msg, flags);
}


static int
__assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
#ifdef HAVE_W32_SYSTEM
  errno = ENOSYS;
  return -1;
#else
  int ret;
  do
    ret = sendmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
#endif
}


int
_assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		 int flags)
{
  return (ctx->system.sendmsg) (ctx, fd, msg, flags);
}


#ifdef HAVE_W32_SYSTEM
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
  STARTUPINFO si;
  int fd;
  int *fdp;
  char *cmdline;
  HANDLE nullfd = INVALID_HANDLE_VALUE;

  /* fixme: Actually we should set the "_assuan_pipe_connect_pid" env
     variable.  However this requires us to write a full environment
     handler, because the strings are expected in sorted order.  The
     suggestion given in the MS Reference Library, to save the old
     value, changeit, create proces and restore it, is not thread
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
  fd = fileno (stderr);
  fdp = fd_child_list;
  if (fdp)
    {
      for (; *fdp != -1 && *fdp != fd; fdp++)
        ;
    }
  if (!fdp || *fdp == -1)
    {
      nullfd = CreateFile ("nul", GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
      if (nullfd == INVALID_HANDLE_VALUE)
        {
	  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		  "can't open `nul': %s", w32_strerror (ctx, -1));
          _assuan_free (cmdline);
          return -1;
        }
      si.hStdError = nullfd;
    }
  else
    si.hStdError = (void*)_get_osfhandle (fd);


  /* Note: We inherit all handles flagged as inheritable.  This seems
     to be a security flaw but there seems to be no way of selecting
     handles to inherit. */
  /*   _assuan_log_printf ("CreateProcess, path=`%s' cmdline=`%s'\n", */
  /*                       name, cmdline); */
  if (!CreateProcess (name,                 /* Program to start.  */
                      cmdline,              /* Command line arguments.  */
                      &sec_attr,            /* Process security attributes.  */
                      &sec_attr,            /* Thread security attributes.  */
                      TRUE,                 /* Inherit handles.  */
                      (CREATE_DEFAULT_ERROR_MODE
                       | ((flags & 128)? DETACHED_PROCESS : 0)
                       | GetPriorityClass (GetCurrentProcess ())
                       | CREATE_SUSPENDED), /* Creation flags.  */
                      NULL,                 /* Environment.  */
                      NULL,                 /* Use current drive/directory.  */
                      &si,                  /* Startup information. */
                      &pi                   /* Returns process information.  */
                      ))
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "pipe_connect_w32", ctx,
	      "CreateProcess failed: %s", w32_strerror (ctx, -1));
      _assuan_free (cmdline);
      if (nullfd != INVALID_HANDLE_VALUE)
        CloseHandle (nullfd);

      errno = EIO;
      return -1;
    }

  _assuan_free (cmdline);
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

#else

static int
writen (int fd, const char *buffer, size_t length)
{
  while (length)
    {
      int nwritten = write (fd, buffer, length);
      
      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* write error */
        }
      length -= nwritten;
      buffer += nwritten;
    }
  return 0;  /* okay */
}


int
__assuan_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
		const char **argv,
		assuan_fd_t fd_in, assuan_fd_t fd_out,
		assuan_fd_t *fd_child_list,
		void (*atfork) (void *opaque, int reserved),
		void *atforkvalue, unsigned int flags)
{
  int pid;

  pid = fork ();
  if (pid < 0)
    return -1;

  if (pid == 0)
    {
      /* Child process (server side).  */
      int i;
      int n;
      char errbuf[512];
      int *fdp;
      int fdnul;

      if (atfork)
	atfork (atforkvalue, 0);

      fdnul = open ("/dev/null", O_WRONLY);
      if (fdnul == -1)
	{
	  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		  "can't open `/dev/null': %s", strerror (errno));
	  _exit (4);
	}
      
      /* Dup handles to stdin/stdout. */
      if (fd_out != STDOUT_FILENO)
	{
	  if (dup2 (fd_out == ASSUAN_INVALID_FD ? fdnul : fd_out,
		    STDOUT_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		      "dup2 failed in child: %s", strerror (errno));
	      _exit (4);
	    }
	}
      
      if (fd_in != STDIN_FILENO)
	{
	  if (dup2 (fd_in == ASSUAN_INVALID_FD ? fdnul : fd_in,
		    STDIN_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		      "dup2 failed in child: %s", strerror (errno));
	      _exit (4);
	    }
	}
      
      /* Dup stderr to /dev/null unless it is in the list of FDs to be
	 passed to the child. */
      fdp = fd_child_list;
      if (fdp)
	{
	  for (; *fdp != -1 && *fdp != STDERR_FILENO; fdp++)
	    ;
	}
      if (!fdp || *fdp == -1)
	{
	  if (dup2 (fdnul, STDERR_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "pipe_connect_unix", ctx,
		      "dup2(dev/null, 2) failed: %s", strerror (errno));
	      _exit (4);
	    }
	}
      close (fdnul);
      
      /* Close all files which will not be duped and are not in the
	 fd_child_list. */
      n = sysconf (_SC_OPEN_MAX);
      if (n < 0)
	n = MAX_OPEN_FDS;
      for (i = 0; i < n; i++)
	{
	  if (i == STDIN_FILENO || i == STDOUT_FILENO || i == STDERR_FILENO)
	    continue;
	  fdp = fd_child_list;
	  if (fdp)
	    {
	      while (*fdp != -1 && *fdp != i)
		fdp++;
	    }
	  
	  if (!(fdp && *fdp != -1))
	    close (i);
	}
      errno = 0;
      
      if (! name)
	{
	  /* No name and no args given, thus we don't do an exec
	     but continue the forked process.  */
	  *argv = "server";
	  
	  /* FIXME: Cleanup.  */
	  return 0;
	}
      
      execv (name, (char *const *) argv); 
      
      /* oops - use the pipe to tell the parent about it */
      snprintf (errbuf, sizeof(errbuf)-1,
		"ERR %d can't exec `%s': %.50s\n",
		_assuan_error (ctx, GPG_ERR_ASS_SERVER_START),
		name, strerror (errno));
      errbuf[sizeof(errbuf)-1] = 0;
      writen (1, errbuf, strlen (errbuf));
      _exit (4);
    }

  if (! name)
    *argv = "client";
  
  *r_pid = pid;

  return 0;
}
#endif	/* ! HAVE_W32_SYSTEM */


/* Create a new process from NAME and ARGV.  Provide FD_IN and FD_OUT
   as stdin and stdout.  Inherit the ASSUAN_INVALID_FD-terminated
   FD_CHILD_LIST as given (no remapping), which must be inheritable.
   On Unix, call ATFORK with ATFORKVALUE after fork and before exec.  */
int
_assuan_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
	       const char **argv,
	       assuan_fd_t fd_in, assuan_fd_t fd_out,
	       assuan_fd_t *fd_child_list,
	       void (*atfork) (void *opaque, int reserved),
	       void *atforkvalue, unsigned int flags)
{
  int res;
  int i;
  TRACE_BEG6 (ctx, ASSUAN_LOG_CTX, "_assuan_spawn", ctx,
	      "name=%s,fd_in=0x%x,fd_out=0x%x,"
	      "atfork=%p,atforkvalue=%p,flags=%i",
	      name ? name : "(null)", fd_in, fd_out,
	      atfork, atforkvalue, flags);

  if (name)
    {
      i = 0;
      while (argv[i])
	{
	  TRACE_LOG2 ("argv[%2i] = %s", i, argv[i]);
	  i++;
	}
    }
  i = 0;
  if (fd_child_list)
    {
      while (fd_child_list[i] != ASSUAN_INVALID_FD)
	{
	  TRACE_LOG2 ("fd_child_list[%2i] = 0x%x", i, fd_child_list[i]);
	  i++;
	}
    }

  res = (ctx->system.spawn) (ctx, r_pid, name, argv, fd_in, fd_out,
			      fd_child_list, atfork, atforkvalue, flags);

  if (name)
    {
      TRACE_LOG1 ("pid = 0x%x", *r_pid);
    }
  else
    {
      TRACE_LOG2 ("pid = 0x%x (%s)", *r_pid, *argv);
    }

  return TRACE_SYSERR (res);
}


/* FIXME: Add some sort of waitpid function that covers GPGME and
   gpg-agent's use of assuan.  */
static pid_t 
__assuan_waitpid (assuan_context_t ctx, pid_t pid, int nowait,
		  int *status, int options)
{
#ifndef HAVE_W32_SYSTEM
  /* We can't just release the PID, a waitpid is mandatory.  But
     NOWAIT in POSIX systems just means the caller already did the
     waitpid for this child.  */
  if (! nowait)
    return waitpid (pid, NULL, 0); 
#else	/* ! HAVE_W32_SYSTEM */
  CloseHandle ((HANDLE) pid);
#endif	/* HAVE_W32_SYSTEM */
  return 0;
}


pid_t 
_assuan_waitpid (assuan_context_t ctx, pid_t pid, int action,
		 int *status, int options)
{
  return (ctx->system.waitpid) (ctx, pid, action, status, options);
}


int
__assuan_socketpair (assuan_context_t ctx, int namespace, int style,
		     int protocol, int filedes[2])
{
#if HAVE_W32_SYSTEM
  errno = ENOSYS;
  return -1;
#else
  return socketpair (namespace, style, protocol, filedes);
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
  
  res = (ctx->system.socketpair) (ctx, namespace, style, protocol, filedes);
  if (res == 0)
    TRACE_LOG2 ("filedes = { 0x%x, 0x%x }", filedes[0], filedes[1]);

  return TRACE_SYSERR (res);
}


/* The default system hooks for assuan contexts.  */
struct assuan_system_hooks _assuan_system_hooks =
  {
    ASSUAN_SYSTEM_HOOKS_VERSION,
    __assuan_usleep,
    __assuan_pipe,
    __assuan_close,
    __assuan_read,
    __assuan_write,
    __assuan_recvmsg,
    __assuan_sendmsg,
    __assuan_spawn,
    __assuan_waitpid,
    __assuan_socketpair    
  };
