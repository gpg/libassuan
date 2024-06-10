/* assuan-pipe-connect.c - Establish a pipe connection (client)
 * Copyright (C) 2001, 2002, 2003, 2005, 2006, 2007, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <string.h>
/* On Windows systems signal.h is not needed and even not supported on
   WindowsCE. */
#ifndef HAVE_DOSISH_SYSTEM
# include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifndef HAVE_W32_SYSTEM
# include <sys/wait.h>
#else
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif

#include "assuan-defs.h"
#include "debug.h"

/* Hacks for Slowaris.  */
#ifndef PF_LOCAL
# ifdef PF_UNIX
#  define PF_LOCAL PF_UNIX
# else
#  define PF_LOCAL AF_UNIX
# endif
#endif
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif


/* This should be called to make sure that SIGPIPE gets ignored.  */
static void
fix_signals (void)
{
#ifndef HAVE_DOSISH_SYSTEM  /* No SIGPIPE for these systems.  */
  static int fixed_signals;

  if (!fixed_signals)
    {
      struct sigaction act;

      sigaction (SIGPIPE, NULL, &act);
      if (act.sa_handler == SIG_DFL)
	{
	  act.sa_handler = SIG_IGN;
	  sigemptyset (&act.sa_mask);
	  act.sa_flags = 0;
	  sigaction (SIGPIPE, &act, NULL);
        }
      fixed_signals = 1;
      /* FIXME: This is not MT safe */
    }
#endif /*HAVE_DOSISH_SYSTEM*/
}


/* Helper for pipe_connect. */
static gpg_error_t
initial_handshake (assuan_context_t ctx)
{
  assuan_response_t response;
  int off;
  gpg_error_t err;

  err = _assuan_read_from_server (ctx, &response, &off, 0);
  if (err)
    TRACE1 (ctx, ASSUAN_LOG_SYSIO, "initial_handshake", ctx,
	    "can't connect server: %s", gpg_strerror (err));
  else if (response == ASSUAN_RESPONSE_OK)
    {
#if defined(HAVE_W32_SYSTEM)
      const char *line = ctx->inbound.line + off;
      int process_id = -1;

      /* Parse the message: OK ..., process %i */
      line = strchr (line, ',');
      if (line)
        {
          line = strchr (line + 1, ' ');
          if (line)
            {
              line = strchr (line + 1, ' ');
              if (line)
                process_id = atoi (line + 1);
            }
        }
      if (process_id != -1)
        ctx->process_id = process_id;
#else
        ;
#endif
    }
  else
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "initial_handshake", ctx,
	      "can't connect server: `%s'", ctx->inbound.line);
      err = _assuan_error (ctx, GPG_ERR_ASS_CONNECT_FAILED);
    }

  return err;
}


struct at_pipe_fork
{
  void (*user_atfork) (void *opaque, int reserved);
  void *user_atforkvalue;
  pid_t parent_pid;
};


static void
at_pipe_fork_cb (void *opaque)
{
  struct at_pipe_fork *atp = opaque;

  if (atp->user_atfork)
    atp->user_atfork (atp->user_atforkvalue, 0);

#ifndef HAVE_W32_SYSTEM
  {
    char mypidstr[50];

    /* We store our parents pid in the environment so that the execed
       assuan server is able to read the actual pid of the client.
       The server can't use getppid because it might have been double
       forked before the assuan server has been initialized. */
    sprintf (mypidstr, "%lu", (unsigned long) atp->parent_pid);
    setenv ("_assuan_pipe_connect_pid", mypidstr, 1);

    /* Make sure that we never pass a connection fd variable when
       using a simple pipe.  */
    unsetenv ("_assuan_connection_fd");
  }
#endif
}


static int
my_spawn (assuan_context_t ctx, const char *name, const char **argv,
          assuan_fd_t *fd_child_list, void (*atfork) (void *opaque),
          void *atforkvalue, unsigned int spawn_flags)
{
  int i;
  gpgrt_spawn_actions_t act = NULL;
  gpg_err_code_t ec;
  gpgrt_process_t proc = NULL;
  int keep_stderr = 0;
  assuan_fd_t *fdp;

  TRACE_BEG4 (ctx, ASSUAN_LOG_CTX, "my_spawn", ctx,
	      "name=%s,atfork=%p,atforkvalue=%p,flags=%i",
	      name ? name : "(null)",
	      atfork, atforkvalue, spawn_flags);

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

  if (fd_child_list)
    {
      for (fdp = fd_child_list; *fdp != ASSUAN_INVALID_FD; fdp++)
        if (*fdp == (assuan_fd_t)STDERR_FILENO)
          {
            keep_stderr = 1;
            break;
          }
    }
  if (keep_stderr)
    spawn_flags |= GPGRT_PROCESS_STDERR_KEEP;

  ec = gpgrt_spawn_actions_new (&act);
  if (ec)
    return -1;

#ifdef HAVE_W32_SYSTEM
  gpgrt_spawn_actions_set_inherit_handles (act, fd_child_list);
#else
  gpgrt_spawn_actions_set_inherit_fds (act, fd_child_list);
  gpgrt_spawn_actions_set_atfork (act, atfork, atforkvalue);
#endif
  ec = gpgrt_process_spawn (name, argv+1, spawn_flags, act, &proc);
  gpgrt_spawn_actions_release (act);
  if (ec)
    return -1;
  ctx->server_proc = proc;

  if (proc)
    {
#ifdef HAVE_W32_SYSTEM
      HANDLE inbound, outbound;
      ec = gpgrt_process_ctl (proc, GPGRT_PROCESS_GET_HANDLES,
                              &inbound, &outbound, NULL);
#else
      int inbound, outbound;
      ec = gpgrt_process_get_fds (proc, 0, &inbound, &outbound, NULL);
#endif
      ctx->inbound.fd  = outbound;
      ctx->outbound.fd = inbound;
    }
  return TRACE_SYSERR (0);
}

static gpg_error_t
pipe_connect (assuan_context_t ctx,
	      const char *name, const char **argv,
	      assuan_fd_t *fd_child_list,
	      void (*atfork) (void *opaque, int reserved),
	      void *atforkvalue, unsigned int flags)
{
  gpg_error_t rc;
  int res;
  struct at_pipe_fork atp;
  unsigned int spawn_flags;

  atp.user_atfork = atfork;
  atp.user_atforkvalue = atforkvalue;
  atp.parent_pid = getpid ();

  if (!ctx || !name || !argv || !argv[0])
    return _assuan_error (ctx, GPG_ERR_ASS_INV_VALUE);

  if (! ctx->flags.no_fixsignals)
    fix_signals ();

  spawn_flags = GPGRT_PROCESS_STDIN_PIPE|GPGRT_PROCESS_STDOUT_PIPE;
  if (flags & ASSUAN_PIPE_CONNECT_DETACHED)
    spawn_flags |= GPGRT_PROCESS_NO_CONSOLE;

  res = my_spawn (ctx, name, argv, fd_child_list, at_pipe_fork_cb, &atp, spawn_flags);
  if (res < 0)
    {
      rc = gpg_err_code_from_syserror ();
      return _assuan_error (ctx, rc);
    }

  /* The fork feature on POSIX when NAME==NULL.  */
  if (!name)
    {
      /* Set ARGV[0] for backward compatibility.  */
      if (ctx->server_proc == NULL)
        {
          /* If this is the server child process, exit early.  */
          argv[0] = "server";
          return 0;
        }
      else
        argv[0] = "client";
    }

  ctx->engine.release = _assuan_client_release;
  ctx->engine.readfnc = _assuan_simple_read;
  ctx->engine.writefnc = _assuan_simple_write;
#ifdef HAVE_W32_SYSTEM
  ctx->engine.sendfd = w32_fdpass_send;
#else
  ctx->engine.sendfd = NULL;
#endif
  ctx->engine.receivefd = NULL;
  ctx->finish_handler = _assuan_client_finish;
  ctx->max_accepts = 1;
  ctx->accept_handler = NULL;

  rc = initial_handshake (ctx);
  if (rc)
    _assuan_reset (ctx);
  return rc;
}


/* FIXME: For socketpair_connect, use spawn function and add atfork
   handler to do the right thing.  Instead of stdin and stdout, we
   extend the fd_child_list by fds[1].  */

#ifndef HAVE_W32_SYSTEM
struct at_socketpair_fork
{
  assuan_fd_t peer_fd;
  void (*user_atfork) (void *opaque, int reserved);
  void *user_atforkvalue;
  pid_t parent_pid;
};


static void
at_socketpair_fork_cb (void *opaque)
{
  struct at_socketpair_fork *atp = opaque;

  if (atp->user_atfork)
    atp->user_atfork (atp->user_atforkvalue, 0);

#ifndef HAVE_W32_SYSTEM
  {
    char mypidstr[50];

    /* We store our parents pid in the environment so that the execed
       assuan server is able to read the actual pid of the client.
       The server can't use getppid because it might have been double
       forked before the assuan server has been initialized. */
    sprintf (mypidstr, "%lu", (unsigned long) atp->parent_pid);
    setenv ("_assuan_pipe_connect_pid", mypidstr, 1);

    /* Now set the environment variable used to convey the
       connection's file descriptor.  */
    sprintf (mypidstr, "%d", atp->peer_fd);
    if (setenv ("_assuan_connection_fd", mypidstr, 1))
      _exit (4);
  }
#endif
}


/* This function is similar to pipe_connect but uses a socketpair and
   sets the I/O up to use sendmsg/recvmsg. */
static gpg_error_t
socketpair_connect (assuan_context_t ctx, const char *name, const char **argv,
                    assuan_fd_t *fd_child_list,
                    void (*atfork) (void *opaque, int reserved),
                    void *atforkvalue)
{
  gpg_error_t err;
  int idx;
  int fds[2];
  char mypidstr[50];
  int *child_fds = NULL;
  int child_fds_cnt = 0;
  struct at_socketpair_fork atp;
  int rc;

  TRACE_BEG3 (ctx, ASSUAN_LOG_CTX, "socketpair_connect", ctx,
	      "name=%s,atfork=%p,atforkvalue=%p", name ? name : "(null)",
	      atfork, atforkvalue);

  atp.user_atfork = atfork;
  atp.user_atforkvalue = atforkvalue;
  atp.parent_pid = getpid ();

  if (!ctx
      || (name && (!argv || !argv[0]))
      || (!name && !argv))
    return _assuan_error (ctx, GPG_ERR_ASS_INV_VALUE);

  if (! ctx->flags.no_fixsignals)
    fix_signals ();

  sprintf (mypidstr, "%lu", (unsigned long)getpid ());

  if (fd_child_list)
    while (fd_child_list[child_fds_cnt] != ASSUAN_INVALID_FD)
      child_fds_cnt++;
  child_fds = _assuan_malloc (ctx, (child_fds_cnt + 2) * sizeof (int));
  if (! child_fds)
    return TRACE_ERR (gpg_err_code_from_syserror ());
  child_fds[1] = ASSUAN_INVALID_FD;
  if (fd_child_list)
    memcpy (&child_fds[1], fd_child_list, (child_fds_cnt + 1) * sizeof (int));

  if (_assuan_socketpair (ctx, AF_LOCAL, SOCK_STREAM, 0, fds))
    {
      TRACE_LOG1 ("socketpair failed: %s", strerror (errno));
      _assuan_free (ctx, child_fds);
      return TRACE_ERR (GPG_ERR_ASS_GENERAL);
    }
  atp.peer_fd = fds[1];
  child_fds[0] = fds[1];

  rc = my_spawn (ctx, name, argv, child_fds, at_socketpair_fork_cb,
                 &atp, 0);
  if (rc < 0)
    {
      err = gpg_err_code_from_syserror ();
      _assuan_close (ctx, fds[0]);
      _assuan_close (ctx, fds[1]);
      _assuan_free (ctx, child_fds);
      return TRACE_ERR (err);
    }

  /* For W32, the user needs to know the server-local names of the
     inherited handles.  Return them here.  Note that the translation
     of the peer socketpair fd (fd_child_list[0]) must be done by the
     wrapper program based on the environment variable
     _assuan_connection_fd.  */
  if (fd_child_list)
    {
      for (idx = 0; fd_child_list[idx] != -1; idx++)
	/* We add 1 to skip over the socketpair end.  */
	fd_child_list[idx] = child_fds[idx + 1];
    }

  _assuan_free (ctx, child_fds);

  /* The fork feature on POSIX when NAME==NULL.  */
  if (!name)
    {
      /* Set ARGV[0] for backward compatibility.  */
      if (ctx->server_proc == NULL)
        {
          /* If this is the server child process, exit early.  */
          argv[0] = "server";
          return 0;
        }
      else
        argv[0] = "client";
    }

  _assuan_close (ctx, fds[1]);

  ctx->engine.release = _assuan_client_release;
  ctx->finish_handler = _assuan_client_finish;
  ctx->max_accepts = 1;
  ctx->inbound.fd  = fds[0];
  ctx->outbound.fd = fds[0];
  _assuan_init_uds_io (ctx);

  err = initial_handshake (ctx);
  if (err)
    _assuan_reset (ctx);
  return err;
}
#endif /*!HAVE_W32_SYSTEM*/


/* Connect to a server over a full-duplex socket (i.e. created by
   socketpair), creating the assuan context and returning it in CTX.
   The server filename is NAME, the argument vector in ARGV.
   FD_CHILD_LIST is a -1 terminated list of file descriptors not to
   close in the child.  ATFORK is called in the child right after the
   fork; ATFORKVALUE is passed as the first argument and 0 is passed
   as the second argument. The ATFORK function should only act if the
   second value is 0.

   FLAGS is a bit vector and controls how the function acts:
   Bit 0: If cleared a simple pipe based server is expected and the
          function behaves similar to `assuan_pipe_connect'.

          If set a server based on full-duplex pipes is expected. Such
          pipes are usually created using the `socketpair' function.
          It also enables features only available with such servers.

   Bit 7: If set and there is a need to start the server it will be
          started as a background process.  This flag is useful under
          W32 systems, so that no new console is created and pops up a
          console window when starting the server


   If NAME is NULL, no exec is done but the same process is continued.
   However all file descriptors are closed and some special
   environment variables are set. To let the caller detect whether the
   child or the parent continues, the child returns "client" or
   "server" in *ARGV (but it is sufficient to check only the first
   character).  This feature is only available on POSIX platforms.  */
gpg_error_t
assuan_pipe_connect (assuan_context_t ctx,
		     const char *name, const char *argv[],
		     assuan_fd_t *fd_child_list,
		     void (*atfork) (void *opaque, int reserved),
		     void *atforkvalue, unsigned int flags)
{
  TRACE2 (ctx, ASSUAN_LOG_CTX, "assuan_pipe_connect", ctx,
	  "name=%s, flags=0x%x", name ? name : "(null)", flags);

#ifndef HAVE_W32_SYSTEM
  if (flags & ASSUAN_PIPE_CONNECT_FDPASSING)
    return socketpair_connect (ctx, name, argv, fd_child_list,
			       atfork, atforkvalue);
  else
#endif
    return pipe_connect (ctx, name, argv, fd_child_list, atfork, atforkvalue,
                         flags);
}

gpg_error_t
assuan_pipe_wait_server_termination (assuan_context_t ctx, int *status,
                                     int no_hang)
{
  gpg_err_code_t ec;

  if (ctx->server_proc == NULL)
    return _assuan_error (ctx, GPG_ERR_NO_SERVICE);

  ec = gpgrt_process_wait (ctx->server_proc, !no_hang);

  if (ec)
    return _assuan_error (ctx, ec);

  return 0;
}

gpg_error_t
assuan_pipe_kill_server (assuan_context_t ctx)
{
  if (ctx->server_proc == NULL)
    ; /* No pid available can't send a kill. */
  else
    {
      _assuan_pre_syscall ();
      gpgrt_process_terminate (ctx->server_proc);
      _assuan_post_syscall ();
    }
  return 0;
}
