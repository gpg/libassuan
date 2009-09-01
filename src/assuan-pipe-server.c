/* assuan-pipe-server.c - Assuan server working over a pipe 
   Copyright (C) 2001, 2002, 2009 Free Software Foundation, Inc.

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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#include <fcntl.h>
#endif

#include "assuan-defs.h"


static void
deinit_pipe_server (assuan_context_t ctx)
{
  /* nothing to do for this simple server */
}

static gpg_error_t
accept_connection (assuan_context_t ctx)
{
  /* This is a NOP for a pipe server */
  return 0;
}

static gpg_error_t
finish_connection (assuan_context_t ctx)
{
  /* This is a NOP for a pipe server */
  return 0;
}

/* Create a new context.  Note that the handlers are set up for a pipe
   server/client - this way we don't need extra dummy functions */
gpg_error_t
_assuan_new_context (assuan_context_t *r_ctx)
{
  static struct assuan_io io = { _assuan_simple_read,
				 _assuan_simple_write,
				 0, 0 };

  assuan_context_t ctx;
  gpg_error_t rc;

  *r_ctx = NULL;
  ctx = _assuan_calloc (1, sizeof *ctx);
  if (!ctx)
    return _assuan_error (gpg_err_code_from_syserror ());
  ctx->input_fd = ASSUAN_INVALID_FD;
  ctx->output_fd = ASSUAN_INVALID_FD;

  ctx->inbound.fd = ASSUAN_INVALID_FD;
  ctx->outbound.fd = ASSUAN_INVALID_FD;
  ctx->io = &io;

  ctx->listen_fd = ASSUAN_INVALID_FD;
  /* Use the pipe server handler as a default.  */
  ctx->deinit_handler = deinit_pipe_server;
  ctx->accept_handler = accept_connection;
  ctx->finish_handler = finish_connection;

  rc = _assuan_register_std_commands (ctx);
  if (rc)
    _assuan_free (ctx);
  else
    *r_ctx = ctx;
  return rc;
}


/* Returns true if atoi(S) denotes a valid socket. */
#ifndef HAVE_W32_SYSTEM
static int
is_valid_socket (const char *s)
{
  struct stat buf;

  if ( fstat (atoi (s), &buf ) )
    return 0;
  return S_ISSOCK (buf.st_mode);
}
#endif /*!HAVE_W32_SYSTEM*/


gpg_error_t
assuan_init_pipe_server (assuan_context_t *r_ctx, int filedes[2])
{
  int rc;

  rc = _assuan_new_context (r_ctx);
  if (!rc)
    {
      assuan_context_t ctx = *r_ctx;
      const char *s;
      unsigned long ul;

      ctx->is_server = 1;
#ifdef HAVE_W32_SYSTEM
      /* MS Windows has so many different types of handle that one
         needs to tranlsate them at many place forth and back.  Also
         make sure that the file descriptors are in binary mode.  */
      setmode (filedes[0], O_BINARY);
      setmode (filedes[1], O_BINARY);
      ctx->inbound.fd  = (void*)_get_osfhandle (filedes[0]);
      ctx->outbound.fd = (void*)_get_osfhandle (filedes[1]);
#else
      s = getenv ("_assuan_connection_fd");
      if (s && *s && is_valid_socket (s) )
        {
          /* Well, we are called with an bi-directional file
             descriptor.  Prepare for using sendmsg/recvmsg.  In this
             case we ignore the passed file descriptors. */
          ctx->inbound.fd  = ctx->outbound.fd = atoi (s);
          _assuan_init_uds_io (ctx);
          ctx->deinit_handler = _assuan_uds_deinit;
        }
      else if (filedes && filedes[0] != ASSUAN_INVALID_FD 
               && filedes[1] != ASSUAN_INVALID_FD )
        {
          /* Standard pipe server. */
          ctx->inbound.fd  = filedes[0];
          ctx->outbound.fd = filedes[1];
        }
      else
        {
          _assuan_release_context (*r_ctx);
          *r_ctx = NULL;
          return _assuan_error (GPG_ERR_ASS_SERVER_START);
        }
#endif
      ctx->pipe_mode = 1;

      s = getenv ("_assuan_pipe_connect_pid");
      if (s && (ul=strtoul (s, NULL, 10)) && ul)
        ctx->pid = (pid_t)ul;
      else
        ctx->pid = (pid_t)-1;

    }
  return rc;
}


void
_assuan_release_context (assuan_context_t ctx)
{
  if (ctx)
    {
      _assuan_inquire_release (ctx);
      _assuan_free (ctx->hello_line);
      _assuan_free (ctx->okay_line);
      _assuan_free (ctx->cmdtbl);
      _assuan_free (ctx);
    }
}

void
assuan_deinit_server (assuan_context_t ctx)
{
  if (ctx)
    {
      /* We use this function pointer to avoid linking other server
         when not needed but still allow for a generic deinit function.  */
      ctx->deinit_handler (ctx);
      ctx->deinit_handler = NULL;
      _assuan_release_context (ctx);
    }
}
