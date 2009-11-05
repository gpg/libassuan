/* assuan-connect.c - Establish a connection (client) 
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
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "assuan-defs.h"

/* Disconnect and release the context CTX. */
void
_assuan_disconnect (assuan_context_t ctx)
{
  assuan_write_line (ctx, "BYE");
  ctx->finish_handler (ctx);
  ctx->finish_handler = NULL;
  ctx->deinit_handler (ctx);
  ctx->deinit_handler = NULL;

  _assuan_inquire_release (ctx);
  _assuan_free (ctx, ctx->hello_line);
  ctx->hello_line = NULL;
  _assuan_free (ctx, ctx->okay_line);
  ctx->okay_line = NULL;
  _assuan_free (ctx, ctx->cmdtbl);
  ctx->cmdtbl = NULL;
}


/* Return the PID of the peer or -1 if not known. This function works
   in some situations where assuan_get_ucred fails. */
pid_t
assuan_get_pid (assuan_context_t ctx)
{
  return (ctx && ctx->pid) ? ctx->pid : -1;
}
