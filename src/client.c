/* client.c - Functions common to all clients.
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

#include "assuan-defs.h"
#include "debug.h"

void
_assuan_client_finish (assuan_context_t ctx)
{
  if (ctx->inbound.fd != ASSUAN_INVALID_FD)
    {
      _assuan_close (ctx, ctx->inbound.fd);
      if (ctx->inbound.fd == ctx->outbound.fd)
        ctx->outbound.fd = ASSUAN_INVALID_FD;
      ctx->inbound.fd = ASSUAN_INVALID_FD;
    }
  if (ctx->outbound.fd != ASSUAN_INVALID_FD)
    {
      _assuan_close (ctx, ctx->outbound.fd);
      ctx->outbound.fd = ASSUAN_INVALID_FD;
    }
  if (ctx->pid != ASSUAN_INVALID_PID && ctx->pid)
    {
      _assuan_waitpid (ctx, ctx->pid, ctx->flags.no_waitpid, NULL, 0);
      ctx->pid = ASSUAN_INVALID_PID;
    }

  _assuan_uds_deinit (ctx);
}


/* Disconnect and release the context CTX.  */
void
_assuan_client_release (assuan_context_t ctx)
{
  assuan_write_line (ctx, "BYE");

  _assuan_client_finish (ctx);
}
