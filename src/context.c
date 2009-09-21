/* context.c - Context specific interface.
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


/* Set user-data in a context.  */
void
assuan_set_pointer (assuan_context_t ctx, void *pointer)
{
  if (ctx)
    ctx->user_pointer = pointer;
}


/* Get user-data in a context.  */
void *
assuan_get_pointer (assuan_context_t ctx)
{
  if (! ctx)
    return NULL;

  return ctx->user_pointer;
}


/* For context CTX, set the flag FLAG to VALUE.  Values for flags
   are usually 1 or 0 but certain flags might allow for other values;
   see the description of the type assuan_flag_t for details.  */
void
assuan_set_flag (assuan_context_t ctx, assuan_flag_t flag, int value)
{
  if (!ctx)
    return;

  switch (flag)
    {
    case ASSUAN_NO_WAITPID:
      ctx->flags.no_waitpid = value;
      break;

    case ASSUAN_CONFIDENTIAL:
      ctx->flags.confidential = value;
      break;
    }
}


/* Return the VALUE of FLAG in context CTX.  */
int
assuan_get_flag (assuan_context_t ctx, assuan_flag_t flag)
{
  if (! ctx)
    return 0;

  switch (flag)
    {
    case ASSUAN_NO_WAITPID:
      return ctx->flags.no_waitpid;
    case ASSUAN_CONFIDENTIAL:
      return ctx->flags.confidential;
    }

  return 0;
}


/* Same as assuan_set_flag (ctx, ASSUAN_NO_WAITPID, 1).  */
void
assuan_begin_confidential (assuan_context_t ctx)
{
  assuan_set_flag (ctx, ASSUAN_CONFIDENTIAL, 1);
}


/* Same as assuan_set_flag (ctx, ASSUAN_NO_WAITPID, 0).  */
void
assuan_end_confidential (assuan_context_t ctx)
{
  assuan_set_flag (ctx, ASSUAN_CONFIDENTIAL, 0);
}


/* Set the IO monitor function.  */
void assuan_set_io_monitor (assuan_context_t ctx,
			    assuan_io_monitor_t io_monitor, void *hook_data)
{
  if (ctx)
    {
      ctx->io_monitor = io_monitor;
      ctx->io_monitor_data = hook_data;
    }
}


/* Store the error in the context so that the error sending function
  can take out a descriptive text.  Inside the assuan code, use the
  macro set_error instead of this function. */
gpg_error_t
assuan_set_error (assuan_context_t ctx, gpg_error_t err, const char *text)
{
  ctx->err_no = err;
  ctx->err_str = text;
  return err;
}
