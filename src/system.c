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

#include "assuan-defs.h"
#include "debug.h"


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
