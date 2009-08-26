/* assuan-error.c
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

#include <stdio.h>
#include <assert.h>
#include <errno.h>

#undef _ASSUAN_IN_LIBASSUAN /* undef to get all error codes. */
#include "assuan.h"
#include "assuan-defs.h"

/* If true the modern gpg-error style error codes are used in the
   API. */
static gpg_err_source_t err_source;

/* Enable gpg-error style error codes.  ERRSOURCE is one of gpg-error
   sources.  Note, that this function is not thread-safe and should be
   used right at startup. Switching back to the old style mode is not
   supported. */
void
assuan_set_assuan_err_source (gpg_err_source_t errsource)
{
  errsource &= 0xff;
  err_source = errsource ? errsource : 31 /*GPG_ERR_SOURCE_ANY*/;
}


/* Helper to map old style Assuan error codes to gpg-error codes.
   This is used internally to keep an compatible ABI. */
gpg_error_t
_assuan_error (gpg_err_code_t errcode)
{
  return gpg_err_make (err_source, errcode);
}


/* A small helper function to treat EAGAIN transparently to the
   caller.  */
int
_assuan_error_is_eagain (gpg_error_t err)
{
  if (gpg_err_code (err) == GPG_ERR_EAGAIN)
    {
      /* Avoid spinning by sleeping for one tenth of a second.  */
       _assuan_usleep (100000);
       return 1;
    }
  else
    return 0;
}
