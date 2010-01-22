/* assuan-logging.c - Default logging function.
   Copyright (C) 2002, 2003, 2004, 2007, 2009 Free Software Foundation, Inc.

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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif /*HAVE_W32_SYSTEM*/
#include <errno.h>
#include <ctype.h>

#include "assuan-defs.h"


/* The default log handler is useful for global logging, but it should
   only be used by one user of libassuan at a time.  Libraries that
   use libassuan can register their own log handler.  */

/* A common prefix for all log messages.  */
static char prefix_buffer[80];

/* A global flag read from the environment to check if to enable full
   logging of buffer data.  */
static int full_logging;

/* A bitfield that specifies the categories to log.  Note that
   assuan-buffer currently does not log through the default handler,
   but directly.  This will be changed later.  Then the default here
   should be to log that and only that.  */
static int log_cats;
#define TEST_LOG_CAT(x) (!! (log_cats & (1 << (x - 1))))

static FILE *_assuan_log;

void
assuan_set_assuan_log_stream (FILE *fp)
{
  char *flagstr;

  _assuan_log = fp;

  /* Set defaults.  */
  full_logging = !!getenv ("ASSUAN_FULL_LOGGING");
  flagstr = getenv ("ASSUAN_DEBUG");
  if (flagstr)
    log_cats = atoi (flagstr);
}


/* Set the per context log stream.  Also enable the default log stream
   if it has not been set.  */
void
assuan_set_log_stream (assuan_context_t ctx, FILE *fp)
{
  if (ctx)
    {
      if (ctx->log_fp)
        fflush (ctx->log_fp);
      ctx->log_fp = fp;
      if (! _assuan_log)
	assuan_set_assuan_log_stream (fp);
    }
}


/* Set the prefix to be used for logging to TEXT or resets it to the
   default if TEXT is NULL. */
void
assuan_set_assuan_log_prefix (const char *text)
{
  if (text)
    {
      strncpy (prefix_buffer, text, sizeof (prefix_buffer)-1);
      prefix_buffer[sizeof (prefix_buffer)-1] = 0;
    }
  else
    *prefix_buffer = 0;
}


/* Get the prefix to be used for logging.  */
const char *
assuan_get_assuan_log_prefix (void)
{
  return prefix_buffer;
}


/* Default log handler.  */
int
_assuan_log_handler (assuan_context_t ctx, void *hook, unsigned int cat,
		     const char *msg)
{
  FILE *fp;
  const char *prf;
  int saved_errno = errno;

  /* For now.  */
  if (msg == NULL)
    return TEST_LOG_CAT (cat);

  if (! TEST_LOG_CAT (cat))
    return 0;

  fp = ctx->log_fp ? ctx->log_fp : _assuan_log;
  if (!fp)
    return 0;

  prf = assuan_get_assuan_log_prefix ();
  if (*prf)
    fprintf (fp, "%s[%u]: ", prf, (unsigned int)getpid ());

  fprintf (fp, "%s", msg);
  /* If the log stream is a file, the output would be buffered.  This
     is bad for debugging, thus we flush the stream if FORMAT ends
     with a LF.  */ 
  if (msg && *msg && msg[strlen (msg) - 1] == '\n')
    fflush (fp);
  gpg_err_set_errno (saved_errno);

  return 0;
}


/* Dump a possibly binary string (used for debugging).  Distinguish
   ascii text from binary and print it accordingly.  This function
   takes FILE pointer arg because logging may be enabled on a per
   context basis.  */
void
_assuan_log_print_buffer (FILE *fp, const void *buffer, size_t length)
{
  const unsigned char *s;
  unsigned int n;

  for (n = length, s = buffer; n; n--, s++)
    if  ((! isascii (*s) || iscntrl (*s) || ! isprint (*s)) && !(*s >= 0x80))
      break;

  s = buffer;
  if (! n && *s != '[')
    fwrite (buffer, length, 1, fp);
  else
    {
#ifdef HAVE_FLOCKFILE
      flockfile (fp);
#endif
      putc_unlocked ('[', fp);
      if (length > 16 && ! full_logging)
        {
          for (n = 0; n < 12; n++, s++)
            fprintf (fp, " %02x", *s);
          fprintf (fp, " ...(%d bytes skipped)", (int) length - 12);
        }
      else
        {
          for (n = 0; n < length; n++, s++)
            fprintf (fp, " %02x", *s);
        }
      putc_unlocked (' ', fp);
      putc_unlocked (']', fp);
#ifdef HAVE_FUNLOCKFILE
      funlockfile (fp);
#endif
    }
}
