/* common.h - Common functions for the tests.
 * Copyright (C) 2006 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

#include <stdarg.h>


static const char *log_prefix;
static int errorcount;
static int verbose;
static int debug;


void *
xmalloc (size_t n)
{
  char *p = malloc (n);
  if (!p)
    {
      fprintf (stderr, "out of core\n");
      exit (1);
    }
  return p;
}

void *
xcalloc (size_t n, size_t m)
{
  char *p = calloc (n, m);
  if (!p)
    {
      fprintf (stderr, "out of core\n");
      exit (1);
    }
  return p;
}

void
xfree (void *a)
{
  if (a)
    free (a);
}


void
log_set_prefix (const char *s)
{
  log_prefix = strrchr (s, '/');
  if (log_prefix)
    log_prefix++;
  else
    log_prefix = s;
}


void
log_info (const char *format, ...)
{
  va_list arg_ptr ;

  if (!verbose)
    return;

  va_start (arg_ptr, format) ;
  if (log_prefix)
    fprintf (stderr, "%s[%u]: ", log_prefix, (unsigned int)getpid ());
  vfprintf (stderr, format, arg_ptr );
  va_end (arg_ptr);
}


void
log_error (const char *format, ...)
{
  va_list arg_ptr ;

  va_start (arg_ptr, format) ;
  if (log_prefix)
    fprintf (stderr, "%s[%u]: ", log_prefix, (unsigned int)getpid ());
  vfprintf (stderr, format, arg_ptr );
  va_end (arg_ptr);
  errorcount++;
}


void
log_fatal (const char *format, ...)
{
  va_list arg_ptr ;

  va_start (arg_ptr, format) ;
  if (log_prefix)
    fprintf (stderr, "%s[%u]: ", log_prefix, (unsigned int)getpid ());
  vfprintf (stderr, format, arg_ptr );
  va_end (arg_ptr);
  exit (2);
}


void
log_printhex (const char *text, const void *buffer, size_t length)
{
  const unsigned char *s;

  if (log_prefix)
    fprintf (stderr, "%s[%u]: ", log_prefix, (unsigned int)getpid ());
  fputs (text, stderr);
  for (s=buffer; length; s++, length--)
    fprintf (stderr, "%02X", *s);
  putc ('\n', stderr);
}


/* Prepend FNAME with the srcdir environment variable's value and
   return an allocated filename. */
char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    srcdir = ".";
  
  result = xmalloc (strlen (srcdir) + 1 + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/");
  strcat (result, fname);
  return result;
}

