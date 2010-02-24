/* sysutils.c - System utilities
   Copyright (C) 2010 Free Software Foundation, Inc.

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
# ifdef HAVE_W32CE_SYSTEM
# include <winioctl.h>
# include <devload.h>
# endif /*HAVE_W32CE_SYSTEM*/
#endif /*HAVE_W32_SYSTEM*/

#include "assuan-defs.h"

#ifdef HAVE_W32CE_SYSTEM
#define GPGCEDEV_IOCTL_SET_HANDLE                                      \
  CTL_CODE (FILE_DEVICE_STREAMS, 2048, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GPGCEDEV_IOCTL_MAKE_PIPE                                        \
  CTL_CODE (FILE_DEVICE_STREAMS, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /*HAVE_W32CE_SYSTEM*/



/* This is actually a dummy function to make sure that is module is
   not empty.  Sokme compilers barf on that.  */
const char *
_assuan_sysutils_blurb (void)
{
  static const char blurb[] = 
    "\n\n"
    "This is Libassuan - The GnuPG IPC Library\n"
    "Copyright 2000, 2002, 2003, 2004, 2007, 2008, 2009,\n"
    "          2010 Free Software Foundation, Inc.\n"
    "\n\n";
  return blurb;
}


/* Return a string from the Win32 Registry or NULL in case of error.
   The returned string is allocated using a plain malloc and thus the
   caller needs to call the standard free().  The string is looked up
   under HKEY_LOCAL_MACHINE.  */
#ifdef HAVE_W32CE_SYSTEM
static char *
w32_read_registry (const wchar_t *dir, const wchar_t *name)
{
  HKEY handle;
  DWORD n, nbytes;
  wchar_t *buffer = NULL;
  char *result = NULL;
  
  if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &handle))
    return NULL; /* No need for a RegClose, so return immediately. */

  nbytes = 1;
  if (RegQueryValueEx (handle, name, 0, NULL, NULL, &nbytes))
    goto leave;
  buffer = malloc ((n=nbytes+2));
  if (!buffer)
    goto leave;
  if (RegQueryValueEx (handle, name, 0, NULL, (PBYTE)buffer, &n))
    {
      free (buffer);
      buffer = NULL;
      goto leave;
    }
  
  n = WideCharToMultiByte (CP_UTF8, 0, buffer, nbytes, NULL, 0, NULL, NULL);
  if (n < 0 || (n+1) <= 0)
    goto leave;
  result = malloc (n+1);
  if (!result)
    goto leave;
  n = WideCharToMultiByte (CP_UTF8, 0, buffer, nbytes, result, n, NULL, NULL);
  if (n < 0)
    {
      free (result);
      result = NULL;
      goto leave;
    }
  result[n] = 0;

 leave:
  free (buffer);
  RegCloseKey (handle);
  return result;
}
#endif /*HAVE_W32CE_SYSTEM*/



#ifdef HAVE_W32CE_SYSTEM
/* Replacement for getenv which takes care of the our use of getenv.
   The code is not thread safe but we expect it to work in all cases
   because it is called for the first time early enough.  */
char *
_assuan_getenv (const char *name)
{
  static int initialized;
  static char *val_debug;
  static char *val_full_logging;

  if (!initialized)
    {
      val_debug = w32_read_registry (L"\\Software\\GNU\\libassuan",
                                     L"debug");
      val_full_logging = w32_read_registry (L"\\Software\\GNU\\libassuan",
                                            L"full_logging");
      initialized = 1;
    }


  if (!strcmp (name, "ASSUAN_DEBUG"))
    return val_debug;
  else if (!strcmp (name, "ASSUAN_FULL_LOGGING"))
    return val_full_logging;
  else
    return NULL;
}
#endif /*HAVE_W32CE_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
/* WindowsCE does not provide a pipe feature.  However we need
   something like a pipe to convey data between processes and in some
   cases within a process.  This replacement is not only used by
   libassuan but exported and thus usable by gnupg and gpgme as well.  */
DWORD
_assuan_w32ce_create_pipe (HANDLE *read_hd, HANDLE *write_hd,
                           LPSECURITY_ATTRIBUTES sec_attr, DWORD size)
{
#ifdef HAVE_W32CE_SYSTEM
  HANDLE hd[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};

  *read_hd = *write_hd = INVALID_HANDLE_VALUE;

  ActivateDevice (L"Drivers\\GnuPG_Device", 0);

  /* Note: Using "\\$device\\GPG1" should be identical to "GPG1:".
     However this returns an invalid parameter error without having
     called GPG_Init in the driver.  The docs mention something about
     RegisterAFXEx but that API is not documented.  */
  hd[0] = CreateFile (L"GPG1:", GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hd[0] == INVALID_HANDLE_VALUE)
    return 0;

  if (!DeviceIoControl (hd[0], GPGCEDEV_IOCTL_SET_HANDLE,
                        &hd[0], sizeof hd[0], NULL, 0, NULL, NULL))
    fprintf (stderr, "GPGCEDEV_IOCTL_SET_HANDLE(0) failed: %d\n", 
             (int)GetLastError ());
  
  hd[1] = CreateFile (L"GPG1:", GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL);
  if (hd[1] == INVALID_HANDLE_VALUE)
    {
      DWORD lasterr = GetLastError ();
      CloseHandle (hd[0]);
      SetLastError (lasterr);
      return 0;
    }
  if (!DeviceIoControl (hd[1], GPGCEDEV_IOCTL_SET_HANDLE,
                        &hd[1], sizeof hd[1], NULL, 0, NULL, NULL))
    fprintf (stderr, "GPGCEDEV_IOCTL_SET_HANDLE(1) failed: %d\n", 
             (int)GetLastError ());

  if (!DeviceIoControl (hd[0], GPGCEDEV_IOCTL_MAKE_PIPE,
                        &hd[1], sizeof hd[1], NULL, 0, NULL, NULL))
    {
      fprintf (stderr, "GPGCEDEV_IOCTL_MAKE_PIPE failed: %d\n", 
               (int)GetLastError ());
      if (hd[0] != INVALID_HANDLE_VALUE)
        CloseHandle (hd[0]);
      if (hd[1] != INVALID_HANDLE_VALUE)
        CloseHandle (hd[1]);
      return 0;
    }
  else
    {
      *read_hd = hd[0];
      *write_hd = hd[1];
      return 1;
    }
#else /*!HAVE_W32CE_SYSTEM*/
  return CreatePipe (read_hd, write_hd, sec_attr, size);
#endif /*!HAVE_W32CE_SYSTEM*/
}

#endif /*!HAVE_W32_SYSTEM*/

