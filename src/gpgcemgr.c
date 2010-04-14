/* gpgcempr.c - Manager for GPG CE devices
   Copyright (C) 2010 Free Software Foundation, Inc.

   This file is part of Assuan.

   Assuan is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of
   the License, or (at your option) any later version.

   Assuan is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define _WIN32_WCE 0x0500

#include <stdio.h>
#include <windows.h>

#define PGM "gpgcemgr"

#define GPGCEDEV_KEY_NAME L"Drivers\\GnuPG_Device"
#define GPGCEDEV_DLL_NAME L"gpgcedev.dll"
#define GPGCEDEV_PREFIX   L"GPG"


static int
install (void)
{
  HKEY handle;
  DWORD disp, dw;
  
  if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, GPGCEDEV_KEY_NAME, 0, NULL, 0,
                      KEY_WRITE, NULL, &handle, &disp))
    {
      fprintf (stderr, PGM": error creating registry key: rc=%d\n", 
               (int)GetLastError ());
      return 1;
    }

  RegSetValueEx (handle, L"dll", 0, REG_SZ, 
                 (void*)GPGCEDEV_DLL_NAME, sizeof (GPGCEDEV_DLL_NAME));
  RegSetValueEx (handle, L"prefix", 0, REG_SZ,
                 (void*)GPGCEDEV_PREFIX, sizeof (GPGCEDEV_PREFIX));

  dw = 1;
  RegSetValueEx (handle, L"Index", 0, REG_DWORD, (void*)&dw, sizeof dw);
  
  RegCloseKey (handle);

  fprintf (stderr, PGM": registry key created\n");


  return 0;
}


static int
deinstall (void)
{
  int result = 0;
  HANDLE shd;
  DEVMGR_DEVICE_INFORMATION dinfo;

  memset (&dinfo, 0, sizeof dinfo);
  dinfo.dwSize = sizeof dinfo;
  shd = FindFirstDevice (DeviceSearchByLegacyName, L"GPG1:", &dinfo);
  if (shd == INVALID_HANDLE_VALUE)
    {
      if (GetLastError () == 18)
        fprintf (stderr, PGM": device not found\n");
      else
        {
          fprintf (stderr, PGM": FindFirstDevice failed: rc=%d\n", 
                   (int)GetLastError ());
          result = 1;
        }
    }
  else
    {
      fprintf (stderr, PGM": ActivateDevice handle is %p\n", dinfo.hDevice);
      if (dinfo.hDevice && dinfo.hDevice != INVALID_HANDLE_VALUE)
        {
          if (!DeactivateDevice (dinfo.hDevice))
            {
              fprintf (stderr, PGM": DeactivateDevice failed: rc=%d\n",
                       (int)GetLastError ());
              result = 1;
            }
          else
            fprintf (stderr, PGM": DeactivateDevice succeeded\n");
        }
      FindClose (shd);
    }

  return result;
}



int
main (int argc, char **argv)
{
  int result = 0;

  if (argc > 1 && !strcmp (argv[1], "--register"))
    result = install ();
  else if (argc > 1 && !strcmp (argv[1], "--deactivate"))
    result = deinstall ();
  else if (argc > 1 && !strcmp (argv[1], "--activate"))
    {
      /* This is mainly for testing.  The activation is usually done
         right before the device is opened.  */
      if (ActivateDevice (GPGCEDEV_DLL_NAME, 0) == INVALID_HANDLE_VALUE)
        {
          fprintf (stderr, PGM": ActivateDevice failed: rc=%d\n",
                   (int)GetLastError ());
          result = 1;
        }
      else
        fprintf (stderr, PGM": device activated\n");
    }
  else
    {
      fprintf (stderr, "usage: " PGM " --register|--deactivate|--activate\n");
      result = 1;
    }

  fflush (stdout);
  fflush (stderr);
  Sleep (1000);
  return result;
}


