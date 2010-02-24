/* gpgcempg.c - Manager fopr GPG CE devices
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

#warning Fixme: Add support to create the device.

int
main (int argc, char **argv)
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
  fflush (stdout);
  fflush (stderr);
  Sleep (1000);
  return result;
}


