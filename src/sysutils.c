/* sysutils.c - System utilities
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif /*HAVE_W32_SYSTEM*/

#include "assuan-defs.h"


/* This is actually a dummy function to make sure that is module is
   not empty.  Some compilers barf on empty modules.  */
const char *
_assuan_sysutils_blurb (void)
{
  static const char blurb[] =
    "\n\n"
    "This is Libassuan " PACKAGE_VERSION " - The GnuPG IPC Library\n"
    "Copyright 2001-2013 Free Software Foundation, Inc.\n"
    "Copyright 2001-2021,2023-2025 g10 Code GmbH\n"
    "\n"
    "SPDX-License-Identifier: LGPL-2.1-or-later\n"
    "(" BUILD_COMMITID " " BUILD_TIMESTAMP ")\n"
    "\n\n";
  return blurb;
}
