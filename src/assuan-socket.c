/* assuan-socket.c
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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
 */

#include <config.h>
#include <stdio.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "assuan-defs.h"

/* Hacks for Slowaris.  */
#ifndef PF_LOCAL
# ifdef PF_UNIX
#  define PF_LOCAL PF_UNIX
# else
#  define PF_LOCAL AF_UNIX
# endif
#endif
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

int
_assuan_close (assuan_fd_t fd)
{
#ifdef HAVE_W32_SYSTEM
  int rc = closesocket (HANDLE2SOCKET(fd));
/*   if (rc) */
/*     _assuan_log_printf ("_assuan_close(%p): closesocket failed: %d/%ld\n", */
/*                         fd, rc, WSAGetLastError ()); */
  if (rc && WSAGetLastError () == WSAENOTSOCK)
    {
      rc = CloseHandle (fd);
/*       if (rc) */
/*         _assuan_log_printf ("_assuan_close(%p): CloseHandle failed: %d\n", */
/*                             fd, rc ); */
    }
  return rc;
#else
  return close (fd);
#endif
}


/* Return a new socket.  Note that under W32 we consider a socket the
   same as an System Handle; all functions using such a handle know
   about this dual use and act accordingly.  */ 
assuan_fd_t
_assuan_sock_new (int domain, int type, int proto)
{
#ifndef HAVE_W32_SYSTEM
  return socket (domain, type, proto);
#else
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;
  return SOCKET2HANDLE(socket (domain, type, proto));
#endif
}


int
_assuan_sock_connect (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
#ifndef HAVE_W32_SYSTEM
  return connect (sockfd, addr, addrlen);
#else
  struct sockaddr_in myaddr;
  struct sockaddr_un * unaddr;
  FILE * fp;
  int port = 0;
  
  unaddr = (struct sockaddr_un *)addr;
  fp = fopen (unaddr->sun_path, "rb");
  if (!fp)
      return -1;
  fscanf (fp, "%d", &port);
  fclose (fp);
  /* XXX: set errno in this case */
  if (port < 0 || port > 65535)
    return -1;
  
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = port; 
  myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  /* we need this later. */
  unaddr->sun_family = myaddr.sin_family;
  unaddr->sun_port = myaddr.sin_port;
  unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
  
  return connect (HANDLE2SOCKET(sockfd), (struct sockaddr *)&myaddr, sizeof myaddr);
#endif
}


int
_assuan_sock_bind (assuan_fd_t sockfd, struct sockaddr * addr, int addrlen)
{
#ifndef HAVE_W32_SYSTEM
  return bind (sockfd, addr, addrlen);
#else
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un * unaddr;
      FILE * fp;
      int len = sizeof myaddr;
      int rc;

      myaddr.sin_port = 0;
      myaddr.sin_family = AF_INET;
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      rc = bind (HANDLE2SOCKET(sockfd), (struct sockaddr *)&myaddr, len);
      if (rc)
        return rc;
      rc = getsockname (HANDLE2SOCKET(sockfd),
                        (struct sockaddr *)&myaddr, &len);
      if (rc)
        return rc;
      unaddr = (struct sockaddr_un *)addr;
      fp = fopen (unaddr->sun_path, "wb");
      if (!fp)
        return -1;
      fprintf (fp, "%d", myaddr.sin_port);
      fclose (fp);

      /* we need this later. */
      unaddr->sun_family = myaddr.sin_family;
      unaddr->sun_port = myaddr.sin_port;
      unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
      
      return 0;
    }
  return bind (HANDLE2SOCKET(sockfd), addr, addrlen);
#endif
}

