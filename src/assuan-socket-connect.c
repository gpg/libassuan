/* assuan-socket-connect.c - Assuan socket based client
   Copyright (C) 2002, 2003, 2004, 2009 Free Software Foundation, Inc.

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

#include <config.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <windows.h>
#endif

#include "assuan-defs.h"
#include "debug.h"

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

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
	               + strlen ((ptr)->sun_path))
#endif


/* Make a connection to the Unix domain socket NAME and return a new
   Assuan context in CTX.  SERVER_PID is currently not used but may
   become handy in the future.  With flags set to 1 sendmsg and
   recvmsg are used. */
gpg_error_t
assuan_socket_connect (assuan_context_t ctx, const char *name,
		       pid_t server_pid, unsigned int flags)
{
  gpg_error_t err;
  assuan_fd_t fd;
  struct sockaddr_un srvr_addr;
  size_t len;
  const char *s;

  TRACE2 (ctx, ASSUAN_LOG_CTX, "assuan_socket_connect", ctx,
	  "name=%s, flags=0x%x", name ? name : "(null)", flags);

  if (!ctx || !name)
    return _assuan_error (ctx, GPG_ERR_ASS_INV_VALUE);

  /* We require that the name starts with a slash, so that we
     eventually can reuse this function for other socket types.  To
     make things easier we allow an optional driver prefix.  */
  s = name;
  if (*s && s[1] == ':')
    s += 2;
  if (*s != DIRSEP_C && *s != '/')
    return _assuan_error (ctx, GPG_ERR_ASS_INV_VALUE);

  if (strlen (name)+1 >= sizeof srvr_addr.sun_path)
    return _assuan_error (ctx, GPG_ERR_ASS_INV_VALUE);

  fd = _assuan_sock_new (ctx, PF_LOCAL, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD)
    {
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "assuan_socket_connect_ext", ctx,
	      "can't create socket: %s", strerror (errno));
      /* FIXME: Cleanup  */
      return _assuan_error (ctx, GPG_ERR_ASS_GENERAL);
    }

  memset (&srvr_addr, 0, sizeof srvr_addr);
  srvr_addr.sun_family = AF_LOCAL;
  strncpy (srvr_addr.sun_path, name, sizeof (srvr_addr.sun_path) - 1);
  srvr_addr.sun_path[sizeof (srvr_addr.sun_path) - 1] = 0;
  len = SUN_LEN (&srvr_addr);

  if (_assuan_sock_connect (ctx, fd, (struct sockaddr *) &srvr_addr, len) == -1)
    {
      TRACE2 (ctx, ASSUAN_LOG_SYSIO, "assuan_socket_connect_ext", ctx,
	      "can't connect to `%s': %s\n", name, strerror (errno));
      /* FIXME: Cleanup */
      _assuan_close (ctx, fd);
      return _assuan_error (ctx, GPG_ERR_ASS_CONNECT_FAILED);
    }
 
  ctx->engine.release = _assuan_client_release;
  ctx->engine.readfnc = _assuan_simple_read;
  ctx->engine.writefnc = _assuan_simple_write;
  ctx->engine.sendfd = NULL;
  ctx->engine.receivefd = NULL;
  ctx->finish_handler = _assuan_client_finish;
  ctx->inbound.fd = fd;
  ctx->outbound.fd = fd;
  ctx->max_accepts = -1;

  if (flags & ASSUAN_SOCKET_CONNECT_FDPASSING)
    _assuan_init_uds_io (ctx);

  /* initial handshake */
  {
    assuan_response_t response;
    int off;

    err = _assuan_read_from_server (ctx, &response, &off);
    if (err)
      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "assuan_socket_connect_ext", ctx,
	      "can't connect to server: %s\n", gpg_strerror (err));
    else if (response != ASSUAN_RESPONSE_OK)
      {
	char *sname = _assuan_encode_c_string (ctx, ctx->inbound.line);
	if (sname)
	  {
	    TRACE1 (ctx, ASSUAN_LOG_SYSIO, "assuan_socket_connect_ext", ctx,
		    "can't connect to server: %s", sname);
	    _assuan_free (ctx, sname);
	  }
	err = _assuan_error (ctx, GPG_ERR_ASS_CONNECT_FAILED);
      }
  }
  
  if (err)
    _assuan_reset (ctx);

  return err;
}
