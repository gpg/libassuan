/* assuan-socket-server.c - Assuan socket based server
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>

#include "assuan-defs.h"

/* Initialize a server.  RENDEZVOUSFD is a bidirectional file
   descriptor (normally returned via socketpair) that the domain
   server can use to rendezvous with the client.  CLIENT is the
   client's pid.  */
assuan_error_t
assuan_init_domain_server (ASSUAN_CONTEXT *r_ctx,
			   int rendezvousfd,
			   pid_t client)
{
  assuan_error_t err;

  err = _assuan_domain_init (r_ctx, rendezvousfd, client);
  if (err)
    return err;

  (*r_ctx)->is_server = 1;
  /* A domain server can only be used once.  */
  (*r_ctx)->pipe_mode = 1;

  return 0;
}
