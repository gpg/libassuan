/* ce-server.c - An Assuan testbed for W32CE; server code
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif
#include <errno.h>


#include "../src/assuan.h"

#include "common.h"

/* The port we are using by default. */
static short server_port = 15898;

/* Flag set to indicate a shutdown.  */
static int shutdown_pending;



/* Helper to print a message while leaving a command.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";
      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name, gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}





static const char hlp_echo[] = 
  "ECHO <line>\n"
  "\n"
  "Print LINE as data lines.\n";
static gpg_error_t
cmd_echo (assuan_context_t ctx, char *line)
{
  gpg_error_t err;

  err = assuan_send_data (ctx, line, strlen (line));

  return leave_cmd (ctx, err);
}



static const char hlp_killserver[] = 
  "KILLSERVER\n"
  "\n"
  "Kill the server process.\n";
static gpg_error_t
cmd_killserver (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  shutdown_pending = 1;
  return 0;
}


static gpg_error_t
register_commands (assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    gpg_error_t (*handler) (assuan_context_t, char *line);
    const char * const help;
  } table[] =
      {
	{ "ECHO", cmd_echo, hlp_echo },
	{ "INPUT", NULL },
	{ "OUTPUT", NULL },
	{ "KILLSERVER", cmd_killserver, hlp_killserver },
	{ NULL, NULL }
      };
  int i;
  gpg_error_t rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, 
                                    table[i].handler, table[i].help);
      if (rc)
        return rc;
    }
  return 0;
}


/* Startup the server.  */
static void
server (void)
{
  gpg_error_t err;
  assuan_fd_t server_fd;
  assuan_sock_nonce_t server_nonce;
  int one = 1;
  struct sockaddr_in name;
  assuan_context_t ctx;

  err = assuan_new (&ctx);
  if (err)
    log_fatal ("assuan_new failed: %s\n", gpg_strerror (err));

  server_fd = assuan_sock_new (PF_INET, SOCK_STREAM, 0);
  if (server_fd == ASSUAN_INVALID_FD)
    log_fatal ("socket() failed: %s", strerror (errno));

  if (setsockopt (HANDLE2SOCKET (server_fd), 
                  SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof one))
    log_error ("setsockopt(SO_REUSEADDR) failed: %s", strerror (errno));

  name.sin_family = AF_INET;
  name.sin_port = htons (server_port);
  name.sin_addr.s_addr = htonl (INADDR_ANY);
  if (assuan_sock_bind (server_fd, (struct sockaddr *) &name, sizeof name))
    log_fatal ("bind() failed: %s", strerror (errno));
  if (assuan_sock_get_nonce ((struct sockaddr*)&name, sizeof name, 
                             &server_nonce))
    log_fatal ("assuan_sock_get_nonce failed: %s", strerror (errno));

  /* Register the nonce with the context so that assuan_accept knows
     about it.  We can't do that directly in assuan_sock_bind because
     we want these socket wrappers to be context neutral and drop in
     replacement for the standard socket functions.  */
  assuan_set_sock_nonce (ctx, &server_nonce);

  if (listen (HANDLE2SOCKET (server_fd), 5))
    log_fatal ("listen() failed: %s\n", strerror (errno));

  log_info ("server listening on port %hd\n", server_port);

  err = assuan_init_socket_server (ctx, server_fd, 0);
  if (err)
    log_fatal ("assuan_init_socket_server failed: %s\n", gpg_strerror (err));

  err = register_commands (ctx);
  if (err)
    log_fatal ("register_commands failed: %s\n", gpg_strerror(err));

  assuan_set_log_stream (ctx, stderr);

  while (!shutdown_pending)
    {
      err = assuan_accept (ctx);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF || err == -1)
            log_error ("assuan_accept failed: %s\n", gpg_strerror (err));
          break;
        }
      
      log_info ("client connected.  Client's pid is %ld\n",
                (long)assuan_get_pid (ctx));

      err = assuan_process (ctx);
      if (err)
        log_error ("assuan_process failed: %s\n", gpg_strerror (err));
    }
  
  assuan_sock_close (server_fd);
  assuan_release (ctx);
}





/* 
 
     M A I N

*/
int 
main (int argc, char **argv)
{
  gpg_error_t err;
  int last_argc = -1;

  if (argc)
    {
      log_set_prefix (*argv);
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          printf (
                  "usage: %s [options]\n"
                  "\n"
                  "Options:\n"
                  "  --verbose      Show what is going on\n",
                  log_get_prefix ());
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
    }

  assuan_set_assuan_log_prefix (log_prefix);
  assuan_set_assuan_log_stream (stderr);

  err = assuan_sock_init ();
  if (err)
    log_fatal ("assuan_sock_init failed: %s\n", gpg_strerror (err));

  log_info ("server starting...\n");
  server ();
  log_info ("server finished\n");

  assuan_sock_deinit ();

  return errorcount ? 1 : 0;
}

