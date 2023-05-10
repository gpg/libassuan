/* fdpassing - Check the file descriptor passing.
   Copyright (C) 2006, 2009 Free Software Foundation, Inc.

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
#include <sys/stat.h>
#if HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <wincrypt.h>
# include <io.h>
#include <fcntl.h>
#else
# include <sys/socket.h>
# include <sys/un.h>
#endif
#include <unistd.h>
#include <errno.h>

#include "../src/assuan.h"
#include "common.h"


/*

       S E R V E R

*/

static gpg_error_t
cmd_echo (assuan_context_t ctx, char *line)
{
  int fd;
  int c;
  FILE *fp;
  int nbytes;
#ifdef HAVE_W32_SYSTEM
  HANDLE file_handle;
#endif

  log_info ("got ECHO command (%s)\n", line);

#if HAVE_W32_SYSTEM
  file_handle = assuan_get_input_fd (ctx);
  if (file_handle == ASSUAN_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
  fd = _open_osfhandle ((intptr_t)file_handle, _O_RDONLY);
  if (fd < 0)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
#else
  fd = (int)assuan_get_input_fd (ctx);
  if (fd == -1)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
#endif
  fp = fdopen (fd, "r");
  if (!fp)
    {
      log_error ("fdopen failed on input fd: %s\n", strerror (errno));
      return gpg_error (GPG_ERR_ASS_GENERAL);
    }
  nbytes = 0;
  while ( (c=getc (fp)) != -1)
    {
      putc (c, stderr);
      nbytes++;
    }
  fflush (stderr);
  log_info ("done printing %d bytes to stderr\n", nbytes);

  fclose (fp);
  return 0;
}

static gpg_error_t
register_commands (assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    gpg_error_t (*handler) (assuan_context_t, char *line);
  } table[] =
      {
	{ "ECHO", cmd_echo },
	{ "INPUT", NULL },
	{ "OUTPUT", NULL },
	{ NULL, NULL }
      };
  int i;
  gpg_error_t rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler, NULL);
      if (rc)
        return rc;
    }
  return 0;
}


static void
server_common (assuan_context_t ctx)
{
  int rc;

  rc = register_commands (ctx);
  if (rc)
    log_fatal ("register_commands failed: %s\n", gpg_strerror(rc));

  assuan_set_log_stream (ctx, stderr);

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc)
        {
          if (rc != -1)
            log_error ("assuan_accept failed: %s\n", gpg_strerror (rc));
          break;
        }

      log_info ("client connected.  Client's pid is %ld\n",
                (long)assuan_get_pid (ctx));

      rc = assuan_process (ctx);
      if (rc)
        log_error ("assuan_process failed: %s\n", gpg_strerror (rc));
    }

  assuan_release (ctx);
}

static void
server_pipe (void)
{
  int rc;
  assuan_context_t ctx;

  log_info ("server started\n");

  rc = assuan_new (&ctx);
  if (rc)
    log_fatal ("assuan_new failed: %s\n", gpg_strerror (rc));

  rc = assuan_init_pipe_server (ctx, NULL);
  if (rc)
    log_fatal ("assuan_init_pipe_server failed: %s\n", gpg_strerror (rc));

  server_common (ctx);
}

static assuan_sock_nonce_t socket_nonce;

static void
server_socket (const char *socketname)
{
  int rc;
  assuan_context_t ctx;
  assuan_fd_t fd;
  struct sockaddr_un unaddr_struct;
  struct sockaddr *addr;
  socklen_t len;

  log_info ("server on socket started\n");

  fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD)
    log_fatal ("assuan_sock_new failed\n");

  addr = (struct sockaddr *)&unaddr_struct;
  rc = assuan_sock_set_sockaddr_un (socketname, addr, NULL);
  if (rc)
    {
      assuan_sock_close (fd);
      log_fatal ("assuan_sock_set_sockaddr_un failed: %s\n", gpg_strerror (rc));
    }

  len = offsetof (struct sockaddr_un, sun_path)
    + strlen (unaddr_struct.sun_path);
  rc = assuan_sock_bind (fd, addr, len);
  if (rc)
    {
      assuan_sock_close (fd);
      log_fatal ("assuan_sock_bind failed: %s\n", gpg_strerror (rc));
    }

  rc = assuan_sock_get_nonce (addr, len, &socket_nonce);
  if (rc)
    {
      assuan_sock_close (fd);
      log_fatal ("assuan_sock_get_nonce failed: %s\n", gpg_strerror (rc));
    }

  rc = listen (HANDLE2SOCKET (fd), 5);
  if (rc < 0)
    {
      assuan_sock_close (fd);
      log_fatal ("listen failed: %s\n",
		 gpg_strerror (gpg_error_from_syserror ()));
    }

  rc = assuan_new (&ctx);
  if (rc)
    log_fatal ("assuan_new failed: %s\n", gpg_strerror (rc));

  rc = assuan_init_socket_server (ctx, fd, ASSUAN_SOCKET_SERVER_FDPASSING);
  if (rc)
    log_fatal ("assuan_init_socket_server failed: %s\n", gpg_strerror (rc));

  assuan_set_sock_nonce (ctx, &socket_nonce);

  server_common (ctx);
}

/*

       C L I E N T

*/


/* Client main.  If true is returned, a disconnect has not been done. */
static int
client (assuan_context_t ctx, const char *fname)
{
  int rc;
  FILE *fp;
  int i;
#if HAVE_W32_SYSTEM
  HANDLE file_handle;
#endif

  log_info ("client started. Servers's pid is %ld\n",
            (long)assuan_get_pid (ctx));

  for (i=0; i < 6; i++)
    {
      fp = fopen (fname, "r");
      if (!fp)
        {
          log_error ("failed to open `%s': %s\n", fname,
                     strerror (errno));
          return -1;
        }

#ifdef HAVE_W32_SYSTEM
      file_handle = (HANDLE)_get_osfhandle (fileno (fp));
      rc = assuan_sendfd (ctx, file_handle);
#else
      rc = assuan_sendfd (ctx, (assuan_fd_t)fileno (fp));
#endif
      if (rc)
        {
          fclose (fp);
          log_error ("assuan_sendfd failed: %s\n", gpg_strerror (rc));
          return -1;
        }
      fclose (fp);

      rc = assuan_transact (ctx, "INPUT FD", NULL, NULL, NULL, NULL,
                            NULL, NULL);
      if (rc)
        {
          log_error ("sending INPUT FD failed: %s\n", gpg_strerror (rc));
          return -1;
        }

      rc = assuan_transact (ctx, "ECHO", NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        {
          log_error ("sending ECHO failed: %s\n", gpg_strerror (rc));
          return -1;
        }
    }

  /* Give us some time to check with lsof that all descriptors are closed. */
/*   sleep (10); */

  assuan_release (ctx);
  return 0;
}




/*

     M A I N

*/
int
main (int argc, char **argv)
{
  const char *program_name = NULL;
  int last_argc = -1;
  assuan_context_t ctx;
  gpg_error_t err;
  int is_server = 0;
  int with_exec = 0;
  const char *socketname = NULL;

  if (argc)
    {
      program_name = *argv;
      log_set_prefix (*argv);
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: ./fdpassing [options]\n"
"\n"
"Options:\n"
"  --verbose      Show what is going on\n"
"  --with-exec    Exec the child.  Default is just a fork on POSIX machine\n"
"  --socketname   Specify the socket path\n"
);
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
      else if (!strcmp (*argv, "--server"))
        {
          is_server = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--with-exec"))
        {
          with_exec = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--socketname"))
        {
          argc--; argv++;
	  if (argc)
	    {
	      socketname = *argv++;
	      argc--;
	    }
        }
    }

  if (socketname)
    assuan_sock_init ();
  else
    {
#ifdef HAVE_W32_SYSTEM
      with_exec = 1;
#else
      ;
#endif
    }

  assuan_set_assuan_log_prefix (log_prefix);

  if (is_server)
    {
      if (socketname)
        server_socket (socketname);
      else
        server_pipe ();
      log_info ("server finished\n");
    }
  else
    {
      char *fname;

      err = assuan_new (&ctx);
      if (err)
	log_fatal ("assuan_new failed: %s\n", gpg_strerror (err));

      if (socketname)
        {
          err = assuan_socket_connect (ctx, socketname, 0,
                                       ASSUAN_SOCKET_CONNECT_FDPASSING);
          if (err)
            {
              log_error ("assuan_socket_connect failed: %s\n",
                         gpg_strerror (err));
              assuan_release (ctx);
              errorcount++;
              goto done;
            }
        }
      else
        {
          assuan_fd_t no_close_fds[2];
          const char *arglist[10];
          const char *loc;

          no_close_fds[0] = verbose?
            assuan_fd_from_posix_fd (2): (assuan_fd_t)-1;
          no_close_fds[1] = (assuan_fd_t)-1;
          if (with_exec)
            {
              arglist[0] = program_name;
              arglist[1] = "--server";
              arglist[2] = verbose? "--verbose":NULL;
              arglist[3] = NULL;
            }

          err = assuan_pipe_connect (ctx, with_exec? program_name : NULL,
                                     with_exec ? arglist : &loc,
                                     no_close_fds, NULL, NULL, 1);
          if (err)
            {
              log_error ("assuan_pipe_connect failed: %s\n",
                         gpg_strerror (err));
              assuan_release (ctx);
              errorcount++;
            }
          else if (!with_exec && loc[0] == 's')
            {
              server_pipe ();
              assuan_release (ctx);
              log_info ("server finished\n");
              goto done;
            }
        }

      fname = prepend_srcdir ("motd");
      if (client (ctx, fname))
        {
          log_info ("waiting for server to terminate...\n");
          assuan_release (ctx);
        }
      log_info ("client finished\n");
      xfree (fname);
    }

 done:
  return errorcount ? 1 : 0;
}
