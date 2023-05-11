/* pipeconnect.c  - Check the assuan_pipe_connect call.
   Copyright (C) 2006, 2009, 2010 Free Software Foundation, Inc.

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

/* 
   This tests creates a program which starts an assuan server and runs
   some simple tests on it.  The other program is actually the same
   program but called with the option --server.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_W32_SYSTEM
#include <fcntl.h>
#endif
#include "../src/assuan.h"
#include "common.h"

static assuan_fd_t my_stdin = ASSUAN_INVALID_FD;
static assuan_fd_t my_stdout = ASSUAN_INVALID_FD;
static assuan_fd_t my_stderr = ASSUAN_INVALID_FD;


static gpg_error_t
cmd_echo (assuan_context_t ctx, char *line)
{
  log_info ("got ECHO command (%s)\n", line);

  assuan_send_data (ctx, line, strlen (line));

  return 0;
}


static gpg_error_t
cmd_cat (assuan_context_t ctx, char *line)
{
#ifdef HAVE_W32_SYSTEM
  assuan_fd_t assuan_fdin, assuan_fdout;
#endif
  int fd, fdout;
  int c;
  FILE *fp, *fpout;
  int nbytes;

  log_info ("got CAT command (%s)\n", line);

#ifdef HAVE_W32_SYSTEM
  assuan_fdin = assuan_get_input_fd (ctx);
  if (assuan_fdin == ASSUAN_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
  assuan_fdout = assuan_get_output_fd (ctx);
  if (assuan_fdout == ASSUAN_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_OUTPUT);
  fd = _open_osfhandle ((intptr_t)assuan_fdin, _O_RDONLY);
  if (fd < 0)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
  fdout = _open_osfhandle ((intptr_t)assuan_fdout, _O_WRONLY);
  if (fdout < 0)
    return gpg_error (GPG_ERR_ASS_NO_OUTPUT);
#else
  fd = assuan_get_input_fd (ctx);
  if (fd == ASSUAN_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
  fdout = assuan_get_output_fd (ctx);
  if (fdout == ASSUAN_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_OUTPUT);
#endif
  fp = fdopen (fd, "r");
  if (!fp)
    {
      log_error ("fdopen failed on input fd: %s\n", strerror (errno));
      return gpg_error (GPG_ERR_ASS_GENERAL);
    }

  fpout = fdopen (fdout, "w");
  if (!fpout)
    {
      log_error ("fdopen failed on output fd: %s\n", strerror (errno));
      fclose (fp);
      return gpg_error (GPG_ERR_ASS_GENERAL);
    }

  nbytes = 0;
  while ( (c=getc (fp)) != -1)
    {
      putc (c, fpout); 
      nbytes++;
    }
  log_info ("done printing %d bytes to output fd\n", nbytes);

  /* Fixme:  This also closes the original fd. */
  fclose (fp);
  fclose (fpout);
  return 0;
}


static gpg_error_t
server_register_commands (assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    gpg_error_t (*handler) (assuan_context_t, char *line);
  } table[] =
      {
	{ "ECHO", cmd_echo },
	{ "CAT", cmd_cat },
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
run_server (int enable_debug)
{
  int rc;
  assuan_context_t ctx;
  assuan_fd_t filedes[2];

  filedes[0] = my_stdin;
  filedes[1] = my_stdout;

  rc = assuan_new (&ctx);
  if (rc)
    log_fatal ("assuan_new failed: %s\n", gpg_strerror (rc));

  rc = assuan_init_pipe_server (ctx, filedes);
  if (rc)
    log_fatal ("assuan_init_pipe_server failed: %s\n", 
               gpg_strerror (rc));

  rc = server_register_commands (ctx);
  if (rc)
    log_fatal ("register_commands failed: %s\n", gpg_strerror(rc));

  if (enable_debug)
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







static gpg_error_t
data_cb (void *opaque, const void *buffer, size_t length)
{
  (void)opaque;

  if (buffer)
    printf ("Received data `%.*s'\n", (int)length, (char*)buffer);
  return 0;
}
  

static void
run_client (const char *servername)
{
  gpg_error_t err;
  assuan_context_t ctx;
  assuan_fd_t no_close_fds[2];
  const char *arglist[5];

  no_close_fds[0] = assuan_fd_from_posix_fd (fileno (stderr));
  no_close_fds[1] = ASSUAN_INVALID_FD;

  arglist[0] = servername;
  arglist[1] = "--server";
  arglist[2] = debug? "--debug" : verbose? "--verbose":NULL;
  arglist[3] = NULL;

  err = assuan_new (&ctx);
  if (err)
    log_fatal ("assuan_new failed: %s\n", gpg_strerror (err));

  err = assuan_pipe_connect (ctx, servername, arglist, no_close_fds,
                             NULL, NULL, 0);
  if (err)
    {
      log_error ("assuan_pipe_connect failed: %s\n",
                 gpg_strerror (err));
      assuan_release (ctx);
      return;
    }
      
  log_info ("server started; pid is %ld\n",
            (long)assuan_get_pid (ctx));
  
  err = assuan_transact (ctx, "ECHO Your lucky number is 3552664958674928.  "
                         "Watch for it everywhere.",
                         data_cb, NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      log_error ("sending ECHO failed: %s\n", gpg_strerror (err));
      return;
    }

  err = assuan_transact (ctx, "BYE", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      log_error ("sending BYE failed: %s\n", gpg_strerror (err));
      return;
    }

  assuan_release (ctx);
  return;
}


static void
parse_std_file_handles (int *argcp, char ***argvp)
{
  (void)argcp;
  (void)argvp;
  my_stdin = assuan_fd_from_posix_fd (0);
  my_stdout = assuan_fd_from_posix_fd (1);
  my_stderr = assuan_fd_from_posix_fd (2);
}


/* 
     M A I N
 */
int 
main (int argc, char **argv)
{
  gpg_error_t err;
  const char *myname = "no-pgm";
  int last_argc = -1;
  int server = 0;
  int silent_client = 0;
  int silent_server = 0;

  parse_std_file_handles (&argc, &argv);
  if (argc)
    {
      myname = *argv;
      log_set_prefix (*argv);
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          printf ("usage: %s [options]\n"
                  "\n"
                  "Options:\n"
                  "  --verbose      Show what is going on\n"
                  "  --server       Run in server mode\n",
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
      else if (!strcmp (*argv, "--server"))
        {
          server = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--silent-server"))
        {
          silent_server = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--silent-client"))
        {
          silent_client = 1;
          argc--; argv++;
        }
      else
        log_fatal ("invalid option `%s' (try --help)\n", *argv);
    }

  log_set_prefix (xstrconcat (log_get_prefix (), 
                              server? ".server":".client", NULL));
  assuan_set_assuan_log_prefix (log_get_prefix ());

  err = assuan_sock_init ();
  if (err)
    log_fatal ("socket init failed: %s\n", gpg_strerror (err));

  if (server)
    {
      log_info ("server started\n");
      if (debug && !silent_server)
        assuan_set_assuan_log_stream (stderr);
      run_server (debug && !silent_server);
      log_info ("server finished\n");
    }
  else
    {
      log_info ("client started\n");
      if (debug && !silent_client)
        assuan_set_assuan_log_stream (stderr);
      run_client (myname);
      log_info ("client finished\n");
    }

  return errorcount ? 1 : 0;
}

