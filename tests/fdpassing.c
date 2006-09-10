/* fdpassing - Check the fiel descriptor passing.
 * Copyright (C) 2006 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>  /* Used by main driver. */

#include "../src/assuan.h"
#include "common.h"


/*

       S E R V E R

*/

static int
cmd_echo (assuan_context_t ctx, char *line)
{
  int fd;
  int c;
  FILE *fp;

  log_info ("got ECHO command (%s)\n", line);

  fd = assuan_get_input_fd (ctx);
  if (fd == -1)
    return ASSUAN_No_Input;
  fp = fdopen (dup (fd), "r");
  if (!fp)
    {
      log_error ("fdopen failed on input fd: %s\n", strerror (errno));
      return ASSUAN_General_Error;
    }
  log_info ("printing input to stdout:\n");
  while ( (c=getc (fp)) != -1)
    putc (c, stdout); 
  fflush (stdout); 
  log_info ("done printing input to stdout\n");

  fclose (fp);
  return 0;
}

static assuan_error_t
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    int (*handler)(assuan_context_t, char *line);
  } table[] = {
    { "ECHO",       cmd_echo },
    { "INPUT",      NULL },
    { "OUTPUT",     NULL },
    { NULL }
  };
  int i;
  assuan_error_t rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler);
      if (rc)
        return rc;
    }
  return 0;
}


static void
server (int fd)
{
  int rc;
  assuan_context_t ctx;

  log_info ("server started on fd %d\n", fd);

  rc = assuan_init_domain_server (&ctx, fd, (pid_t)(-1));
  if (rc)
    log_fatal ("assuan_init_domain_server failed: %s\n", assuan_strerror (rc));

  rc = register_commands (ctx);
  if (rc)
    log_fatal ("register_commands failed: %s\n", assuan_strerror(rc));

  assuan_set_assuan_log_prefix (log_prefix);
  assuan_set_log_stream (ctx, stderr);

  for (;;) 
    {
      rc = assuan_accept (ctx);
      if (rc)
        {
          log_error ("assuan_accept failed: %s\n", assuan_strerror (rc));
          break;
        }

      rc = assuan_process (ctx);
      if (rc)
        log_error ("assuan_process failed: %s\n", assuan_strerror (rc));
    }
  
  assuan_deinit_server (ctx);
}




/*

       C L I E N T

*/


/* Client main.  If true is returned, a disconnect has not been done. */
static int
client (int fd)
{
  int rc;
  assuan_context_t ctx;
  FILE *fp;
  int i;

  log_info ("client started on fd %d\n", fd);

  rc = assuan_domain_connect (&ctx, fd, (pid_t)(-1));
  if (rc)
    {
      log_error ("assuan_domain_connect failed: %s\n", assuan_strerror (rc));
      return -1;
    }

  fp = fopen ("/etc/motd", "r");
  if (!fp)
    {
      log_error ("failed to open `%s': %s\n", "/etc/motd", strerror (errno));
      return -1;
    }

  rc = assuan_sendfd (ctx, fileno (fp));
  if (rc)
    {
      log_error ("assuan_sendfd failed: %s\n", assuan_strerror (rc));
      return -1;
    }
  
  rc = assuan_transact (ctx, "INPUT FD", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_error ("sending INPUT FD failed: %s\n", assuan_strerror (rc));
      return -1;
    }


  rc = assuan_transact (ctx, "ECHO", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_error ("sending ECHO failed: %s\n", assuan_strerror (rc));
      return -1;
    }

  sleep (100);

  assuan_disconnect (ctx);
  return 0;
}




/* 
 
     M A I N

*/
int 
main (int argc, char **argv)
{
  int last_argc = -1;
  const char *srcdir = getenv ("srcdir");
  int fds[2];
  pid_t pid;
  
  if (!srcdir)
    srcdir = ".";

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
          puts (
"usage: ./fdpassing [options]\n"
"\n"
"       Options are --verbose and --debug");
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

  /* Create a socketpair.  */
  if ( socketpair (AF_LOCAL, SOCK_STREAM, 0, fds) )
    log_fatal ("socketpair failed: %s\n", strerror (errno));

  /* Fork and run server and client.  */
  pid = fork ();
  if (pid == (pid_t)(-1))
    log_fatal ("fork failed: %s\n", strerror (errno));
  if (!pid)
    {
      server (fds[0]); /* The child is our server. */
      log_info ("server finished\n");
    }
  else
    {
      if (client (fds[1])) /* The parent is the client.  */
        {
          log_info ("waiting for server to terminate...\n");
          waitpid (pid, NULL, 0); 
        }
      log_info ("client finished\n");
    }

  return errorcount? 1:0;
}

