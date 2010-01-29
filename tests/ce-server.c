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

#ifdef HAVE_W32CE_SYSTEM
#ifndef FILE_ATTRIBUTE_ROMSTATICREF
#define FILE_ATTRIBUTE_ROMSTATICREF FILE_ATTRIBUTE_OFFLINE
#endif
#endif

#include "../src/assuan.h"

#include "common.h"

/* The port we are using by default. */
static short server_port = 15898;

/* Flag set to indicate a shutdown.  */
static int shutdown_pending;

/* The local state of a connection.  */
struct state_s
{
  char *cwd;  /* The current working directory - access using get_cwd().  */
};
typedef struct state_s *state_t;



static void 
release_state (state_t state)
{
  if (!state)
    return;
  xfree (state->cwd);
  xfree (state);
}


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


#ifdef HAVE_W32CE_SYSTEM
static char *
wchar_to_utf8 (const wchar_t *string)
{
  int n;
  size_t length = wcslen (string);
  char *result;

  n = WideCharToMultiByte (CP_UTF8, 0, string, length, NULL, 0, NULL, NULL);
  if (n < 0 || (n+1) <= 0)
    log_fatal ("WideCharToMultiByte failed\n");

  result = xmalloc (n+1);
  n = WideCharToMultiByte (CP_ACP, 0, string, length, result, n, NULL, NULL);
  if (n < 0)
    log_fatal ("WideCharToMultiByte failed\n");
  
  result[n] = 0;
  return result;
}

static wchar_t *
utf8_to_wchar (const char *string)
{
  int n;
  size_t length = strlen (string);
  wchar_t *result;
  size_t nbytes;

  n = MultiByteToWideChar (CP_UTF8, 0, string, length, NULL, 0);
  if (n < 0 || (n+1) <= 0)
    log_fatal ("MultiByteToWideChar failed\n");

  nbytes = (size_t)(n+1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n+1)) 
    log_fatal ("utf8_to_wchar: integer overflow\n");
  result = xmalloc (nbytes);
  n = MultiByteToWideChar (CP_UTF8, 0, string, length, result, n);
  if (n < 0)
    log_fatal ("MultiByteToWideChar failed\n");
  result[n] = 0;
  
  return result;
}
#endif /*HAVE_W32CE_SYSTEM*/

#ifndef HAVE_W32CE_SYSTEM
static char *
gnu_getcwd (void)
{
  size_t size = 100;
  
  while (1)
    {
      char *buffer = xmalloc (size);
      if (getcwd (buffer, size) == buffer)
        return buffer;
      xfree (buffer);
      if (errno != ERANGE)
        return 0;
      size *= 2;
    }
}
#endif /*!HAVE_W32CE_SYSTEM*/


/* Return the current working directory.  The returned string is valid
   as long as STATE->cwd is not changed.  */
static const char *
get_cwd (state_t state)
{
  if (!state->cwd)
    {
      /* No working directory yet.  On WindowsCE make it the module
         directory of this process.  */
      char *p;
#ifdef HAVE_W32CE_SYSTEM
      wchar_t buf[MAX_PATH+1];
      size_t n;

      n = GetModuleFileName (NULL, buf, MAX_PATH);
      if (!n)
        state->cwd = xstrdup ("/");
      else
        {
          buf[n] = 0;
          state->cwd = wchar_to_utf8 (buf);
          p = strrchr (state->cwd, '\\');
          if (p)
            *p = 0;
        }
#else
      state->cwd = gnu_getcwd ();
#endif
#ifdef HAVE_W32_SYSTEM
      for (p=state->cwd; *p; p++)
        if (*p == '\\')
          *p = '/';
#endif /*HAVE_W32_SYSTEM*/
    }

  return state->cwd;
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


static const char hlp_pwd[] = 
  "PWD\n"
  "\n"
  "Print the curent working directory of this session.\n";
static gpg_error_t
cmd_pwd (assuan_context_t ctx, char *line)
{
  state_t state = assuan_get_pointer (ctx);
  gpg_error_t err;
  const char *string;
  
  string = get_cwd (state);
  err = assuan_send_data (ctx, string, strlen (string));

  return leave_cmd (ctx, err);
}


static const char hlp_cd[] = 
  "CD [dir]\n"
  "\n"
  "Change the curretn directory of the session.\n";
static gpg_error_t
cmd_cd (assuan_context_t ctx, char *line)
{
  state_t state = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  char *newdir, *p;

  for (p=line; *p; p++)
    if (*p == '\\')
      *p = '/';

  if (!*line)
    {
      xfree (state->cwd);
      state->cwd = NULL;
      get_cwd (state);
    }
  else
    {
      if (*line == '/')
        newdir = xstrdup (line);
      else
        newdir = xstrconcat (get_cwd (state), "/", line, NULL);
      
      while (strlen(newdir) > 1 && line[strlen(newdir)-1] == '/')
        line[strlen(newdir)-1] = 0;
      xfree (state->cwd);
      state->cwd = newdir;
    }

  return leave_cmd (ctx, err);
}





#ifdef HAVE_W32CE_SYSTEM
static const char hlp_ls[] = 
  "LS [<pattern>]\n"
  "\n"
  "List the files described by PATTERN.\n";
static gpg_error_t
cmd_ls (assuan_context_t ctx, char *line)
{
  state_t state = assuan_get_pointer (ctx);
  gpg_error_t err;
  WIN32_FIND_DATA fi;
  char buf[500];
  HANDLE hd;
  char *p, *fname;
  wchar_t *wfname;

  if (!*line)
    fname = xstrconcat (get_cwd (state), "/*", NULL);
  else if (*line == '/' || *line == '\\')
    fname = xstrdup (line);
  else
    fname = xstrconcat (get_cwd (state), "/", line, NULL);
  for (p=fname; *p; p++)
    if (*p == '/')
      *p = '\\';
  assuan_write_status (ctx, "PATTERN", fname);
  wfname = utf8_to_wchar (fname);
  xfree (fname);
  hd = FindFirstFile (wfname, &fi);
  free (wfname);
  if (hd == INVALID_HANDLE_VALUE)
    {
      log_info ("FindFirstFile returned %d\n", GetLastError ());
      err = gpg_error_from_syserror ();  /* Works for W32CE.  */
      goto leave;
    }

  do
    {
      DWORD attr = fi.dwFileAttributes;

      fname = wchar_to_utf8 (fi.cFileName);
      snprintf (buf, sizeof buf, 
                "%c%c%c%c%c%c%c%c%c%c%c%c%c %7lu%c %s\n",
                (attr & FILE_ATTRIBUTE_DIRECTORY)
                ? ((attr & FILE_ATTRIBUTE_DEVICE)? 'c':'d'):'-',
                (attr & FILE_ATTRIBUTE_READONLY)? 'r':'-',
                (attr & FILE_ATTRIBUTE_HIDDEN)? 'h':'-',
                (attr & FILE_ATTRIBUTE_SYSTEM)? 's':'-',
                (attr & FILE_ATTRIBUTE_ARCHIVE)? 'a':'-',
                (attr & FILE_ATTRIBUTE_COMPRESSED)? 'c':'-',
                (attr & FILE_ATTRIBUTE_ENCRYPTED)? 'e':'-',
                (attr & FILE_ATTRIBUTE_INROM)? 'R':'-',
                (attr & FILE_ATTRIBUTE_REPARSE_POINT)? 'P':'-',
                (attr & FILE_ATTRIBUTE_ROMMODULE)? 'M':'-',
                (attr & FILE_ATTRIBUTE_ROMSTATICREF)? 'R':'-',
                (attr & FILE_ATTRIBUTE_SPARSE_FILE)? 'S':'-',
                (attr & FILE_ATTRIBUTE_TEMPORARY)? 't':'-',
                (unsigned long)fi.nFileSizeLow,
                fi.nFileSizeHigh? 'X':' ',
                fname);
      free (fname);
      err = assuan_send_data (ctx, buf, strlen (buf));
      if (!err)
        err = assuan_send_data (ctx, NULL, 0);
    }
  while (!err && FindNextFile (hd, &fi));
  if (err)
    ;
  else if (GetLastError () == ERROR_NO_MORE_FILES)
    err = 0;
  else
    {
      log_info ("FindNextFile returned %d\n", GetLastError ());
      err = gpg_error_from_syserror (); 
    }
  FindClose (hd);

 leave:
  return leave_cmd (ctx, err);
}
#endif /*HAVE_W32CE_SYSTEM*/


#ifdef HAVE_W32CE_SYSTEM
static const char hlp_run[] = 
  "RUN <filename> [<args>]\n"
  "\n"
  "Run the program in FILENAME with the arguments ARGS.\n"
  "This creates a new process and waits for it to finish.\n"
  "FIXME: The process' stdin is connected to the file set by the\n"
  "INPUT command; stdout and stderr to the one set by OUTPUT.\n";
static gpg_error_t
cmd_run (assuan_context_t ctx, char *line)
{
  /*  state_t state = assuan_get_pointer (ctx); */
  gpg_error_t err;
  PROCESS_INFORMATION pi = { NULL, 0, 0, 0 };
  char *p;
  wchar_t *pgmname = NULL;
  wchar_t *cmdline = NULL;
  int code;
  DWORD exc;

  p = strchr (line, ' ');
  if (p)
    {
      *p = 0;
      pgmname = utf8_to_wchar (line);
      for (p++; *p && *p == ' '; p++)
        ;
      cmdline = utf8_to_wchar (p);
    }
  else
    pgmname = utf8_to_wchar (line);
  {
    char *tmp1 = wchar_to_utf8 (pgmname);
    char *tmp2 = wchar_to_utf8 (cmdline);
    log_info ("CreateProcess, path=`%s' cmdline=`%s'\n", tmp1, tmp2);
    xfree (tmp2);
    xfree (tmp1);
  }
  if (!CreateProcess (pgmname,     /* Program to start.  */
                      cmdline,     /* Command line arguments.  */
                      NULL,        /* Process security attributes. notsup. */
                      NULL,        /* Thread security attributes.  notsup. */
                      FALSE,       /* Inherit handles.  notsup.  */
                      CREATE_SUSPENDED, /* Creation flags.  */
                      NULL,        /* Environment.  notsup.  */
                      NULL,        /* Use current drive/directory.  notsup. */
                      NULL,        /* Startup information.  notsup. */
                      &pi          /* Returns process information.  */
                      ))
    {
      log_error ("CreateProcess failed: %d", GetLastError ());
      err = gpg_error_from_syserror ();
      goto leave;
    }

  log_info ("CreateProcess ready: hProcess=%p hThread=%p" 
            " dwProcessID=%d dwThreadId=%d\n", 
            pi.hProcess, pi.hThread,
            (int) pi.dwProcessId, (int) pi.dwThreadId);

  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread); 

  code = WaitForSingleObject (pi.hProcess, INFINITE);
  switch (code) 
    {
      case WAIT_FAILED:
        err = gpg_error_from_syserror ();;
        log_error ("waiting for process %d to terminate failed: %d\n",
                   (int)pi.dwProcessId, GetLastError ());
        break;

      case WAIT_OBJECT_0:
        if (!GetExitCodeProcess (pi.hProcess, &exc))
          {
            err = gpg_error_from_syserror ();;
            log_error ("error getting exit code of process %d: %s\n",
                       (int)pi.dwProcessId, GetLastError () );
          }
        else if (exc)
          {
            log_info ("error running process: exit status %d\n", (int)exc);
            err = gpg_error (GPG_ERR_GENERAL);
          }
        else
          {
            err = 0;
          }
        break;
        
      default:
        err = gpg_error_from_syserror ();;
        log_error ("WaitForSingleObject returned unexpected "
                   "code %d for pid %d\n", code, (int)pi.dwProcessId);
        break;
    }
  CloseHandle (pi.hProcess);
  
 leave:
  xfree (cmdline);
  xfree (pgmname);
  return leave_cmd (ctx, err);
}
#endif /*HAVE_W32CE_SYSTEM*/


static const char hlp_shutdown[] = 
  "SHUTDOWN\n"
  "\n"
  "Shutdown the server process after ending this connection\n";
static gpg_error_t
cmd_shutdown (assuan_context_t ctx, char *line)
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
#ifdef HAVE_W32CE_SYSTEM
        { "LS",   cmd_ls, hlp_ls },
        { "RUN",  cmd_run, hlp_run },
#endif
        { "PWD",  cmd_pwd, hlp_pwd },
        { "CD",   cmd_cd,  hlp_cd },
	{ "ECHO", cmd_echo, hlp_echo },
	{ "INPUT", NULL },
	{ "OUTPUT", NULL },
	{ "SHUTDOWN", cmd_shutdown, hlp_shutdown },
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
  state_t state = NULL;

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

  if (debug)
    assuan_set_log_stream (ctx, stderr);

  
  state = xcalloc (1, sizeof state);
  assuan_set_pointer (ctx, state);

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
  release_state (state);
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
  if (debug)
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

