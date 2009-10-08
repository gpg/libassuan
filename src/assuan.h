/* assuan.h - Definitions for the Assuan IPC library
   Copyright (C) 2001-2003, 2005, 2007-2009 Free Software Foundation, Inc.

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

#ifndef ASSUAN_H
#define ASSUAN_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#ifndef _ASSUAN_NO_SOCKET_WRAPPER
#ifdef _WIN32
#include <ws2tcpip.h> 
#else
#include <sys/socket.h>
#endif
#endif /*!_ASSUAN_NO_SOCKET_WRAPPER*/

#include <gpg-error.h>

/* Compile time configuration:

   #define _ASSUAN_NO_SOCKET_WRAPPER

       Do not include the definitions for the socket wrapper feature.

   The follwing macros are used internally in the implementation of
   libassuan:

     #define _ASSUAN_NO_PTH 

       This avoids inclusion of special GNU Pth hacks.

     #define _ASSUAN_NO_FIXED_SIGNALS 

       This disables changing of certain signal handler; i.e. SIGPIPE.

     #define _ASSUAN_USE_DOUBLE_FORK

       Use a double fork approach when connecting to a server through
       a pipe.
 */


#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif


/* Check for compiler features.  */
#if __GNUC__
#define _ASSUAN_GCC_VERSION (__GNUC__ * 10000 \
                            + __GNUC_MINOR__ * 100 \
                            + __GNUC_PATCHLEVEL__)

#if _ASSUAN_GCC_VERSION > 30100
#define _ASSUAN_DEPRECATED  __attribute__ ((__deprecated__))
#endif
#endif
#ifndef _ASSUAN_DEPRECATED
#define _ASSUAN_DEPRECATED
#endif


#define ASSUAN_LINELENGTH 1002 /* 1000 + [CR,]LF */

struct assuan_context_s;
typedef struct assuan_context_s *assuan_context_t;

/* Because we use system handles and not libc low level file
   descriptors on W32, we need to declare them as HANDLE (which
   actually is a plain pointer).  This is required to eventually
   support 64 bit Windows systems.  */
#ifdef _WIN32
typedef void *assuan_fd_t;
#define ASSUAN_INVALID_FD ((void*)(-1))
#else
typedef int assuan_fd_t;
#define ASSUAN_INVALID_FD (-1)
#endif


/* Assuan features an emulation of Unix domain sockets based on a
   local TCP connections.  To implement access permissions based on
   file permissions a nonce is used which is expected by th server as
   the first bytes received.  This structure is used by the server to
   save the nonce created initially by bind.  On POSIX systems this is
   a dummy operation. */  
struct assuan_sock_nonce_s
{
  size_t length;
#ifdef _WIN32
  char nonce[16];
#endif
};
typedef struct assuan_sock_nonce_s assuan_sock_nonce_t;

/* Define the Unix domain socket structure for Windows.  */
#if defined(_WIN32) && !defined(_ASSUAN_NO_SOCKET_WRAPPER)
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif
#define EADDRINUSE WSAEADDRINUSE
struct sockaddr_un
{
  short          sun_family;
  unsigned short sun_port;
  struct         in_addr sun_addr;
  char           sun_path[108-2-4]; 
};
#endif


/* Global interface.  */

struct assuan_malloc_hooks
{
  void *(*malloc) (size_t cnt);
  void *(*realloc) (void *ptr, size_t cnt);
  void (*free) (void *ptr);
};
typedef struct assuan_malloc_hooks *assuan_malloc_hooks_t;

/* Categories for log messages.  */
#define ASSUAN_LOG_INIT 1
#define ASSUAN_LOG_CTX 2
#define ASSUAN_LOG_ENGINE 3
#define ASSUAN_LOG_DATA 4
#define ASSUAN_LOG_SYSIO 5

/* If MSG is NULL, return true/false depending on if this category is
   logged.  This is used to probe before expensive log message
   generation (buffer dumps).  */
typedef int (*assuan_log_cb_t) (assuan_context_t ctx, void *hook,
				unsigned int cat, const char *msg);

/* Set the default gpg error source.  */
void assuan_set_gpg_err_source (gpg_err_source_t errsource);

/* Get the default gpg error source.  */
gpg_err_source_t assuan_get_gpg_err_source (void);


/* Set the default malloc hooks.  */
void assuan_set_malloc_hooks (assuan_malloc_hooks_t malloc_hooks);

/* Get the default malloc hooks.  */
assuan_malloc_hooks_t assuan_get_malloc_hooks (void);


/* Set the default log callback handler.  */
void assuan_set_log_cb (assuan_log_cb_t log_cb, void *log_cb_data);

/* Get the default log callback handler.  */
void assuan_get_log_cb (assuan_log_cb_t *log_cb, void **log_cb_data);


/* Create a new Assuan context.  The initial parameters are all needed
   in the creation of the context.  */
gpg_error_t assuan_new_ext (assuan_context_t *ctx, gpg_err_source_t errsource,
			    assuan_malloc_hooks_t malloc_hooks,
			    assuan_log_cb_t log_cb, void *log_cb_data);

/* Create a new context with default arguments.  */
gpg_error_t assuan_new (assuan_context_t *ctx);

/* Release all resources associated with the given context.  */
void assuan_release (assuan_context_t ctx);


/* Set user-data in a context.  */
void assuan_set_pointer (assuan_context_t ctx, void *pointer);

/* Get user-data in a context.  */
void *assuan_get_pointer (assuan_context_t ctx);


/* Definitions of flags for assuan_set_flag().  */
typedef unsigned int assuan_flag_t;

/* When using a pipe server, by default Assuan will wait for the
   forked process to die in assuan_release.  In certain cases this
   is not desirable.  By setting this flag, the waitpid will be
   skipped and the caller is responsible to cleanup a forked
   process. */
#define ASSUAN_NO_WAITPID 1
/* This flag indicates whether Assuan logging is in confidential mode.
   You can use assuan_{begin,end}_condidential to change the mode.  */
#define ASSUAN_CONFIDENTIAL 2

/* For context CTX, set the flag FLAG to VALUE.  Values for flags
   are usually 1 or 0 but certain flags might allow for other values;
   see the description of the type assuan_flag_t for details.  */
void assuan_set_flag (assuan_context_t ctx, assuan_flag_t flag, int value);

/* Return the VALUE of FLAG in context CTX.  */
int assuan_get_flag (assuan_context_t ctx, assuan_flag_t flag);


/* Same as assuan_set_flag (ctx, ASSUAN_CONFIDENTIAL, 1).  */
void assuan_begin_confidential (assuan_context_t ctx);

/* Same as assuan_set_flag (ctx, ASSUAN_CONFIDENTIAL, 0).  */
void assuan_end_confidential (assuan_context_t ctx);


/* Direction values for assuan_set_io_monitor.  */
#define ASSUAN_IO_FROM_PEER 0
#define ASSUAN_IO_TO_PEER 1

/* Return flags of I/O monitor.  */
#define ASSUAN_IO_MONITOR_NOLOG 1
#define ASSUAN_IO_MONITOR_IGNORE 2

/* The IO monitor gets to see all I/O on the context, and can return
   ASSUAN_IO_MONITOR_* bits to control actions on it.  */
typedef unsigned int (*assuan_io_monitor_t) (assuan_context_t ctx, void *hook,
					     int inout, const char *line,
					     size_t linelen);

/* Set the IO monitor function.  */
void assuan_set_io_monitor (assuan_context_t ctx,
			    assuan_io_monitor_t io_monitor, void *hook_data);


/* Configuration of the default log handler.  */

/* Set the prefix to be used at the start of a line emitted by assuan
   on the log stream.  The default is the empty string.  Note, that
   this function is not thread-safe and should in general be used
   right at startup. */
void assuan_set_assuan_log_prefix (const char *text);

/* Return a prefix to be used at the start of a line emitted by assuan
   on the log stream.  The default implementation returns the empty
   string, i.e. ""  */
const char *assuan_get_assuan_log_prefix (void);

/* Set the per context log stream for the default log handler.  */
void assuan_set_log_stream (assuan_context_t ctx, FILE *fp);


/*-- assuan-handler.c --*/
gpg_error_t assuan_register_command (assuan_context_t ctx,
				     const char *cmd_string,
				     gpg_error_t (*handler)(assuan_context_t, char *));
gpg_error_t assuan_register_post_cmd_notify (assuan_context_t ctx,
					     void (*fnc)(assuan_context_t, gpg_error_t));
gpg_error_t assuan_register_bye_notify (assuan_context_t ctx,
					void (*fnc)(assuan_context_t));
gpg_error_t assuan_register_reset_notify (assuan_context_t ctx,
					  void (*fnc)(assuan_context_t));
gpg_error_t assuan_register_cancel_notify (assuan_context_t ctx,
					   void (*fnc)(assuan_context_t));
gpg_error_t assuan_register_input_notify (assuan_context_t ctx,
					  void (*fnc)(assuan_context_t, const char *));
gpg_error_t assuan_register_output_notify (assuan_context_t ctx,
					   void (*fnc)(assuan_context_t, const char *));

gpg_error_t assuan_register_option_handler (assuan_context_t ctx,
					    gpg_error_t (*fnc)(assuan_context_t,
							       const char*, const char*));

gpg_error_t assuan_process (assuan_context_t ctx);
gpg_error_t assuan_process_next (assuan_context_t ctx);
gpg_error_t assuan_process_done (assuan_context_t ctx, gpg_error_t rc);
int assuan_get_active_fds (assuan_context_t ctx, int what,
                           assuan_fd_t *fdarray, int fdarraysize);


FILE *assuan_get_data_fp (assuan_context_t ctx);
gpg_error_t assuan_set_okay_line (assuan_context_t ctx, const char *line);
gpg_error_t assuan_write_status (assuan_context_t ctx,
                                    const char *keyword, const char *text);

/* Negotiate a file descriptor.  If LINE contains "FD=N", returns N
   assuming a local file descriptor.  If LINE contains "FD" reads a
   file descriptor via CTX and stores it in *RDF (the CTX must be
   capable of passing file descriptors).  Under W32 the returned FD is
   a libc-type one.  */
gpg_error_t assuan_command_parse_fd (assuan_context_t ctx, char *line,
                                        assuan_fd_t *rfd);


/*-- assuan-listen.c --*/
gpg_error_t assuan_set_hello_line (assuan_context_t ctx, const char *line);
gpg_error_t assuan_accept (assuan_context_t ctx);
assuan_fd_t assuan_get_input_fd (assuan_context_t ctx);
assuan_fd_t assuan_get_output_fd (assuan_context_t ctx);
gpg_error_t assuan_close_input_fd (assuan_context_t ctx);
gpg_error_t assuan_close_output_fd (assuan_context_t ctx);


/*-- assuan-pipe-server.c --*/
gpg_error_t assuan_init_pipe_server (assuan_context_t ctx, int filedes[2]);

/*-- assuan-socket-server.c --*/
gpg_error_t assuan_init_socket_server (assuan_context_t ctx,
				       assuan_fd_t listen_fd);
gpg_error_t assuan_init_socket_server_ext (assuan_context_t ctx,
					   assuan_fd_t fd,
					   unsigned int flags);
void assuan_set_sock_nonce (assuan_context_t ctx, assuan_sock_nonce_t *nonce);

/*-- assuan-pipe-connect.c --*/
gpg_error_t assuan_pipe_connect (assuan_context_t ctx,
				 const char *name,
				 const char *argv[],
				 int *fd_child_list);
gpg_error_t assuan_pipe_connect_ext (assuan_context_t ctx,
				     const char *name,
				     const char *argv[],
				     int *fd_child_list,
				     void (*atfork) (void *, int),
				     void *atforkvalue,
				     unsigned int flags);

/*-- assuan-socket-connect.c --*/
gpg_error_t assuan_socket_connect (assuan_context_t ctx, 
				   const char *name,
				   pid_t server_pid);

gpg_error_t assuan_socket_connect_ext (assuan_context_t ctx,
				       const char *name,
				       pid_t server_pid,
				       unsigned int flags);

/*-- assuan-connect.c --*/
pid_t assuan_get_pid (assuan_context_t ctx);
#ifndef _WIN32
gpg_error_t assuan_get_peercred (assuan_context_t ctx,
                                    pid_t *pid, uid_t *uid, gid_t *gid);
#endif

/*-- assuan-client.c --*/
gpg_error_t 
assuan_transact (assuan_context_t ctx,
                 const char *command,
                 gpg_error_t (*data_cb)(void *, const void *, size_t),
                 void *data_cb_arg,
                 gpg_error_t (*inquire_cb)(void*, const char *),
                 void *inquire_cb_arg,
                 gpg_error_t (*status_cb)(void*, const char *),
                 void *status_cb_arg);


/*-- assuan-inquire.c --*/
gpg_error_t assuan_inquire (assuan_context_t ctx, const char *keyword,
                               unsigned char **r_buffer, size_t *r_length,
                               size_t maxlen);
gpg_error_t assuan_inquire_ext (assuan_context_t ctx, const char *keyword,
				   size_t maxlen,
				   gpg_error_t (*cb) (void *cb_data,
						      gpg_error_t rc,
						      unsigned char *buf,
						      size_t buf_len),
				   void *cb_data);
/*-- assuan-buffer.c --*/
gpg_error_t assuan_read_line (assuan_context_t ctx,
                              char **line, size_t *linelen);
int assuan_pending_line (assuan_context_t ctx);
gpg_error_t assuan_write_line (assuan_context_t ctx, const char *line );
gpg_error_t assuan_send_data (assuan_context_t ctx,
                              const void *buffer, size_t length);

/* The file descriptor must be pending before assuan_receivefd is
   called.  This means that assuan_sendfd should be called *before* the
   trigger is sent (normally via assuan_write_line ("INPUT FD")).  */
gpg_error_t assuan_sendfd (assuan_context_t ctx, assuan_fd_t fd);
gpg_error_t assuan_receivefd (assuan_context_t ctx, assuan_fd_t *fd);


/*-- assuan-util.c --*/
gpg_error_t assuan_set_error (assuan_context_t ctx, gpg_error_t err, const char *text);



/*-- assuan-socket.c --*/

/* These are socket wrapper functions to support an emulation of Unix
   domain sockets on Windows W32.  */
int assuan_sock_close (assuan_fd_t fd);
assuan_fd_t assuan_sock_new (int domain, int type, int proto);
int assuan_sock_connect (assuan_fd_t sockfd, 
                         struct sockaddr *addr, int addrlen);
int assuan_sock_bind (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen);
int assuan_sock_get_nonce (struct sockaddr *addr, int addrlen, 
                           assuan_sock_nonce_t *nonce);
int assuan_sock_check_nonce (assuan_fd_t fd, assuan_sock_nonce_t *nonce);


#ifdef __cplusplus
}
#endif
#endif /* ASSUAN_H */
