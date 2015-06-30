/* assuan-socket.c - Socket wrapper
   Copyright (C) 2004, 2005, 2009 Free Software Foundation, Inc.
   Copyright (C) 2001-2015 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <wincrypt.h>
#ifndef HAVE_W32CE_SYSTEM
# include <io.h>
#endif
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <assert.h>

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

#ifdef HAVE_W32_SYSTEM
#ifndef S_IRUSR
# define S_IRUSR 0
# define S_IWUSR 0
#endif
#ifndef S_IRGRP
# define S_IRGRP 0
# define S_IWGRP 0
#endif
#endif

#ifndef ENAMETOOLONG
# define ENAMETOOLONG EINVAL
#endif

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
	               + strlen ((ptr)->sun_path))
#endif

/* In the future, we can allow access to sock_ctx, if that context's
   hook functions need to be overridden.  There can only be one global
   assuan_sock_* user (one library or one application) with this
   convenience interface, if non-standard hook functions are
   needed.  */
static assuan_context_t sock_ctx;


#ifdef HAVE_W32_SYSTEM

#ifdef HAVE_W32CE_SYSTEM
static wchar_t *
utf8_to_wchar (const char *string)
{
  int n;
  size_t nbytes;
  wchar_t *result;

  if (!string)
    return NULL;

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, NULL, 0);
  if (n < 0)
    return NULL;

  nbytes = (size_t)(n+1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n+1))
    {
      SetLastError (ERROR_INVALID_PARAMETER);
      return NULL;
    }
  result = malloc (nbytes);
  if (!result)
    return NULL;

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, result, n);
  if (n < 0)
    {
      n = GetLastError ();
      free (result);
      result = NULL;
      SetLastError (n);
    }
  return result;
}

static HANDLE
MyCreateFile (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwSharedMode,
              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
              DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
              HANDLE hTemplateFile)
{
  wchar_t *filename;
  HANDLE result;
  int err;

  filename = utf8_to_wchar (lpFileName);
  if (!filename)
    return INVALID_HANDLE_VALUE;

  result = CreateFileW (filename, dwDesiredAccess, dwSharedMode,
			lpSecurityAttributes, dwCreationDisposition,
			dwFlagsAndAttributes, hTemplateFile);
  err = GetLastError ();
  free (filename);
  SetLastError (err);
  return result;
}
static int
MyDeleteFile (LPCSTR lpFileName)
{
  wchar_t *filename;
  int result, err;

  filename = utf8_to_wchar (lpFileName);
  if (!filename)
    return 0;

  result = DeleteFileW (filename);
  err = GetLastError ();
  free (filename);
  SetLastError (err);
  return result;
}
#else /*!HAVE_W32CE_SYSTEM*/
#define MyCreateFile CreateFileA
#define MyDeleteFile DeleteFileA
#endif /*!HAVE_W32CE_SYSTEM*/

int
_assuan_sock_wsa2errno (int err)
{
  switch (err)
    {
    case WSAENOTSOCK:
      return EINVAL;
    case WSAEWOULDBLOCK:
      return EAGAIN;
    case ERROR_BROKEN_PIPE:
      return EPIPE;
    case WSANOTINITIALISED:
      return ENOSYS;
    default:
      return EIO;
    }
}


/* W32: Fill BUFFER with LENGTH bytes of random.  Returns -1 on
   failure, 0 on success.  Sets errno on failure.  */
static int
get_nonce (char *buffer, size_t nbytes)
{
  HCRYPTPROV prov;
  int ret = -1;

  if (!CryptAcquireContext (&prov, NULL, NULL, PROV_RSA_FULL,
                            (CRYPT_VERIFYCONTEXT|CRYPT_SILENT)) )
    gpg_err_set_errno (ENODEV);
  else
    {
      if (!CryptGenRandom (prov, nbytes, (unsigned char *) buffer))
        gpg_err_set_errno (ENODEV);
      else
        ret = 0;
      CryptReleaseContext (prov, 0);
    }
  return ret;
}


/* W32: The buffer for NONCE needs to be at least 16 bytes.  Returns 0 on
   success and sets errno on failure. */
static int
read_port_and_nonce (const char *fname, unsigned short *port, char *nonce)
{
  FILE *fp;
  char buffer[50], *p;
  size_t nread;
  int aval;

  fp = fopen (fname, "rb");
  if (!fp)
    return -1;
  nread = fread (buffer, 1, sizeof buffer - 1, fp);
  fclose (fp);
  if (!nread)
    {
      gpg_err_set_errno (ENOENT);
      return -1;
    }
  buffer[nread] = 0;
  aval = atoi (buffer);
  if (aval < 1 || aval > 65535)
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }
  *port = (unsigned int)aval;
  for (p=buffer; nread && *p != '\n'; p++, nread--)
    ;
  if (*p != '\n' || nread != 17)
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }
  p++; nread--;
  memcpy (nonce, p, 16);
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/


#ifndef HAVE_W32_SYSTEM
/* Find a redirected socket name for fname and return a malloced setup
   filled sockaddr.  If this does not work out NULL is returned and
   ERRNO is set.  If the file seems to be a redirect True is stored at
   R_REDIRECT.  Note that this function uses the standard malloc and
   not the assuan wrapped one.  The format of the file is:

   %Assuan%
   socket=NAME

   where NAME is the actual socket to use.  No white spaces are
   allowed, both lines must be terminated by a single LF, extra lines
   are not allowed.  Environment variables are interpreted in NAME if
   given in "${VAR} notation; no escape characters are defined, if
   "${" shall be used verbatim, you need to use an environment
   variable with that content.

   The use of an absolute NAME is strongly suggested.  The length of
   the file is limited to 511 bytes which is more than sufficient for
   that common value of 107 for sun_path.  */
static struct sockaddr_un *
eval_redirection (const char *fname, int *r_redirect)
{
  FILE *fp;
  char buffer[512], *name;
  size_t n;
  struct sockaddr_un *addr;
  char *p, *pend;
  const char *s;

  *r_redirect = 0;

  fp = fopen (fname, "rb");
  if (!fp)
    return NULL;
  n = fread (buffer, 1, sizeof buffer - 1, fp);
  fclose (fp);
  if (!n)
    {
      gpg_err_set_errno (ENOENT);
      return NULL;
    }
  buffer[n] = 0;

  /* Check that it is a redirection file.  We also check that the
     first byte of the name is not a LF because that would lead to an
     zero length name. */
  if (n < 17 || buffer[n-1] != '\n'
      || memcmp (buffer, "%Assuan%\nsocket=", 16)
      || buffer[16] == '\n')
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }
  buffer[n-1] = 0;
  name = buffer + 16;

  *r_redirect = 1;

  addr = calloc (1, sizeof *addr);
  if (!addr)
    return NULL;
  addr->sun_family = AF_LOCAL;

  n = 0;
  for (p=name; *p; p++)
    {
      if (*p == '$' && p[1] == '{')
        {
          p += 2;
          pend = strchr (p, '}');
          if (!pend)
            {
              free (addr);
              gpg_err_set_errno (EINVAL);
              return NULL;
            }
          *pend = 0;
          if (*p && (s = getenv (p)))
            {
              for (; *s; s++)
                {
                  if (n < sizeof addr->sun_path - 1)
                    addr->sun_path[n++] = *s;
                  else
                    {
                      free (addr);
                      gpg_err_set_errno (ENAMETOOLONG);
                      return NULL;
                  }
                }
            }
          p = pend;
        }
      else if (*p == '\n')
        break; /* Be nice and stop at the first LF.  */
      else if (n < sizeof addr->sun_path - 1)
        addr->sun_path[n++] = *p;
      else
        {
          free (addr);
          gpg_err_set_errno (ENAMETOOLONG);
          return NULL;
        }
    }

  return addr;
}
#endif /*!HAVE_W32_SYSTEM*/



/* Return a new socket.  Note that under W32 we consider a socket the
   same as an System Handle; all functions using such a handle know
   about this dual use and act accordingly. */
assuan_fd_t
_assuan_sock_new (assuan_context_t ctx, int domain, int type, int proto)
{
#ifdef HAVE_W32_SYSTEM
  assuan_fd_t res;
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;
  res = SOCKET2HANDLE(_assuan_socket (ctx, domain, type, proto));
  return res;
#else
  return _assuan_socket (ctx, domain, type, proto);
#endif
}


int
_assuan_sock_set_flag (assuan_context_t ctx, assuan_fd_t sockfd,
		      const char *name, int value)
{
  if (0)
    {
    }
  else
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }

  return 0;
}


int
_assuan_sock_get_flag (assuan_context_t ctx, assuan_fd_t sockfd,
                       const char *name, int *r_value)
{
  (void)ctx;

  if (0)
    {
    }
  else
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }

  return 0;
}


int
_assuan_sock_connect (assuan_context_t ctx, assuan_fd_t sockfd,
		      struct sockaddr *addr, int addrlen)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un *unaddr;
      unsigned short port;
      char nonce[16];
      int ret;

      unaddr = (struct sockaddr_un *)addr;
      if (read_port_and_nonce (unaddr->sun_path, &port, nonce))
        return -1;

      myaddr.sin_family = AF_INET;
      myaddr.sin_port = htons (port);
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      /* Set return values.  */
      unaddr->sun_family = myaddr.sin_family;
      unaddr->sun_port = myaddr.sin_port;
      unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;

      ret = _assuan_connect (ctx, HANDLE2SOCKET(sockfd),
			    (struct sockaddr *)&myaddr, sizeof myaddr);
      if (!ret)
        {
          /* Send the nonce. */
          ret = _assuan_write (ctx, sockfd, nonce, 16);
          if (ret >= 0 && ret != 16)
            {
              gpg_err_set_errno (EIO);
              ret = -1;
            }
        }
      return ret;
    }
  else
    {
      int res;
      res = _assuan_connect (ctx, HANDLE2SOCKET (sockfd), addr, addrlen);
      return res;
    }
#else
# if HAVE_STAT
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_un *unaddr;
      struct stat statbuf;
      int redirect, res;

      unaddr = (struct sockaddr_un *)addr;
      if (!stat (unaddr->sun_path, &statbuf)
          && !S_ISSOCK (statbuf.st_mode)
          && S_ISREG (statbuf.st_mode))
        {
          /* The given socket file is not a socket but a regular file.
             We use the content of that file to redirect to another
             socket file.  This can be used to use sockets on file
             systems which do not support sockets or if for example a
             home directory is shared by several machines.  */
          unaddr = eval_redirection (unaddr->sun_path, &redirect);
          if (unaddr)
            {
              res = _assuan_connect (ctx, sockfd, (struct sockaddr *)unaddr,
                                     SUN_LEN (unaddr));
              free (unaddr);
              return res;
            }
          if (redirect)
            return -1;
          /* Continue using the standard connect.  */
        }

    }
# endif /*HAVE_STAT*/
  return _assuan_connect (ctx, sockfd, addr, addrlen);
#endif
}


int
_assuan_sock_bind (assuan_context_t ctx, assuan_fd_t sockfd,
		   struct sockaddr *addr, int addrlen)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un *unaddr;
      HANDLE filehd;
      int len = sizeof myaddr;
      int rc;
      char nonce[16];
      char tmpbuf[33+16];
      DWORD nwritten;

      if (get_nonce (nonce, 16))
        return -1;

      unaddr = (struct sockaddr_un *)addr;

      myaddr.sin_port = 0;
      myaddr.sin_family = AF_INET;
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      filehd = MyCreateFile (unaddr->sun_path,
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             NULL,
                             CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
      if (filehd == INVALID_HANDLE_VALUE)
        {
          if (GetLastError () == ERROR_FILE_EXISTS)
            gpg_err_set_errno (EADDRINUSE);
          return -1;
        }

      rc = bind (HANDLE2SOCKET (sockfd), (struct sockaddr *)&myaddr, len);
      if (!rc)
        rc = getsockname (HANDLE2SOCKET (sockfd),
                          (struct sockaddr *)&myaddr, &len);
      if (rc)
        {
          int save_e = errno;
          CloseHandle (filehd);
          MyDeleteFile (unaddr->sun_path);
          gpg_err_set_errno (save_e);
          return rc;
        }
      snprintf (tmpbuf, sizeof tmpbuf, "%d\n", ntohs (myaddr.sin_port));
      len = strlen (tmpbuf);
      memcpy (tmpbuf+len, nonce,16);
      len += 16;

      if (!WriteFile (filehd, tmpbuf, len, &nwritten, NULL))
        {
          CloseHandle (filehd);
          MyDeleteFile (unaddr->sun_path);
          gpg_err_set_errno (EIO);
          return -1;
        }
      CloseHandle (filehd);
      return 0;
    }
  else
    {
      int res = bind (HANDLE2SOCKET(sockfd), addr, addrlen);
      if (res < 0)
	gpg_err_set_errno ( _assuan_sock_wsa2errno (WSAGetLastError ()));
      return res;
    }
#else
  return bind (sockfd, addr, addrlen);
#endif
}


/* Setup the ADDR structure for a Unix domain socket with the socket
   name FNAME.  If this is a redirected socket and R_REDIRECTED is not
   NULL, it will be setup for the real socket.  Returns 0 on success
   and stores 1 at R_REDIRECTED if it is a redirected socket.  On
   error -1 is returned and ERRNO will be set.  */
int
_assuan_sock_set_sockaddr_un (const char *fname, struct sockaddr *addr,
                              int *r_redirected)
{
  struct sockaddr_un *unaddr = (struct sockaddr_un *)addr;
#if !defined(HAVE_W32_SYSTEM) && defined(HAVE_STAT)
  struct stat statbuf;
#endif

  if (r_redirected)
    *r_redirected = 0;

#if !defined(HAVE_W32_SYSTEM) && defined(HAVE_STAT)
  if (r_redirected
      && !stat (fname, &statbuf)
      && !S_ISSOCK (statbuf.st_mode)
      && S_ISREG (statbuf.st_mode))
    {
      /* The given socket file is not a socket but a regular file.  We
         use the content of that file to redirect to another socket
         file.  This can be used to use sockets on file systems which
         do not support sockets or if for example a home directory is
         shared by several machines.  */
      struct sockaddr_un *unaddr_new;
      int redirect;

      unaddr_new = eval_redirection (fname, &redirect);
      if (unaddr_new)
        {
          memcpy (unaddr, unaddr_new, sizeof *unaddr);
          free (unaddr_new);
          *r_redirected = 1;
          return 0;
        }
      if (redirect)
        {
          *r_redirected = 1;
          return -1;  /* Error.  */
        }
      /* Fallback to standard setup.  */
    }
#endif /*!HAVE_W32_SYSTEM && HAVE_STAT*/

  if (strlen (fname)+1 >= sizeof unaddr->sun_path)
    {
      gpg_err_set_errno (ENAMETOOLONG);
      return -1;
    }

  memset (unaddr, 0, sizeof *unaddr);
  unaddr->sun_family = AF_LOCAL;
  strncpy (unaddr->sun_path, fname, sizeof unaddr->sun_path - 1);
  unaddr->sun_path[sizeof unaddr->sun_path - 1] = 0;

  return 0;
}


int
_assuan_sock_get_nonce (assuan_context_t ctx, struct sockaddr *addr,
			int addrlen, assuan_sock_nonce_t *nonce)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_un *unaddr;
      unsigned short port;

      if (sizeof nonce->nonce != 16)
        {
          gpg_err_set_errno (EINVAL);
          return -1;
        }
      nonce->length = 16;
      unaddr = (struct sockaddr_un *)addr;
      if (read_port_and_nonce (unaddr->sun_path, &port, nonce->nonce))
        return -1;
    }
  else
    {
      nonce->length = 42; /* Arbitrary value to detect unitialized nonce. */
      nonce->nonce[0] = 42;
    }
#else
  (void)addr;
  (void)addrlen;
  nonce->length = 0;
#endif
  return 0;
}


int
_assuan_sock_check_nonce (assuan_context_t ctx, assuan_fd_t fd,
			  assuan_sock_nonce_t *nonce)
{
#ifdef HAVE_W32_SYSTEM
  char buffer[16], *p;
  size_t nleft;
  int n;

  if (sizeof nonce->nonce != 16)
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }

  if (nonce->length == 42 && nonce->nonce[0] == 42)
    return 0; /* Not a Unix domain socket.  */

  if (nonce->length != 16)
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }

  p = buffer;
  nleft = 16;
  while (nleft)
    {
      n = _assuan_read (ctx, SOCKET2HANDLE(fd), p, nleft);
      if (n < 0 && errno == EINTR)
        ;
      else if (n < 0 && errno == EAGAIN)
        Sleep (100);
      else if (n < 0)
        return -1;
      else if (!n)
        {
          gpg_err_set_errno (EIO);
          return -1;
        }
      else
        {
          p += n;
          nleft -= n;
        }
    }
  if (memcmp (buffer, nonce->nonce, 16))
    {
      gpg_err_set_errno (EACCES);
      return -1;
    }
#else
  (void)fd;
  (void)nonce;
#endif
  return 0;
}


/* Public API.  */

gpg_error_t
assuan_sock_init ()
{
  gpg_error_t err;
#ifdef HAVE_W32_SYSTEM
  WSADATA wsadat;
#endif

  if (sock_ctx != NULL)
    return 0;

  err = assuan_new (&sock_ctx);

#ifdef HAVE_W32_SYSTEM
  if (! err)
    WSAStartup (0x202, &wsadat);
#endif

  return err;
}


void
assuan_sock_deinit ()
{
  if (sock_ctx == NULL)
    return;

#ifdef HAVE_W32_SYSTEM
  WSACleanup ();
#endif

  assuan_release (sock_ctx);
  sock_ctx = NULL;
}


int
assuan_sock_close (assuan_fd_t fd)
{
  return _assuan_close (sock_ctx, fd);
}

assuan_fd_t
assuan_sock_new (int domain, int type, int proto)
{
  return _assuan_sock_new (sock_ctx, domain, type, proto);
}

int
assuan_sock_set_flag (assuan_fd_t sockfd, const char *name, int value)
{
  return _assuan_sock_set_flag (sock_ctx, sockfd, name, value);
}

int
assuan_sock_get_flag (assuan_fd_t sockfd, const char *name, int *r_value)
{
  return _assuan_sock_get_flag (sock_ctx, sockfd, name, r_value);
}

int
assuan_sock_connect (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
  return _assuan_sock_connect (sock_ctx, sockfd, addr, addrlen);
}

int
assuan_sock_bind (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
  return _assuan_sock_bind (sock_ctx, sockfd, addr, addrlen);
}

int
assuan_sock_set_sockaddr_un (const char *fname, struct sockaddr *addr,
                             int *r_redirected)
{
  return _assuan_sock_set_sockaddr_un (fname, addr, r_redirected);
}

int
assuan_sock_get_nonce (struct sockaddr *addr, int addrlen,
                       assuan_sock_nonce_t *nonce)
{
  return _assuan_sock_get_nonce (sock_ctx, addr, addrlen, nonce);
}

int
assuan_sock_check_nonce (assuan_fd_t fd, assuan_sock_nonce_t *nonce)
{
  return _assuan_sock_check_nonce (sock_ctx, fd, nonce);
}
