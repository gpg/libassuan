/* gpgcedrv.c - WindowsCE device driver to implement a pipe.
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


#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <devload.h>
#include <winioctl.h>

#define ENABLE_DEBUG
#warning Cancel and caller process termination not handled.


/* Missing IOCTLs in the current mingw32ce.  */
#ifndef IOCTL_PSL_NOTIFY
# define FILE_DEVICE_PSL 259
# define IOCTL_PSL_NOTIFY                               \
  CTL_CODE (259, 255, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif /*IOCTL_PSL_NOTIFY*/


/* The IOCTL to return the rendezvous id of the handle.

   The required outbuf parameter is the address of a variable to store
   the rendezvous ID, which is a LONG value.  */
#define GPGCEDEV_IOCTL_GET_RVID \
  CTL_CODE (FILE_DEVICE_STREAMS, 2048, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* The IOCTL used to create the pipe. 

   The caller sends this IOCTL to the read or the write handle.  The
   required inbuf parameter is address of a variable holding the
   rendezvous id of the pipe's other end.  There is one possible
   problem with the code: If a pipe is kept in non-rendezvous state
   until after the rendezvous ids overflow, it is possible that the
   wrong end will be used.  However this is not a realistic scenario.  */
#define GPGCEDEV_IOCTL_MAKE_PIPE \
  CTL_CODE (FILE_DEVICE_STREAMS, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)


/* An object to store information pertaining to an open-context.  */
struct opnctx_s;
typedef struct opnctx_s *opnctx_t;
struct opnctx_s
{
  int inuse;        /* True if this object has valid data.  */
  opnctx_t assoc;   /* This context has been associated with this
                       other context; i.e. a pipe has been
                       established.  */
  int is_write;     /* True if this is the write end of the pipe.  */
  LONG rvid;        /* The unique rendezvous identifier.  */
  DWORD access_code;/* Value from OpenFile.  */
  DWORD share_mode; /* Value from OpenFile.  */
  CRITICAL_SECTION critsect;  /* Lock for all operations.  */
  int locked;       /* True if we are in a critical section.  */

  /* The malloced buffer and its size.  We use a buffer for each
     handle which allows us eventually implement a system to
     distribute data to several handles.  Not sure whether this is
     really needed but as a side effect it makes the code easier. */
  char *buffer;       
  size_t buffer_size;
  size_t buffer_len;  /* The valid length of the bufer.  */
  size_t buffer_pos;  /* The actual read or write position.  */

  HANDLE space_available; /* Set if space is available.  */
  HANDLE data_available;  /* Set if data is available.  */
};

/* A malloced table of open-context and the number of allocated slots.  */
static opnctx_t opnctx_table;
static size_t   opnctx_table_size;

/* A criticial section object used to protect the OPNCTX_TABLE.  */
static CRITICAL_SECTION opnctx_table_cs;

/* We don't need a device context thus we use the adress of the
   critical section object for it.  */
#define DEVCTX_VALUE ((DWORD)(&opnctx_table_cs))

/* Constants used for our lock functions.  */
#define LOCK_TRY  0
#define LOCK_WAIT 1



static void
log_debug (const char *fmt, ...)
{
#ifndef ENABLE_DEBUG
  (void)fmt;
#else
  va_list arg_ptr;
  FILE *fp;

  fp = fopen ("\\gpgcedev.log", "a+");
  if (!fp)
    return;
  va_start (arg_ptr, fmt);
  vfprintf (fp, fmt, arg_ptr);
  va_end (arg_ptr);
  fclose (fp);
#endif
}


/* Return a new rendezvous next command id.  Command Ids are used to group
   resources of one command.  We will never return an RVID of 0. */
static LONG
create_rendezvous_id (void)
{
  static LONG rendezvous_id;
  LONG rvid;

  while (!(rvid = InterlockedIncrement (&rendezvous_id)))
    ;
  return rvid;
}



/* Return a new opnctx handle and mark it as used.  Returns NULL and
   sets LastError on memory failure etc.  On success the context is
   locked.  */
static opnctx_t
get_new_opnctx (void)
{
  opnctx_t opnctx = NULL;
  int idx;

  EnterCriticalSection (&opnctx_table_cs);
  for (idx=0; idx < opnctx_table_size; idx++)
    if (!opnctx_table[idx].inuse)
      break;
  if (idx == opnctx_table_size)
    {
      /* We need to increase the size of the table.  The approach we
         take is straightforward to minimize the risk of bugs.  */
      opnctx_t newtbl;
      size_t newsize = opnctx_table_size + 64;

      newtbl = calloc (newsize, sizeof *newtbl);
      if (!newtbl)
        goto leave;
      for (idx=0; idx < opnctx_table_size; idx++)
        newtbl[idx] = opnctx_table[idx];
      free (opnctx_table);
      opnctx_table = newtbl;
      idx = opnctx_table_size;
      opnctx_table_size = newsize;
    }
  opnctx = opnctx_table + idx;
  opnctx->assoc = NULL;
  opnctx->rvid = create_rendezvous_id ();
  opnctx->buffer_size = 512;
  opnctx->buffer = malloc (opnctx->buffer_size);
  if (!opnctx->buffer)
    {
      opnctx = NULL;
      goto leave;
    }
  opnctx->buffer_len = 0;
  opnctx->buffer_pos = 0;
  opnctx->data_available = INVALID_HANDLE_VALUE;
  opnctx->space_available = INVALID_HANDLE_VALUE;

  opnctx->inuse = 1;
  InitializeCriticalSection (&opnctx->critsect);
  EnterCriticalSection (&opnctx->critsect);
  opnctx->locked = 1;
  
 leave:
  LeaveCriticalSection (&opnctx_table_cs);
  if (opnctx)
    log_debug ("get_new_opnctx -> %p (rvid=%ld)\n", opnctx, opnctx->rvid);
  else
    log_debug ("get_new_opnctx -> failed\n");
  return opnctx;
}


/* Find the OPNCTX object with the rendezvous id RVID.  */
static opnctx_t
find_and_lock_opnctx (LONG rvid)
{
  opnctx_t result = NULL;
  int idx;

  EnterCriticalSection (&opnctx_table_cs);
  for (idx=0; idx < opnctx_table_size; idx++)
    if (opnctx_table[idx].inuse && opnctx_table[idx].rvid == rvid)
      {
        result = opnctx_table + idx;
        break;
      }
  LeaveCriticalSection (&opnctx_table_cs);
  if (!result)
    {
      SetLastError (ERROR_INVALID_HANDLE);
      log_debug ("find_opnctx -> invalid rendezvous id\n");
    }
  else if (TryEnterCriticalSection (&result->critsect))
    {
      result->locked++;
      log_debug ("find_opnctx -> %p (rvid=%ld)\n", result, result->rvid);
    }
  else
    {
      SetLastError (ERROR_BUSY);
      result = NULL;
      log_debug ("find_opnctx -> busy\n");
    }
  return result;
}


/* Check that OPNCTX is valid.  Returns TRUE if it is valid or FALSE
   if it is a bad or closed contect.  In the latter case SetLastError
   is called.  In the former case a lock is taken and unlock_opnctx
   needs to be called.  If WAIT is false the fucntion only tries to
   acquire a lock. */
static BOOL
validate_and_lock_opnctx (opnctx_t opnctx, int wait)
{
  BOOL result = FALSE;
  int idx;

  EnterCriticalSection (&opnctx_table_cs);
  for (idx=0; idx < opnctx_table_size; idx++)
    if (opnctx_table[idx].inuse && (opnctx_table + idx) == opnctx)
      {
        result = TRUE;
        break;
      }
  LeaveCriticalSection (&opnctx_table_cs);

  if (!result)
    SetLastError (ERROR_INVALID_HANDLE);
  else if (wait)
    {
      EnterCriticalSection (&opnctx->critsect);
      opnctx->locked++;
    }
  else if (TryEnterCriticalSection (&opnctx->critsect))
    opnctx->locked++;
  else
    {
      SetLastError (ERROR_BUSY);
      result = FALSE;
    }
  return result;
}


static void
unlock_opnctx (opnctx_t opnctx)
{
  opnctx->locked--;
  LeaveCriticalSection (&opnctx->critsect);
}




static char *
wchar_to_utf8 (const wchar_t *string)
{
  int n;
  size_t length = wcslen (string);
  char *result;

  n = WideCharToMultiByte (CP_UTF8, 0, string, length, NULL, 0, NULL, NULL);
  if (n < 0 || (n+1) <= 0)
    abort ();

  result = malloc (n+1);
  if (!result)
    abort ();
  n = WideCharToMultiByte (CP_ACP, 0, string, length, result, n, NULL, NULL);
  if (n < 0)
    abort ();
  
  result[n] = 0;
  return result;
}


/* Initialize the device and return a device specific context.  */
DWORD
GPG_Init (LPCTSTR active_key, DWORD bus_context)
{
  char *tmpbuf;
  (void)bus_context;
  
  tmpbuf = wchar_to_utf8 (active_key);
  log_debug ("GPG_Init (%s)\n", tmpbuf);
  free (tmpbuf);

  /* We don't need any global data.  However, we need to return
     something.  */
  return DEVCTX_VALUE;
}



/* Deinitialize this device driver.  */
BOOL
GPG_Deinit (DWORD devctx)
{
  log_debug ("GPG_Deinit (%p)\n", (void*)devctx);
  if (devctx != DEVCTX_VALUE)
    {
      SetLastError (ERROR_INVALID_PARAMETER);
      return FALSE; /* Error.  */
    }
  
  /* FIXME: Release resources.  */

  return TRUE; /* Success.  */
}



/* Create a new open context.  This fucntion is called due to a
   CreateFile from the application.  */
DWORD
GPG_Open (DWORD devctx, DWORD access_code, DWORD share_mode)
{
  opnctx_t opnctx;

  log_debug ("GPG_Open(devctx=%p)\n", (void*)devctx);
  if (devctx != DEVCTX_VALUE)
    {
      SetLastError (ERROR_INVALID_PARAMETER);
      return 0; /* Error.  */
    }

  opnctx = get_new_opnctx ();
  if (!opnctx)
    return 0;
  opnctx->access_code = access_code;
  opnctx->share_mode = share_mode;

  unlock_opnctx (opnctx);
  return (DWORD)opnctx;
}



BOOL
GPG_Close (DWORD opnctx_arg)
{
  opnctx_t opnctx = (opnctx_t)opnctx_arg;
  BOOL result = FALSE;
  int idx;

  log_debug ("GPG_Close(%p)\n", (void*)opnctx);

  EnterCriticalSection (&opnctx_table_cs);
  for (idx=0; idx < opnctx_table_size; idx++)
    if (opnctx_table[idx].inuse && (opnctx_table + idx) == opnctx)
      {
        if (opnctx->assoc)
          {
            opnctx->assoc->assoc = NULL;
            opnctx->assoc = NULL;
          }
        if (opnctx->locked)
          {
            /* FIXME: Check earlier or use close only in locked state
               or use PReClose.  */
            log_debug ("GPG_Close while still locked\n");
          }
        DeleteCriticalSection (&opnctx->critsect);
        if (opnctx->buffer)
          {
            free (opnctx->buffer);
            opnctx->buffer = NULL;
            opnctx->buffer_size = 0;
          }
        if (opnctx->space_available != INVALID_HANDLE_VALUE)
          {
            CloseHandle (opnctx->space_available);
            opnctx->space_available = INVALID_HANDLE_VALUE;
          }
        if (opnctx->data_available != INVALID_HANDLE_VALUE)
          {
            CloseHandle (opnctx->data_available);
            opnctx->data_available = INVALID_HANDLE_VALUE;
          }
        opnctx->inuse = 0;
        result = TRUE;
        break;
      }
  LeaveCriticalSection (&opnctx_table_cs);

  if (!result)
    SetLastError (ERROR_INVALID_HANDLE);
  return result;
}



DWORD
GPG_Read (DWORD opnctx_arg, void *buffer, DWORD count)
{
  opnctx_t rctx = (opnctx_t)opnctx_arg;
  opnctx_t wctx;
  int result = -1;
  const char *src;
  char *dst;

  log_debug ("GPG_Read(%p, count=%d)\n", (void*)rctx, count);

  /* We use the write end's buffer, thus there is no need to wait for
     our (read end) lock.  */
  if (!validate_and_lock_opnctx (rctx, LOCK_TRY))
    return -1; /* Error.  */

  if (rctx->is_write)
    {
      SetLastError (ERROR_INVALID_ACCESS);
      goto leave;
    }
  if (!rctx->assoc)
    {
      SetLastError (ERROR_BROKEN_PIPE);
      goto leave;
    }

  /* Read from the corresponding write buffer.  */
 retry:
  wctx = rctx->assoc;
  if (!validate_and_lock_opnctx (wctx, LOCK_WAIT))
    goto leave;

  if (wctx->buffer_pos == wctx->buffer_len)
    {
      unlock_opnctx (wctx);
      log_debug ("%s:%d: WFSO(data_available)\n",  __func__, __LINE__);
      WaitForSingleObject (wctx->data_available, INFINITE);
      log_debug ("%s:%d: WFSO ... woke up\n",  __func__, __LINE__);
      goto retry;
    }
  
  dst = buffer;
  src = wctx->buffer + wctx->buffer_pos;
  while (count > 0 && wctx->buffer_pos < wctx->buffer_len)
    {
      *dst++ = *src++;
      count--;
      wctx->buffer_pos++;
    }
  result = (dst - (char*)buffer);
  if (wctx->buffer_pos == wctx->buffer_len)
    wctx->buffer_pos = wctx->buffer_len = 0;
  
  /* Now there should be some space available.  Signal the write end.
     Even if COUNT was passed as NULL and no space is available,
     signaling must be done.  */
  if (!SetEvent (wctx->space_available))
    {
      log_debug ("%s:%d: SetEvent(space_available) failed: rc=%d\n",
                 __func__, __LINE__, (int)GetLastError ());
      unlock_opnctx (wctx);
      goto leave;
    }
  unlock_opnctx (wctx);

 leave:
  unlock_opnctx (rctx);
  return result;
}



DWORD
GPG_Write (DWORD opnctx_arg, const void *buffer, DWORD count)
{
  opnctx_t wctx = (opnctx_t)opnctx_arg;
  int result = -1;
  const char *src;
  char *dst;
  size_t nwritten = 0;

  log_debug ("GPG_Write(%p, count=%d)\n", (void*)wctx, count);
 retry:
  if (!validate_and_lock_opnctx (wctx, LOCK_WAIT))
    return -1; /* Error.  */

  if (!wctx->is_write)
    {
      SetLastError (ERROR_INVALID_ACCESS);
      goto leave;
    }
  if (!wctx->assoc)
    {
      SetLastError (ERROR_BROKEN_PIPE);
      goto leave;
    }
  if (!count)
    {
      result = 0;
      goto leave;
    }

  /* Write to our buffer.  */
  if (wctx->buffer_len == wctx->buffer_size)
    {
      /* Buffer is full.  */
      unlock_opnctx (wctx);
      log_debug ("%s:%d: WFSO(space_available)\n",  __func__, __LINE__);
      WaitForSingleObject (wctx->space_available, INFINITE);
      log_debug ("%s:%d: WFSO ... woke up\n",  __func__, __LINE__);
      goto retry;
    }

  src = buffer;
  dst = wctx->buffer + wctx->buffer_len;
  while (count > 0 && wctx->buffer_len < wctx->buffer_size)
    {
      *dst++ = *src++;
      count--;
      wctx->buffer_len++;
      nwritten++;
    }
  if (!SetEvent (wctx->data_available))
    {
      log_debug ("%s:%d: SetEvent(data_available) failed: rc=%d\n",
                 __func__, __LINE__, (int)GetLastError ());
      goto leave;
    }
  result = nwritten;

 leave:
  unlock_opnctx (wctx);
  return result;
}



DWORD
GPG_Seek (DWORD opnctx, long amount, WORD type)
{
  SetLastError (ERROR_SEEK_ON_DEVICE);
  return -1; /* Error.  */
}



static BOOL
make_pipe (opnctx_t ctx, LONG rvid)
{
  BOOL result = FALSE;
  opnctx_t peerctx = NULL;

  log_debug ("  make_pipe(%p, rvid=%ld)\n", ctx, rvid);
  if (ctx->assoc)
    {
      SetLastError (ERROR_ALREADY_ASSIGNED);
      goto leave;
    }

  peerctx = find_and_lock_opnctx (rvid);
  if (!peerctx)
    {
      SetLastError (ERROR_NOT_FOUND);
      goto leave;
    }
  if (peerctx == ctx)
    {
      SetLastError (ERROR_INVALID_TARGET_HANDLE);
      goto leave;
    }
  if (peerctx->assoc)
    {
      SetLastError (ERROR_ALREADY_ASSIGNED);
      goto leave;
    }

  if ((ctx->access_code & GENERIC_READ))
    {
      /* Check that the peer is a write end.  */
      if (!(peerctx->access_code & GENERIC_WRITE))
        {
          SetLastError (ERROR_INVALID_ACCESS);
          goto leave;
        }
      peerctx->space_available = CreateEvent (NULL, FALSE, FALSE, NULL);
      peerctx->data_available = CreateEvent (NULL, FALSE, FALSE, NULL);
      
      ctx->assoc = peerctx;
      peerctx->assoc = ctx;
      ctx->is_write = 0;
      peerctx->is_write = 1;
      result = TRUE;
    }
  else if ((ctx->access_code & GENERIC_WRITE))
    {
      /* Check that the peer is a read end.  */
      if (!(peerctx->access_code & GENERIC_READ))
        {
          SetLastError (ERROR_INVALID_ACCESS);
          goto leave;
        }
      ctx->space_available = CreateEvent (NULL, FALSE, FALSE, NULL);
      ctx->data_available = CreateEvent (NULL, FALSE, FALSE, NULL);
      
      ctx->assoc = peerctx;
      peerctx->assoc = ctx;
      ctx->is_write = 1;
      peerctx->is_write = 0;
      result = TRUE;
    }
  else
    {
      SetLastError (ERROR_INVALID_ACCESS);
      goto leave;
    }

 leave:
  if (peerctx)
    unlock_opnctx (peerctx);
  return result;
}


BOOL
GPG_IOControl (DWORD opnctx_arg, DWORD code, void *inbuf, DWORD inbuflen,
               void *outbuf, DWORD outbuflen, DWORD *actualoutlen)
{
  opnctx_t opnctx = (opnctx_t)opnctx_arg;
  BOOL result = FALSE;
  LONG rvid;

  log_debug ("GPG_IOControl(%p, %d)\n", (void*)opnctx, code);
  if (!validate_and_lock_opnctx (opnctx, LOCK_TRY))
    return FALSE;

  switch (code)
    {
    case GPGCEDEV_IOCTL_GET_RVID:
      if (!opnctx || inbuf || inbuflen
          || !outbuf || outbuflen  < sizeof (LONG))
        {
          SetLastError (ERROR_INVALID_PARAMETER);
          goto leave;
        }
      memcpy (outbuf, &opnctx->rvid, sizeof (LONG));
      if (actualoutlen)
        *actualoutlen = sizeof (LONG);
      result = TRUE;
      break;

    case GPGCEDEV_IOCTL_MAKE_PIPE:
      if (!opnctx || !inbuf || inbuflen < sizeof (LONG) 
          || outbuf || outbuflen || actualoutlen )
        {
          SetLastError (ERROR_INVALID_PARAMETER);
          goto leave;
        }
      memcpy (&rvid, inbuf, sizeof (LONG));
      if (make_pipe (opnctx, rvid))
        result = TRUE;
      break;

    case IOCTL_PSL_NOTIFY:
      /* Unexpected process termination.  */
      break;

    default:
      SetLastError (ERROR_INVALID_PARAMETER);
      break;
    }

 leave:
  unlock_opnctx (opnctx);
  return result;
}



void
GPG_PowerUp (DWORD devctx)
{
}



void
GPG_PowerDown (DWORD devctx)
{
}




/* Entry point called by the DLL loader.  */
int WINAPI
DllMain (HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
  (void)reserved;

  switch (reason)
    {
    case DLL_PROCESS_ATTACH:
      InitializeCriticalSection (&opnctx_table_cs);
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      DeleteCriticalSection (&opnctx_table_cs);
      break;

    default:
      break;
    }
  
  return TRUE;
}

