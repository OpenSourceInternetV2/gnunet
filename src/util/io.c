/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/io.c
 * @brief (network) input/output operations
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"

/* some systems send us signals, so we'd better
   catch them (& ignore) */
#ifndef LINUX
static void catcher(int sig) {
  LOG(LOG_INFO,
      "INFO: signal %d caught\n", 
      sig);
  /* re-install signal handler! */
  signal(sig, catcher);
}


#endif

void gnunet_util_initIO() {
#if ! (defined(LINUX) || defined(MINGW))
  if ( SIG_ERR == signal(SIGPIPE, SIG_IGN)) {
    if ( SIG_ERR == signal(SIGPIPE, catcher))
      LOG(LOG_WARNING,
	  "WARNING: could not install handler for SIGPIPE!\n"\
	  "Attempting to continue anyway.");
  }
#endif
}

void gnunet_util_doneIO() {
}

/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @param doBlock use YES to change the socket to blocking, NO to non-blocking
 * @return Upon successful completion, it returns zero, otherwise -1 
 */
int setBlocking(int s, int doBlock) {  
#if MINGW
  u_long l = !doBlock;
  if (ioctlsocket(s, FIONBIO, &l) == SOCKET_ERROR) {
    SetErrnoFromWinsockError(WSAGetLastError());
    
    return -1;
  } else {
    /* store the blocking mode */
    __win_SetHandleBlockingMode(s, doBlock);
    return 0;
  }
#else
  int flags = fcntl(s, F_GETFL);
  if (doBlock)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;

  return fcntl(s, 
	       F_SETFL, 
	       flags);
#endif
}

/**
 * Check whether the socket is blocking
 * @param s the socket
 * @return YES if blocking, NO non-blocking
 **/
int isSocketBlocking(int s)
{
#ifndef MINGW
 return (fcntl(s, F_GETFL) & O_NONBLOCK) ? NO : YES;
#else
  return __win_IsHandleMarkedAsBlocking(s);
#endif
}

/* recv wrappers */

/**
 * Do a NONBLOCKING read on the given socket.  Note that in order to
 * avoid blocking, the caller MUST have done a select call before
 * calling this function.
 *
 * Reads at most max bytes to buf.  On error, return SYSERR (errors
 * are blocking or invalid socket but NOT a partial read).  Interrupts
 * are IGNORED.
 *
 * @return the number of bytes read or SYSERR. 
 *         0 is returned if no more bytes can be read
 */ 
int RECV_NONBLOCKING(int s,
		     void * buf,
		     size_t max) {  
  int ret, flags;

  setBlocking(s, NO);  
  do {

#ifdef CYGWIN
    flags = MSG_NOSIGNAL;
#elif OSX
    flags = 0;
#elif SOMEBSD || SOLARIS
    flags = MSG_DONTWAIT;
#elif LINUX
    flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
    /* good luck */
    flags = 0;
#endif

    ret = RECV(s,
	       buf,
	       max,
	       flags);
  } while ( ( ret == -1) && ( errno == EINTR) );
  setBlocking(s, YES);

  if ( (ret < 0) || ((size_t)ret > max) )
    return SYSERR;
  return ret;
}

/**
 * Do a BLOCKING read on the given socket.  Read len bytes (if needed
 * try multiple reads).  Interrupts are ignored.
 *
 * @return SYSERR if len bytes could not be read,
 *   otherwise the number of bytes read (must be len)
 */
int RECV_BLOCKING_ALL(int s,
		      void * buf,
		      size_t len) {
  size_t pos;
  int i, flags;

  pos = 0;
  setBlocking(s, YES);

  while (pos < len) {
#if LINUX || CYGWIN
    flags = MSG_NOSIGNAL;
#else
    flags = 0;
#endif

    i = RECV(s,
	     &((char*)buf)[pos],
	     len - pos,
	     flags);

    if ( (i == -1) && (errno == EINTR) )
      continue;
    if (i <= 0)
    {
      setBlocking(s, NO);
      return SYSERR;
    }
    pos += i;
  }
  if (pos != len)
    errexit("ASSERTION failed: %u != %u\n",
	    len, pos);
  
  setBlocking(s, NO);

  return pos;
}

/**
 * Do a NONBLOCKING write on the given socket.
 * Write at most max bytes from buf.  On error,
 * return SYSERR (errors are blocking or invalid
 * socket but NOT an interrupt or partial write).
 * Interrupts are ignored (cause a re-try).
 *
 * @return the number of bytes written or SYSERR. 
 */ 
int SEND_NONBLOCKING(int s,
		     void * buf,
		     size_t max) {  
  int ret, flags;

  setBlocking(s, NO);
  do {
#ifdef SOMEBSD
    flags = MSG_DONTWAIT;
#elif SOLARIS
    flags = MSG_DONTWAIT;
#elif OSX
    /* As braindead as Win32? */
    flags = 0;
#elif CYGWIN
	flags = MSG_NOSIGNAL;
#elif LINUX
	flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
    /* pray */
	flags = 0;
#endif
    ret = SEND(s,
	       buf,
	       max,
	       flags);

  } while ( (ret == -1) &&
	    (errno == EINTR) );
  setBlocking(s, YES);
  if ( (ret < 0) || ((size_t)ret > max) )
    return SYSERR;
  return ret;
}

/**
 * Do a BLOCKING write on the given socket.  Write len bytes (if
 * needed do multiple write).  Interrupts are ignored (cause a
 * re-try).
 *
 * @return SYSERR if len bytes could not be send,
 *   otherwise the number of bytes transmitted (must be len)
 */
int SEND_BLOCKING_ALL(int s,
		      void * buf,
		      size_t len) {
  size_t pos;
  int i, flags;

  pos = 0;
  setBlocking(s, YES);
  while (pos < len) {
#if CYGWIN || LINUX
    flags = MSG_NOSIGNAL;
#else
    flags = 0;
#endif  
    i = SEND(s,
	           &((char*)buf)[pos],
	           len - pos,
	           flags);
	     
    if ( (i == -1) &&
	 (errno == EINTR) )
      continue; /* ingnore interrupts */
    if (i <= 0) {
      if (i == -1)
	LOG(LOG_WARNING,
	    "WARNING: could not send: %s\n",
	    STRERROR(errno));
      return SYSERR;    
    }
    pos += i;
  }
  setBlocking(s, NO);

  if (pos != len)
    errexit("ASSERTION failed: %u != %u\n",
	    len, pos);
  return pos;
}

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 **/
int isSocketValid(int s)
{
#ifndef MINGW
  struct stat buf;
  return -1 != fstat(s, &buf);
#else
  long l;
  return ioctlsocket(s, FIONREAD, &l) != SOCKET_ERROR;
#endif
}

/**
 * Open a file
 **/
int OPEN(const char *filename, int oflag, ...)
{
  int mode;
  char *fn;

#ifdef MINGW
  char szFile[_MAX_PATH + 1];
  long lRet;
  
  if ((lRet = conv_to_win_path(filename, szFile)) != ERROR_SUCCESS)
  {
    errno = ENOENT;
    SetLastError(lRet);
    
    return -1;
  }
  fn = szFile;
#else
  fn = (char *) filename;
#endif
  
  if (oflag & O_CREAT)
  {
    va_list arg;
    va_start(arg, oflag);
    mode = va_arg(arg, int);
    va_end(arg);    
  }
  else
  {
    mode = 0;
  }
  
#ifdef MINGW
  /* Set binary mode */
  mode |= O_BINARY;
#endif
  
  return open(fn, oflag, mode);
}

/* end of io.c */
