/*
     This file is part of GNUnet

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
 * @file transports/tcp6.c
 * @brief Implementation of the TCP6 transport service over IPv6
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_transport.h"
#include "platform.h"

#define DEBUG_TCP6 NO

/**
 * after how much time of the core not being associated with a tcp6
 * connection anymore do we close it? 
 */
#define TCP6_TIMEOUT 30 * cronSECONDS

/**
 * @brief Host-Address in a TCP6 network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order 
   */  
  IP6addr ip;

  /**
   * claimed port of the sender, network byte order 
   */
  unsigned short port; 

  /**
   * reserved (set to 0 for signature verification) 
   */
  unsigned short reserved; 

} Host6Address;

/**
 * @brief TCP6 Message-Packet header. 
 */
typedef struct {
  /**
   * size of the message, in bytes, including this header; 
   * max 65536-header (network byte order) 
   */
  unsigned short size;

  /**
   * reserved, must be 0 (network byte order) 
   */
  unsigned short isEncrypted;

  /**
   * CRC checksum of the packet  (network byte order)
   */ 
  int checkSum;
  
  /**
   * This struct is followed by MESSAGE_PARTs - until size is reached 
   * There is no "end of message".
   */
  p2p_HEADER parts[0];
} TCP6MessagePack;

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_HEADER since we are using tcp6io.
 */
typedef struct {
  /**
   * size of the handshake message, in nbo, value is 24 
   */    
  unsigned short size;

  /**
   * "message type", TCP6 version number, always 0.
   */
  unsigned short version;

  /**
   * Identity of the node connecting (TCP6 client) 
   */
  HostIdentity clientIdentity;
} TCP6Welcome;

/**
 * @brief TCP6 Transport Session handle.
 */
typedef struct {
  /**
   * the tcp6 socket 
   */
  int sock;

  /**
   * number of users of this session 
   */
  int users;

  /**
   * Last time this connection was used
   */
  cron_t lastUse;

  /**
   * mutex for synchronized access to 'users' 
   */
  Mutex lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  HostIdentity sender;

  /**
   * Are we still expecting the welcome? (YES/NO)
   */
  int expectingWelcome;

  /**
   * Current read position in the buffer.
   */
  unsigned int pos;  

  /**
   * Current size of the buffer.
   */
  unsigned int size;

  /**
   * The read buffer.
   */
  char * rbuff;

  /**
   * Position in the write buffer
   */
  unsigned int wpos;

  /**
   * The write buffer.
   */
  char * wbuff;

} TCP6Session;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api ) 
 */
static CoreAPIForTransport * coreAPI;
static TransportAPI tcp6API;

/**
 * one thread for listening for new connections,
 * and for reading on all open sockets 
 */
static PTHREAD_T listenThread;

/**
 * sock is the tcp6 socket that we listen on for new inbound
 * connections.
 */
static int tcp6_sock;

/**
 * tcp6_pipe is used to signal the thread that is
 * blocked in a select call that the set of sockets to listen
 * to has changed.
 */
static int tcp6_pipe[2];

/**
 * Array of currently active TCP6 sessions. 
 */
static TSession ** tsessions = NULL;
static int tsessionCount;
static int tsessionArrayLength;

/**
 * handles for statistics 
 */
static int stat_octets_total_tcp6_in;
static int stat_octets_total_tcp6_out;

/* configuration */
static CIDR6Network * filteredNetworks_;

/**
 * Lock for access to mutable state of the module,
 * that is the configuration and the tsessions array.
 * Note that we ONLY need to synchronize access to
 * the tsessions array when adding or removing sessions,
 * since removing is done only by one thread and we just
 * need to avoid another thread adding an element at the
 * same point in time. We do not need to synchronize at
 * every access point since adding new elements does not
 * prevent the select thread from operating and removing
 * is done by the only therad that reads from the array.
 */
static Mutex tcp6lock;

/**
 * Semaphore used by the server-thread to signal that
 * the server has been started -- and later again to
 * signal that the server has been stopped.
 */
static Semaphore * serverSignal = NULL;
static int tcp6_shutdown = YES;

/* ******************** helper functions *********************** */

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isBlacklisted(IP6addr * ip) {
  int ret;

  MUTEX_LOCK(&tcp6lock);
  ret = checkIP6Listed(filteredNetworks_,
		       ip);
  MUTEX_UNLOCK(&tcp6lock);
  return ret;
}

/**
 * Write to the pipe to wake up the select thread (the set of
 * files to watch has changed).
 */
static void signalSelect() {
  char i = 0;
  int ret;

  LOG(LOG_DEBUG,
      "Signaling select.\n");
  ret = WRITE(tcp6_pipe[1],
	      &i,
	      sizeof(char));
  if (ret != sizeof(char))
    LOG_STRERROR(LOG_ERROR, "write");
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were aquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int tcp6Disconnect(TSession * tsession) {
  if (tsession->internal != NULL) {
    TCP6Session * tcp6session = tsession->internal;

    MUTEX_LOCK(&tcp6session->lock);
    tcp6session->users--;
    if (tcp6session->users > 0) {
      MUTEX_UNLOCK(&tcp6session->lock);
      return OK;
    }
    MUTEX_UNLOCK(&tcp6session->lock);
    MUTEX_DESTROY(&tcp6session->lock);
    FREE(tcp6session->rbuff);
    FREENONNULL(tcp6session->wbuff);
    FREE(tcp6session);
    FREE(tsession);
  }
  return OK;
}

/**
 * Remove a session, either the other side closed the connection
 * or we have otherwise reason to believe that it should better
 * be killed. Destroy session closes the session as far as the
 * TCP6 layer is concerned, but since the core may still have
 * references to it, tcp6Disconnect may not instantly free all
 * the associated resources. <p>
 *
 * destroySession may only be called if the tcp6lock is already
 * held.
 *
 * @param i index to the session handle
 */
static void destroySession(int i) {  
  TCP6Session * tcp6Session;

  tcp6Session = tsessions[i]->internal;
  if (-1 != tcp6Session->sock)
    if (0 != SHUTDOWN(tcp6Session->sock, SHUT_RDWR))
      LOG(LOG_EVERYTHING,
	  "Error shutting down socket %d: %s\n",
	  tcp6Session->sock,
	  STRERROR(errno));
  CLOSE(tcp6Session->sock);
  tcp6Session->sock = -1;
  tcp6Disconnect(tsessions[i]);
  tsessions[i] = tsessions[--tsessionCount];
  tsessions[tsessionCount] = NULL;
}

/**
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in 
 * the config file.
 */
static unsigned short getGNUnetTCP6Port() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("TCP6",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("gnunet", "tcp6"))) 
      port = htons(pse->s_port);      
  }
  return port;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 * 
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
static int tcp6Associate(TSession * tsession) {
  TCP6Session * tcp6Session;

  GNUNET_ASSERT(tsession != NULL);
  tcp6Session = (TCP6Session*) tsession->internal;
  MUTEX_LOCK(&tcp6Session->lock);
  tcp6Session->users++;
  MUTEX_UNLOCK(&tcp6Session->lock);
  return OK;
}

/**
 * The socket of session i has data waiting, process!
 * 
 * This function may only be called if the tcp6lock is
 * already held by the caller.
 */
static int readAndProcess(int i) {
  TSession * tsession;
  TCP6Session * tcp6Session;
  unsigned int len;
  int ret;
  TCP6MessagePack * pack;
  MessagePack * mp;

  tsession = tsessions[i];
  if (SYSERR == tcp6Associate(tsession))
    return SYSERR;
  tcp6Session = tsession->internal;
  ret = RECV_NONBLOCKING(tcp6Session->sock,
			 &tcp6Session->rbuff[tcp6Session->pos],
	     tcp6Session->size - tcp6Session->pos);
  cronTime(&tcp6Session->lastUse);
  if (ret == 0) {
    tcp6Disconnect(tsession);
#if DEBUG_TCP6
    LOG(LOG_DEBUG,
	"READ on socket %d returned 0 bytes, closing connection\n",
	tcp6Session->sock);
#endif
    return SYSERR; /* other side closed connection */
  }
  if (ret < 0) {
    if ( (errno == EINTR) ||
	 (errno == EAGAIN) ) { 
#if DEBUG_TCP6
      LOG(LOG_DEBUG,
	  "READ on socket %d returned %s, closing connection\n",
	  tcp6Session->sock,
	  STRERROR(errno));
#endif
      tcp6Disconnect(tsession);
      return OK;    
    }
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"Read failed on peer tcp6 connection (%d), closing (%s).\n",
	ret,
	STRERROR(errno));
#endif
    tcp6Disconnect(tsession);
    return SYSERR;
  }
  incrementBytesReceived(ret);
  statChange(stat_octets_total_tcp6_in,
	     ret);
  tcp6Session->pos += ret;
  len = ntohs(((TCP6MessagePack*)&tcp6Session->rbuff[0])->size);
  if (len > tcp6Session->size) /* if MTU larger than expected, grow! */
    GROW(tcp6Session->rbuff,
	 tcp6Session->size,
	 len);
#if DEBUG_TCP6
  LOG(LOG_DEBUG,
      "Read %d bytes on socket %d, expecting %d for full message\n",
      tcp6Session->pos,
      tcp6Session->sock, 
      len);
#endif
  if ( (tcp6Session->pos < 2) ||
       (tcp6Session->pos < len) ) {
    tcp6Disconnect(tsession);
    return OK;
  }
 
  /* complete message received, let's check what it is */
  if (YES == tcp6Session->expectingWelcome) {
    TCP6Welcome * welcome;
#if DEBUG_TCP6
    EncName hex;
#endif
    
    welcome = (TCP6Welcome*) &tcp6Session->rbuff[0];
    if ( (ntohs(welcome->version) != 0) ||
	 (ntohs(welcome->size) != sizeof(TCP6Welcome)) ) {
      LOG(LOG_WARNING,
	  _("Expected welcome message on tcp connection, got garbage. Closing.\n"));
      tcp6Disconnect(tsession);
      return SYSERR;
    }
    tcp6Session->expectingWelcome = NO;
    memcpy(&tcp6Session->sender,
	   &welcome->clientIdentity,
	   sizeof(HostIdentity));     
#if DEBUG_TCP6
    IFLOG(LOG_DEBUG,
	  hash2enc(&tcp6Session->sender.hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"tcp6 welcome message from %s received\n",
	&enc);
#endif
    memmove(&tcp6Session->rbuff[0],
	    &tcp6Session->rbuff[sizeof(TCP6Welcome)],
	    tcp6Session->pos - sizeof(TCP6Welcome));
    tcp6Session->pos -= sizeof(TCP6Welcome); 
    len = ntohs(((TCP6MessagePack*)&tcp6Session->rbuff[0])->size);
  } 
  if ( (tcp6Session->pos < 2) ||
       (tcp6Session->pos < len) ) {
    tcp6Disconnect(tsession);
    return OK;
  }
     
  pack = (TCP6MessagePack*)&tcp6Session->rbuff[0];
  /* send msg to core! */
  if (len <= sizeof(TCP6MessagePack)) {
    LOG(LOG_WARNING,
	_("Received malformed message from tcp6-peer connection. Closing connection.\n"));
    tcp6Disconnect(tsession);
    return SYSERR;
  }
  mp      = MALLOC(sizeof(MessagePack));
  mp->msg = MALLOC(len);
  memcpy(mp->msg,
	 &pack->parts[0],
	 len - sizeof(TCP6MessagePack));
  memcpy(&mp->sender,
	 &tcp6Session->sender,
	 sizeof(HostIdentity));
  mp->crc         = ntohl(pack->checkSum);
  mp->isEncrypted = ntohs(pack->isEncrypted);
  mp->size        = len - sizeof(TCP6MessagePack);
  mp->tsession    = tsession;
#if DEBUG_TCP6
  LOG(LOG_DEBUG,
      "tcp6 transport received %d bytes, forwarding to core\n",
      mp->size);
#endif
  coreAPI->receive(mp);

  if (tcp6Session->pos < len) { 
    BREAK();
    tcp6Disconnect(tsession);
    return SYSERR;
  }
  /* finally, shrink buffer adequately */
  memmove(&tcp6Session->rbuff[0],
	  &tcp6Session->rbuff[len],
	  tcp6Session->pos - len);
  tcp6Session->pos -= len;	   
  
  tcp6Disconnect(tsession);
  return OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on tcp6lock before
 * calling.  It is ok to call this function without holding tcp6lock if
 * the return value is ignored.
 */
static int addTSession(TSession * tsession) {
  int i;

  MUTEX_LOCK(&tcp6lock);
  if (tsessionCount == tsessionArrayLength) 
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(&tcp6lock);
  return i;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void createNewSession(int sock) {
  TSession * tsession;
  TCP6Session * tcp6Session;

  tcp6Session = MALLOC(sizeof(TCP6Session));
  tcp6Session->pos = 0;
  tcp6Session->size = tcp6API.mtu + sizeof(TCP6MessagePack);
  tcp6Session->rbuff = MALLOC(tcp6Session->size);
  tcp6Session->wpos = 0;
  tcp6Session->wbuff = NULL;
  tcp6Session->sock = sock;
  /* fill in placeholder identity to mark that we 
     are waiting for the welcome message */
  memcpy(&tcp6Session->sender,
	 coreAPI->myIdentity,
	 sizeof(HostIdentity));
  tcp6Session->expectingWelcome = YES;
  MUTEX_CREATE_RECURSIVE(&tcp6Session->lock);
  tcp6Session->users = 1; /* us only, core has not seen this tsession! */
  cronTime(&tcp6Session->lastUse);
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = TCP6_PROTOCOL_NUMBER;
  tsession->internal = tcp6Session;
  addTSession(tsession);
}					 

/**
 * Main method for the thread listening on the tcp6 socket and all tcp6
 * connections. Whenever a message is received, it is forwarded to the
 * core. This thread waits for activity on any of the TCP6 connections
 * and processes deferred (async) writes and buffers reads until an
 * entire message has been received.
 */
static void * tcp6ListenMain() {
  struct sockaddr_in6 clientAddr;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  struct stat buf;
  int lenOfIncomingAddr;
  int i;
  int max;
  int ret;
  
  if (tcp6_sock != -1)
    if (0 != LISTEN(tcp6_sock, 5)) 
      LOG_STRERROR(LOG_ERROR, "listen");
  SEMAPHORE_UP(serverSignal); /* we are there! */
  MUTEX_LOCK(&tcp6lock);
  while (tcp6_shutdown == NO) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (tcp6_sock != -1) {
      if (isSocketValid(tcp6_sock)) {
	FD_SET(tcp6_sock, &readSet);
	FD_SET(tcp6_sock, &writeSet);
	FD_SET(tcp6_sock, &errorSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "isSocketValid");
	tcp6_sock = -1; /* prevent us from error'ing all the time */
      }
    } else
      LOG(LOG_DEBUG,
	  "TCP6 server socket not open!\n");
    if (tcp6_pipe[0] != -1) {
      if (-1 != FSTAT(tcp6_pipe[0], &buf)) {
	FD_SET(tcp6_pipe[0], &readSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "fstat");
	tcp6_pipe[0] = -1; /* prevent us from error'ing all the time */	
      }
    }
    max = tcp6_pipe[0];
    if (tcp6_sock > tcp6_pipe[0])
      max = tcp6_sock;
    for (i=0;i<tsessionCount;i++) {
      TCP6Session * tcp6Session = tsessions[i]->internal;
      int sock = tcp6Session->sock;
      if (sock != -1) {
	if (isSocketValid(sock)) {
	  FD_SET(sock, &readSet);
	  FD_SET(sock, &errorSet);
	  if (tcp6Session->wpos > 0)
	    FD_SET(sock, &writeSet); /* do we have a pending write request? */
	} else {
	  LOG_STRERROR(LOG_ERROR, "isSocketValid");
	  destroySession(i);
	}
      } else {
	BREAK();
	destroySession(i);
      }
      if (sock > max)
	max = sock;
    }    
    LOG(LOG_DEBUG,
	"Blocking on select!\n");
    MUTEX_UNLOCK(&tcp6lock);
    ret = SELECT(max+1, &readSet, &writeSet, &errorSet, NULL);    
    MUTEX_LOCK(&tcp6lock);
    LOG(LOG_DEBUG,
	"Select returned!\n");
    if ( (ret == -1) &&
	 ( (errno == EAGAIN) || (errno == EINTR) ) ) 
      continue;    
    if (ret == -1) {
      if (errno == EBADF) {
	LOG_STRERROR(LOG_ERROR, "select");
      } else {
	DIE_STRERROR("select");
      }
    }
    if (tcp6_sock != -1) {
      if (FD_ISSET(tcp6_sock, &readSet)) {
	int sock;
	
	LOG(LOG_DEBUG,
	    "accepting inbound connection\n");
	lenOfIncomingAddr = sizeof(clientAddr);               
	sock = ACCEPT(tcp6_sock, 
		      (struct sockaddr *)&clientAddr, 
		      &lenOfIncomingAddr);
	if (sock != -1) {	  
	  /* verify clientAddr for eligibility here (ipcheck-style,
	     user should be able to specify who is allowed to connect,
	     otherwise we just close and reject the communication! */  	  
	  GNUNET_ASSERT(sizeof(struct in6_addr) == sizeof(IP6addr));
	  if (YES == isBlacklisted((IP6addr*)&clientAddr.sin6_addr)) {
	    char * tmp = MALLOC(INET6_ADDRSTRLEN);
	    LOG(LOG_INFO,
		_("Rejected blacklisted connection from address %s.\n"),
		inet_ntop(AF_INET6,
			  &clientAddr,
			  tmp,
			  INET6_ADDRSTRLEN));
	    FREE(tmp);
	    SHUTDOWN(sock, 2);
	    CLOSE(sock);
	  } else 
	    createNewSession(sock);      
	} else {
	  LOG_STRERROR(LOG_INFO, "accept");
	}
      }
    }
    if (FD_ISSET(tcp6_pipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */

#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(tcp6_pipe[0], 
		    &buf[0], 
		    MAXSIG_BUF)) {
	LOG_STRERROR(LOG_WARNING, "read");
      }
    }
    for (i=0;i<tsessionCount;i++) {
      TCP6Session * tcp6Session = tsessions[i]->internal;
      int sock = tcp6Session->sock;
      if (FD_ISSET(sock, &readSet)) {
	if (SYSERR == readAndProcess(i)) {
	  destroySession(i);
	  i--;
	  continue;
	}
      }
      if (FD_ISSET(sock, &writeSet)) {
	int ret;

	ret = SEND_NONBLOCKING(sock,
			       tcp6Session->wbuff,
			       tcp6Session->wpos);
	if (ret == SYSERR) {
	  LOG_STRERROR(LOG_WARNING, "send");
	  destroySession(i);
	  i--;
	  continue;
	}
	if (ret == 0) {
          /* send only returns 0 on error (other side closed connection),
	   * so close the session */
	  destroySession(i);
	  i--;
	  continue;
	}
	if ((unsigned int)ret == tcp6Session->wpos) {
	  FREENONNULL(tcp6Session->wbuff);
	  tcp6Session->wbuff = NULL;
	  tcp6Session->wpos = 0;
	} else {
	  memmove(tcp6Session->wbuff,
		  &tcp6Session->wbuff[ret],
		  tcp6Session->wpos - ret);
	  tcp6Session->wpos -= ret;
	}
      }
      if (FD_ISSET(sock, &errorSet)) {
	destroySession(i);
	i--;
	continue;
      }
      if ( ( tcp6Session->users == 1) &&
	   (cronTime(NULL) > tcp6Session->lastUse + TCP6_TIMEOUT) ) {
	destroySession(i);
	i--;
	continue;
      }
    }
  }
  /* shutdown... */
  if (tcp6_sock != -1) {
    CLOSE(tcp6_sock);
    tcp6_sock = -1;
  }
  /* close all sessions */
  while (tsessionCount > 0) 
    destroySession(0);
  MUTEX_UNLOCK(&tcp6lock);
  SEMAPHORE_UP(serverSignal); /* we are there! */
  return NULL;
} /* end of tcp6 listen main */

/**
 * Send a message (already encapsulated if needed) via the
 * tcp6 socket (or enqueue if sending now would block).
 *
 * @param tcp6Session the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, SYSERR if queue is full and
 * message was dropped.
 */
static int tcp6DirectSend(TCP6Session * tcp6Session,
			  void * mp,
			  unsigned int ssize) {
  int ok;
  int ret;

  if (tcp6Session->sock == -1) {
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"tcp6DirectSend called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    BREAK();
    return SYSERR;
  }
  if (ssize > tcp6API.mtu + sizeof(TCP6MessagePack)) {
    BREAK();
    return SYSERR;
  }
  ok = SYSERR;
  MUTEX_LOCK(&tcp6lock);
  if (tcp6Session->wpos > 0) {
    ret = 0;
  } else {
    ret = SEND_NONBLOCKING(tcp6Session->sock,
			   mp,
			   ssize);
  }
  if (ret == SYSERR) {
    if ( (errno == EAGAIN) ||
	 (errno == EWOULDBLOCK)) {
      LOG_STRERROR(LOG_DEBUG, "send");
      ret = 0;
    } else {
      LOG_STRERROR(LOG_INFO, "send");
      MUTEX_UNLOCK(&tcp6lock);
      return SYSERR;
    }
  }
  if ((unsigned int) ret <= ssize) { /* some bytes send or blocked */
    if ((unsigned int)ret < ssize) {
      if (tcp6Session->wbuff == NULL) {
	tcp6Session->wbuff = MALLOC(tcp6API.mtu + sizeof(TCP6MessagePack));
	tcp6Session->wpos = 0;
      }
      if ((unsigned int) (ssize - ret) > 
	  tcp6API.mtu + sizeof(TCP6MessagePack) - tcp6Session->wpos) {
	ssize = 0;
	ok = SYSERR; /* buffer full, drop */
      } else {
	memcpy(&tcp6Session->wbuff[tcp6Session->wpos],
	       mp,
	       ssize - ret);
	tcp6Session->wpos += ssize - ret;
	if (tcp6Session->wpos == ssize - ret)
	  signalSelect(); /* select set changed! */
	ok = OK; /* all buffered */
      }      
    } else 
      ok = OK; /* all written */
  } else {
    LOG_STRERROR(LOG_WARNING, "send");
    ssize = 0;
    ok = SYSERR; /* write failed for real */
  }
  MUTEX_UNLOCK(&tcp6lock);
  cronTime(&tcp6Session->lastUse);
  incrementBytesSent(ssize);
  statChange(stat_octets_total_tcp6_out,
	     ssize);
  return ok;
}


/**
 * Send a message (already encapsulated if needed) via the
 * tcp6 socket.  Block if required.
 *
 * @param tcp6Session the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, SYSERR if queue is full and
 * message was dropped.
 */
static int tcp6DirectSendReliable(TCP6Session * tcp6Session,
				  void * mp,
				  unsigned int ssize) {
  int ok;

  if (tcp6Session->sock == -1) {
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"tcp6DirectSendReliable called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    BREAK();
    return SYSERR;
  }
  if (ssize > tcp6API.mtu + sizeof(TCP6MessagePack)) {
    BREAK();
    return SYSERR;
  }
  MUTEX_LOCK(&tcp6lock);
  if (tcp6Session->wpos > 0) {
    unsigned int old = tcp6Session->wpos;
    /* reliable: grow send-buffer above limit! */
    GROW(tcp6Session->wbuff,
	 tcp6Session->wpos,
	 tcp6Session->wpos + ssize);
    memcpy(&tcp6Session->wbuff[old],
	   mp,
	   ssize);    
    ok = OK;
  } else {
    ok = tcp6DirectSend(tcp6Session,
			mp,
			ssize);
  }
  MUTEX_UNLOCK(&tcp6lock);
  return ok;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the HELO_Message identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @param isEncrypted is the message encrypted (YES/NO)
 * @param crc CRC32 of the plaintext
 * @return SYSERR on error, OK on success
 */
static int tcp6SendReliable(TSession * tsession,
			   const void * msg,
			   const unsigned int size,
			   int isEncrypted,
			   const int crc) {
  TCP6MessagePack * mp;
  int ok;
  int ssize;
  
  if (tcp6_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (size > tcp6API.mtu) {
    BREAK();
    return SYSERR;
  }
  if (((TCP6Session*)tsession->internal)->sock == -1)
    return SYSERR; /* other side closed connection */
  mp = MALLOC(sizeof(TCP6MessagePack) + size);
  mp->checkSum = htonl(crc);
  mp->isEncrypted = htons(isEncrypted);
  memcpy(&mp->parts[0],
	 msg,
	 size);
  ssize = size + sizeof(TCP6MessagePack);
  mp->size = htons(ssize);
  
  ok = tcp6DirectSendReliable(tsession->internal,
			     mp,
			     ssize);
  FREE(mp);
  return ok;
}


/**
 * Verify that a HELO-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success. 
 * @param helo the HELO message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const HELO_Message * helo) {
  Host6Address * haddr;

  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];
  if ( (ntohs(helo->senderAddressSize) != sizeof(Host6Address)) ||
       (ntohs(helo->header.size) != HELO_Message_size(helo)) ||
       (ntohs(helo->header.requestType) != p2p_PROTO_HELO) ||
       (ntohs(helo->protocol) != TCP6_PROTOCOL_NUMBER) ||
       (YES == isBlacklisted(&haddr->ip)) )
    return SYSERR; /* obviously invalid */
  else
    return OK;
}

/**
 * Create a HELO-Message for the current node. The HELO is
 * created without signature and without a timestamp. The
 * GNUnet core will sign the message and add an expiration time. 
 *
 * @param helo address where to store the pointer to the HELO
 *        message
 * @return OK on success, SYSERR on error
 */
static int createHELO(HELO_Message ** helo) {
  HELO_Message * msg;
  Host6Address * haddr;
  unsigned short port;

  port = getGNUnetTCP6Port();
  if (0 == port) {
    LOG(LOG_DEBUG,
	"TCP6 port is 0, will only send using TCP6\n");
    return SYSERR; /* TCP6 transport is configured SEND-only! */
  }
  msg = (HELO_Message *) MALLOC(sizeof(HELO_Message) + sizeof(Host6Address));
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)msg)->senderAddress[0];

  if (SYSERR == getPublicIP6Address(&haddr->ip)) {
    FREE(msg);
    LOG(LOG_WARNING,
	_("Could not determine my public IPv6 address.\n"));
    return SYSERR;
  }
  haddr->port = htons(port); 
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(Host6Address));
  msg->protocol = htons(TCP6_PROTOCOL_NUMBER);
  msg->MTU = htonl(tcp6API.mtu);
  *helo = msg;
  return OK;
}

/**
 * Establish a connection to a remote node.
 *
 * @param helo the HELO-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int tcp6Connect(HELO_Message * helo,
		       TSession ** tsessionPtr) {
  int i;
  Host6Address * haddr;
  TCP6Welcome welcome;
  int sock;
  TSession * tsession;
  TCP6Session * tcp6Session;
  char * hostname;
  struct addrinfo hints, *res, *res0;
  int rtn;

#if DEBUG_TCP6
  char * tmp;
#endif

  if (tcp6_shutdown == YES)
    return SYSERR;
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hostname = MALLOC(INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6,
	    haddr,
	    hostname,
	    INET6_ADDRSTRLEN);
  rtn = getaddrinfo(hostname, NULL, &hints, &res0);
  FREE(hostname);
  if (rtn != 0) {    
    LOG(LOG_WARNING,	
	_("'%s': unknown service: %s\n"), 
	__FUNCTION__,
	gai_strerror(rtn));
    return SYSERR;
  }

#if DEBUG_TCP6
  tmp = MALLOC(INET6_ADDRSTRLEN);
  LOG(LOG_DEBUG,
      "creating TCP6 connection to %s:%d\n",
      inet_ntop(AF_INET6,
		haddr,
		tmp,
		INET6_ADDRSTRLEN), 
      ntohs(haddr->port));
  FREE(tmp);
#endif

  sock = -1;
  for (res=res0; res; res=res->ai_next) {
    if (res->ai_family != PF_INET6)
      continue;
    sock = SOCKET(res->ai_family, 
		  res->ai_socktype, 
		  res->ai_protocol);
    if (sock < 0)
      continue;
    if (0 != setBlocking(sock, NO)) {
      CLOSE(sock);
      LOG_STRERROR(LOG_FAILURE, "setBlocking");
      return SYSERR;
    }
    ((struct sockaddr_in6*)(res->ai_addr))->sin6_port 
      = haddr->port;
    if ( (CONNECT(sock, 
		  res->ai_addr, 
		  res->ai_addrlen) < 0) &&
	 (errno != EINPROGRESS) ) {
      LOG_STRERROR(LOG_WARNING, "connect");
      CLOSE(sock);
      sock = -1;
      continue;
    }
    break;
  }
  freeaddrinfo(res0);
  if (sock == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }
  if (0 != setBlocking(sock, NO)) {
    LOG_STRERROR(LOG_FAILURE, "setBlocking");
    CLOSE(sock);
    return SYSERR;
  }

  tcp6Session = MALLOC(sizeof(TCP6Session));
  tcp6Session->sock = sock;
  tcp6Session->wpos = 0;
  tcp6Session->wbuff = NULL;
  tcp6Session->size = tcp6API.mtu + sizeof(TCP6MessagePack);
  tcp6Session->rbuff = MALLOC(tcp6Session->size);
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcp6Session;
  tsession->ttype = tcp6API.protocolNumber;
  MUTEX_CREATE_RECURSIVE(&tcp6Session->lock);
  tcp6Session->users = 2; /* caller + us */
  tcp6Session->pos = 0;
  cronTime(&tcp6Session->lastUse);
  memcpy(&tcp6Session->sender,
	 &helo->senderIdentity,
	 sizeof(HostIdentity));
  tcp6Session->expectingWelcome = NO;
  MUTEX_LOCK(&tcp6lock);
  i = addTSession(tsession);

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.size = htons(sizeof(TCP6Welcome));
  welcome.version = htons(0);
  memcpy(&welcome.clientIdentity,
	 coreAPI->myIdentity,
	 sizeof(HostIdentity));
  if (SYSERR == tcp6DirectSend(tcp6Session,
			       &welcome,
			       sizeof(TCP6Welcome))) {
    destroySession(i);
    tcp6Disconnect(tsession);
    MUTEX_UNLOCK(&tcp6lock);
    return SYSERR;
  }
  MUTEX_UNLOCK(&tcp6lock);
  signalSelect();
  
  *tsessionPtr = tsession;
  FREE(helo);
  return OK;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the HELO_Message identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @param isEncrypted is the message encrypted (YES/NO)
 * @param crc CRC32 of the plaintext
 * @return SYSERR on error, OK on success
 */
static int tcp6Send(TSession * tsession,
		    const void * msg,
		    const unsigned int size,
		    int isEncrypted,
		    const int crc) {
  TCP6MessagePack * mp;
  int ok;
  int ssize;
  
  if (tcp6_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (size > tcp6API.mtu) {
    BREAK();
    return SYSERR;
  }
  if (((TCP6Session*)tsession->internal)->sock == -1)
    return SYSERR; /* other side closed connection */
  mp = MALLOC(sizeof(TCP6MessagePack) + size);
  mp->checkSum = htonl(crc);
  mp->isEncrypted = htons(isEncrypted);
  memcpy(&mp->parts[0],
	 msg,
	 size);
  ssize = size + sizeof(TCP6MessagePack);
  mp->size = htons(ssize);
  
  ok = tcp6DirectSend(tsession->internal,
		      mp,
		      ssize);
  FREE(mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  struct sockaddr_in6 serverAddr;
  const int on = 1;
  unsigned short port;
  int flags;
  
  GNUNET_ASSERT(serverSignal == NULL);
  serverSignal = SEMAPHORE_NEW(0);
  tcp6_shutdown = NO;
    
  if (0 != PIPE(tcp6_pipe)) {
    LOG_STRERROR(LOG_ERROR, "pipe");
    return SYSERR;
  }
  flags = fcntl(tcp6_pipe[1], F_GETFL, 0);
  fcntl(tcp6_pipe[1], F_SETFL, flags | O_NONBLOCK);
 
  port = getGNUnetTCP6Port();
  if (port != 0) { /* if port == 0, this is a read-only
		      business! */
    tcp6_sock = SOCKET(PF_INET6, 
		       SOCK_STREAM, 
		       0);   
    if (tcp6_sock < 0) 
      DIE_STRERROR("socket");
    if ( SETSOCKOPT(tcp6_sock,
		    SOL_SOCKET, 
		    SO_REUSEADDR, 
		    &on, 
		    sizeof(on)) < 0 ) 
      DIE_STRERROR("setsockopt");
    memset((char *) &serverAddr, 
	   0,
	   sizeof(serverAddr));
    serverAddr.sin6_family   = AF_INET6;
    serverAddr.sin6_flowinfo = 0;
    serverAddr.sin6_addr     = in6addr_any;
    serverAddr.sin6_port     = htons(getGNUnetTCP6Port());
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"starting tcp6 peer server on port %d\n",
	ntohs(serverAddr.sin6_port));
#endif
    if (BIND(tcp6_sock, 
	     (struct sockaddr *) &serverAddr,
	     sizeof(serverAddr)) < 0) {
      LOG_STRERROR(LOG_ERROR, "bind");
      LOG(LOG_ERROR,
	  _("Failed to start transport service on port %d.\n"),
	  getGNUnetTCPPort());
      CLOSE(tcp6_sock);
      tcp6_sock = -1;
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
  } else
    tcp6_sock = -1;
  if (0 == PTHREAD_CREATE(&listenThread, 
			  (PThreadMain) &tcp6ListenMain,
			  NULL,
			  2048)) {
      SEMAPHORE_DOWN(serverSignal); /* wait for server to be up */      
  } else {
    LOG_STRERROR(LOG_FAILURE, "pthread_create");
    CLOSE(tcp6_sock);
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    return SYSERR;
  }
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  void * unused;
  int haveThread;

  tcp6_shutdown = YES;  
  signalSelect();
  if (serverSignal != NULL) {
    haveThread = YES;
    SEMAPHORE_DOWN(serverSignal);
    SEMAPHORE_FREE(serverSignal);
  } else
    haveThread = NO;
  serverSignal = NULL; 
  CLOSE(tcp6_pipe[1]);
  CLOSE(tcp6_pipe[0]);
  if (tcp6_sock != -1) {
    CLOSE(tcp6_sock);
    tcp6_sock = -1;
  }
  if (haveThread == YES)
    PTHREAD_JOIN(&listenThread, &unused);
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static void reloadConfiguration(void) {
  char * ch;

  MUTEX_LOCK(&tcp6lock);
  FREENONNULL(filteredNetworks_);
  ch = getConfigurationString("TCP6",
			      "BLACKLIST");
  if (ch == NULL)
    filteredNetworks_ = parseRoutes6("");
  else {
    filteredNetworks_ = parseRoutes6(ch);
    FREE(ch);
  }
  MUTEX_UNLOCK(&tcp6lock);
}

/**
 * Convert TCP6 address to a string.
 */
static char * addressToString(const HELO_Message * helo) {
  char * ret;
  char * tmp;
  Host6Address * haddr;
  
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];  
  ret = MALLOC(INET6_ADDRSTRLEN+16);
  tmp = MALLOC(INET6_ADDRSTRLEN);  
  SNPRINTF(ret,
	   INET6_ADDRSTRLEN+16,
	   "%s:%d (TCP6)",
	   inet_ntop(AF_INET6,
		     haddr,
		     tmp,
		     INET6_ADDRSTRLEN), 
	   ntohs(haddr->port));
  FREE(tmp);
  return ret;
}

 
/* ******************** public API ******************** */
 
/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */ 
TransportAPI * inittransport_tcp6(CoreAPIForTransport * core) {
  int mtu;

  MUTEX_CREATE_RECURSIVE(&tcp6lock);
  reloadConfiguration();
  tsessionCount = 0;
  tsessionArrayLength = 32;
  tsessions = MALLOC(sizeof(TSession*) * tsessionArrayLength);
  coreAPI = core;
  stat_octets_total_tcp6_in 
    = statHandle(_("# bytes received via tcp6"));
  stat_octets_total_tcp6_out 
    = statHandle(_("# bytes sent via tcp6"));
  mtu = getConfigurationInt("TCP6",
			    "MTU");
  if (mtu == 0)
    mtu = 1440;
  if (mtu < 1200)
    LOG(LOG_ERROR,
	_("MTU for '%s' is probably too low (fragmentation not implemented!)\n"),
	"TCP6");
 
  tcp6API.protocolNumber       = TCP6_PROTOCOL_NUMBER;
  tcp6API.mtu                  = mtu - sizeof(TCP6MessagePack);
  tcp6API.cost                 = 19950; /* about equal to udp6 */
  tcp6API.verifyHelo           = &verifyHelo;
  tcp6API.createHELO           = &createHELO;
  tcp6API.connect              = &tcp6Connect;
  tcp6API.associate            = &tcp6Associate;
  tcp6API.send                 = &tcp6Send;
  tcp6API.sendReliable         = &tcp6SendReliable;
  tcp6API.disconnect           = &tcp6Disconnect;
  tcp6API.startTransportServer = &startTransportServer;
  tcp6API.stopTransportServer  = &stopTransportServer;
  tcp6API.reloadConfiguration  = &reloadConfiguration;
  tcp6API.addressToString      = &addressToString;

  return &tcp6API;
}

void donetransport_tcp6() {
  int i;

  for (i=0;i<tsessionCount;i++)
    LOG(LOG_DEBUG,
	"tsessions array still contains %p\n",
	tsessions[i]);
  FREE(tsessions);
  tsessions = NULL;
  tsessionArrayLength = 0;
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(&tcp6lock);
}

/* end of tcp6.c */
