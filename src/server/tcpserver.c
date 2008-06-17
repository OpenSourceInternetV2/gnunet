/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/tcpserver.c
 * @brief TCP server (gnunetd-client communication using util/tcpio.c).
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "tcpserver.h"
#include "handler.h"

#define DEBUG_TCPHANDLER NO

/**
 * Array of the message handlers.
 **/
static CSHandler * handlers = NULL;

/**
 * Number of handlers in the array (max, there
 * may be NULL pointers in it!)
 **/
static int max_registeredType = 0;

/**
 * Mutex to guard access to the handler array.
 **/
static Mutex handlerlock;

/**
 * Mutex to guard access to the client list.
 **/
static Mutex clientlock;

#if VERBOSE_STATS
static int octets_total_tcp_in;
static int octets_total_tcp_out;
#endif

/**
 * The thread that waits for new connections.
 **/
static PTHREAD_T TCPLISTENER_listener_;

/**
 * Pipe to communicate with select thread
 */
static int signalingPipe[2];

/**
 * Handlers to call if client exits.
 **/
static ClientExitHandler * exitHandlers = NULL;

/**
 * How many entries are in exitHandlers?
 */
static int exitHandlerCount = 0;

/**
 * Signals for control-thread to server-thread communication
 **/
static Semaphore * serverSignal = NULL;

/**
 * Should the select-thread exit?
 */
static int tcpserver_keep_running = NO;

/**
 * Per-client data structure (kept in linked list).  Also: the opaque
 * handle for client connections passed by the core to the CSHandlers.
 */
typedef struct ClientH {
  /**
   * Socket to communicate with the client.
   */
  int sock;

  char * readBuffer;
  unsigned int readBufferPos;
  unsigned int readBufferSize;

  char * writeBuffer;
  unsigned int writeBufferSize;

  CS_HEADER ** writeQueue;
  unsigned int writeQueueSize;

  ClientHandle next;
} ClientThreadHandle;


/**
 * Start of the linked list of client structures.
 */
static ClientHandle clientList = NULL;

static void signalSelect() {
  char i = 0;
  int ret;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: signaling select.\n");
#endif
  ret = WRITE(signalingPipe[1], 
	      &i, 
	      sizeof(char));
  if (ret != sizeof(char)) {
    if (errno != EAGAIN)
      LOG(LOG_ERROR,
	  "ERROR: write to tcp-server pipe (signalSelect) failed: %s\n",
	  STRERROR(errno));
  }
}

int registerClientExitHandler(ClientExitHandler callback) {
  MUTEX_LOCK(&handlerlock);
  GROW(exitHandlers,
       exitHandlerCount,
       exitHandlerCount+1);
  exitHandlers[exitHandlerCount-1] = callback;
  MUTEX_UNLOCK(&handlerlock);
  return OK;
}

/**
 * The client identified by 'session' has disconnected.  Close the
 * socket, free the buffers, unlink session from the linked list.
 */
static void destroySession(ClientHandle session) {
  ClientHandle prev;
  ClientHandle pos;
  int i;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: destroying session %d\n",
      session);
#endif
  /* avoid deadlock: give up the lock while
     the client is processing; since only (!) the
     select-thread can possibly free handle/readbuffer,
     releasing the lock here is safe. */
  MUTEX_UNLOCK(&clientlock);
  MUTEX_LOCK(&handlerlock);
  for (i=0;i<exitHandlerCount;i++) 
    exitHandlers[i](session);  
  MUTEX_UNLOCK(&handlerlock);
  MUTEX_LOCK(&clientlock);
  prev = NULL;
  pos = clientList;
  while (pos != session) {
    if (pos == NULL)
      errexit("FATAL: assertion violated: pos == NULL\n");
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL)
    clientList = session->next;
  else
    prev->next = session->next;
  close(session->sock);
  GROW(session->writeBuffer,
       session->writeBufferSize,
       0);
  GROW(session->readBuffer,
       session->readBufferSize,
       0);
  for (i=session->writeQueueSize-1;i>=0;i--)
    FREE(session->writeQueue[i]);
  GROW(session->writeQueue,
       session->writeQueueSize,
       0);
  FREE(session);
}
  
int unregisterClientExitHandler(ClientExitHandler callback) {
  int i;

  MUTEX_LOCK(&handlerlock);
  for (i=0;i<exitHandlerCount;i++) {
    if (exitHandlers[i] == callback) {
      exitHandlers[i] = exitHandlers[exitHandlerCount-1];
      GROW(exitHandlers,
	   exitHandlerCount,
	   exitHandlerCount-1);
      MUTEX_UNLOCK(&handlerlock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&handlerlock);
  return SYSERR;
}

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return SYSERR if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
int sendToClient(ClientHandle handle,
		 CS_HEADER * message) {
  CS_HEADER * cpy;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: sending message to client %d\n",
      handle);
#endif
  cpy = MALLOC(ntohs(message->size));
  memcpy(cpy, message, ntohs(message->size));
  MUTEX_LOCK(&clientlock);
  GROW(handle->writeQueue,
       handle->writeQueueSize,
       handle->writeQueueSize+1);
  handle->writeQueue[handle->writeQueueSize-1] = cpy;
  MUTEX_UNLOCK(&clientlock);
  signalSelect();
  return OK;
}

/**
 * Handle a message (that was decrypted if needed).
 * Checks the CRC and if that's ok, processes the
 * message by calling the registered handler for
 * each message part.
 **/
static int processHelper(CS_HEADER * msg,
			 ClientHandle sender) {
  unsigned short ptyp;
  CSHandler callback;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: processing message from %d\n",
      sender);
#endif
  ptyp = htons(msg->tcpType);
  MUTEX_LOCK(&handlerlock);
  if (ptyp >= max_registeredType) {
    LOG(LOG_INFO, 
	"INFO: processHelper: Message not understood: %d (no handler registered, max is %d)\n",
	ptyp, 
	max_registeredType);
    MUTEX_UNLOCK(&handlerlock);
    destroySession(sender);
    return SYSERR;
  }
  callback = handlers[ptyp];
  if (callback == NULL) {
    LOG(LOG_INFO, 
	"INFO: processHelper: Message not understood: %d (no handler registered)!\n",
	ptyp);
    MUTEX_UNLOCK(&handlerlock);
    return SYSERR;
  } else
    callback(sender,
	     msg);
  MUTEX_UNLOCK(&handlerlock);
  return OK;
}

/**
 * Handle data available on the TCP socket descriptor. This method
 * first aquires a slot to register this socket for the writeBack
 * method (@see writeBack) and then demultiplexes all TCP traffic
 * received to the appropriate handlers.  
 * @param sockDescriptor the socket that we are listening to (fresh)
 **/
static int readAndProcess(ClientHandle handle) {
  unsigned int len;
  int ret;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: reading from client %d\n",
      handle);
#endif
  ret = READ(handle->sock,
	     &handle->readBuffer[handle->readBufferPos],
	     handle->readBufferSize - handle->readBufferPos);
  if (ret == 0) {
#if DEBUG_TCPHANDLER
    LOG(LOG_DEBUG,
	"DEBUG: read 0 bytes from client %d (socket %d). Closing.\n",
	handle,
	handle->sock);
#endif
    return SYSERR; /* other side closed connection */
  }
  if (ret < 0) {
    if ( (errno == EINTR) ||
	 (errno == EAGAIN) ) 
      return OK;        
    LOG(LOG_WARNING,
	"WARNING: error reading from client: %s\n",
	STRERROR(errno));
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(octets_total_tcp_in,
	     ret);
#endif
  handle->readBufferPos += ret;
  if (handle->readBufferPos < sizeof(CS_HEADER))
    return OK;
  len = ntohs(((CS_HEADER*)handle->readBuffer)->size);
  if (len > handle->readBufferSize) /* if MTU larger than expected, grow! */
    GROW(handle->readBuffer,
	 handle->readBufferSize,
	 len);
  if (handle->readBufferPos < len) 
    return OK;  
  /* avoid deadlock: give up the lock while
     the client is processing; since only (!) the
     select-thread can possibly free handle/readbuffer,
     releasing the lock here is safe. */
  MUTEX_UNLOCK(&clientlock);
  ret = processHelper((CS_HEADER*)handle->readBuffer,
		      handle);
  MUTEX_LOCK(&clientlock);
  /* finally, shrink buffer adequately */
  memcpy(&handle->readBuffer[0],
	 &handle->readBuffer[len],
	 handle->readBufferPos - len);
  handle->readBufferPos -= len;	   
  if (ret == SYSERR)
    destroySession(handle);
  return OK;
}

/**
 * Initialize the TCP port and listen for incoming connections.
 **/
static void * tcpListenMain() {
  int max;
  int ret;
  int listenerFD;
  int lenOfIncomingAddr;
  int listenerPort;
  struct sockaddr_in serverAddr, clientAddr;
  int secs = 5;
  const int on = 1;
  ClientHandle pos;
  struct stat buf;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;

  listenerPort = getGNUnetPort(); 
  /* create the socket */
 CREATE_SOCKET:
  while ( (listenerFD = SOCKET(PF_INET,
			       SOCK_STREAM,
			       0)) < 0) {
    LOG(LOG_ERROR, 
	"ERROR opening socket (%s). No client service started. Trying again in 30 seconds.\n",
	STRERROR(errno));
    sleep(30);
  }
  
  /* fill in the inet address structure */
  memset((char *) &serverAddr,
	 0,
	 sizeof(serverAddr));
  serverAddr.sin_family 
    = AF_INET;
  serverAddr.sin_addr.s_addr
    = htonl(INADDR_ANY);
  serverAddr.sin_port
    = htons(listenerPort);
 
  if ( SETSOCKOPT(listenerFD, 
		  SOL_SOCKET, 
		  SO_REUSEADDR, 
		  &on, sizeof(on)) < 0 )
    perror("setsockopt");

  /* bind the socket */
  if (BIND(listenerFD, 
	   (struct sockaddr *) &serverAddr,
	   sizeof(serverAddr)) < 0) {
    LOG(LOG_ERROR, 
	"ERROR (%s) binding the TCP listener to port %d. No proxy service started.\nTrying again in %d seconds...\n",
	STRERROR(errno),
	listenerPort, 
	secs);
    sleep(secs);
    secs += 5; /* slow progression... */
    CLOSE(listenerFD);
    goto CREATE_SOCKET;
  }
  
  /* start listening for new connections */
  LISTEN(listenerFD, 5); /* max: 5 pending, unhandled connections */
  SEMAPHORE_UP(serverSignal); 

  MUTEX_LOCK(&clientlock);
  /* process incoming data */
  while (tcpserver_keep_running == YES) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (-1 != FSTAT(listenerFD, &buf)) {
      FD_SET(listenerFD, &readSet);
    } else {
      errexit("ERROR: tcp-server socket invalid: %s\n",
	      STRERROR(errno));
    }
    if (-1 != FSTAT(signalingPipe[0], &buf)) {
      FD_SET(signalingPipe[0], &readSet);
    } else {
      errexit("ERROR: signalingPipe invalid: %s\n",
	      STRERROR(errno));
    }
    max = signalingPipe[0];
    if (listenerFD > max)
      max = listenerFD;
    pos = clientList;
    while (pos != NULL) {
      int sock = pos->sock;
      if (-1 != FSTAT(sock, &buf)) {
	FD_SET(sock, &errorSet);
	if ( (pos->writeBufferSize > 0) ||
	     (pos->writeQueueSize > 0) ) 
	  FD_SET(sock, &writeSet); /* we have a pending write request? */
	else
	  FD_SET(sock, &readSet); /* ONLY read if no writes are pending! */
	if (sock > max)
	  max = sock;
      } else {
	ClientHandle ch;
	LOG(LOG_ERROR,
	    "ERROR: sock %d invalid: %s -- closing.\n",
	    sock, 
	    STRERROR(errno));
	ch = pos->next;
	destroySession(pos);
	pos = ch;
	continue;
      }
      pos = pos->next;
    }  
    MUTEX_UNLOCK(&clientlock);
    ret = SELECT(max+1, 
		 &readSet,
		 &writeSet,
		 &errorSet,
		 NULL);    
    MUTEX_LOCK(&clientlock);
    if ( (ret == -1) &&
	 ( (errno == EAGAIN) || (errno == EINTR) ) ) 
      continue;    
    if (ret == -1) {
      if (errno == EBADF) {
	LOG(LOG_ERROR,
	    "ERROR: %s in tcpserver select.\n",
	    STRERROR(errno));
      } else {
	errexit("FATAL: unexpected error in tcpserver select: %s (that's the end)\n",
		STRERROR(errno));
      }
    }
    if (FD_ISSET(listenerFD, &readSet)) {
      int sock;
      
      lenOfIncomingAddr = sizeof(clientAddr);
      sock = ACCEPT(listenerFD, 
		    (struct sockaddr *)&clientAddr, 
		    &lenOfIncomingAddr);
      if (sock != -1) {	  
	/* verify clientAddr for eligibility here (ipcheck-style,
	   user should be able to specify who is allowed to connect,
	   otherwise we just close and reject the communication! */  

	IPaddr ipaddr;
	if (sizeof(struct in_addr) != sizeof(IPaddr))
	  errexit("FATAL: assertion failed at %s:%d\n",
		  __FILE__, __LINE__);
	memcpy(&ipaddr,
	       &clientAddr.sin_addr,
	       sizeof(struct in_addr));

	if (NO == isWhitelisted(ipaddr)) {
	  LOG(LOG_WARNING,
	      "WARNING: Rejected unauthorized connection from %d.%d.%d.%d.\n",
	      PRIP(ntohl(*(int*)&clientAddr.sin_addr)));
	  CLOSE(sock);
	} else {
	  ClientHandle ch
	    = MALLOC(sizeof(ClientThreadHandle));
#if DEBUG_TCPHANDLER
	  LOG(LOG_DEBUG,
	      "DEBUG: accepting connection from %d.%d.%d.%d (socket: %d).\n",
	      PRIP(ntohl(*(int*)&clientAddr.sin_addr)),
	      sock);
#endif
	  ch->sock = sock;
	  ch->readBufferSize = 2048;
	  ch->readBuffer = MALLOC(ch->readBufferSize);
	  ch->readBufferPos = 0;
	  ch->writeBuffer = NULL;
	  ch->writeBufferSize = 0;
	  ch->writeQueue = NULL;
	  ch->writeQueueSize = 0;
	  ch->next = clientList;
	  clientList = ch;
	}
      } else {
	LOG(LOG_INFO,
	    "INFO: CS TCP server accept failed: %s\n",
	    STRERROR(errno));
      }
    }
    
    if (FD_ISSET(signalingPipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */

#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];

#if DEBUG_TCPHANDLER
	  LOG(LOG_DEBUG,
	      "DEBUG: tcpserver eats signal\n");
#endif
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(signalingPipe[0], 
		    &buf[0], 
		    MAXSIG_BUF)) {
	LOG(LOG_WARNING,
	    "WARNING: reading signal on TCP pipe failed (%s)\n",
	    STRERROR(errno));
      }
    }

    pos = clientList;
    while (pos != NULL) {
      int sock = pos->sock;
      if (FD_ISSET(sock, &readSet)) {
#if DEBUG_TCPHANDLER
	LOG(LOG_DEBUG,
	    "DEBUG: tcpserver reads from %d (socket %d)\n",
	    pos,
	    sock);
#endif
	if (SYSERR == readAndProcess(pos)) {
	  ClientHandle ch
	    = pos->next;
	  destroySession(pos); 
	  pos = ch;
	  continue;
	}
      }
      if (FD_ISSET(sock, &writeSet)) {
	int ret;
	
#if DEBUG_TCPHANDLER
	  LOG(LOG_DEBUG,
	      "DEBUG: tcpserver writes to %d\n",
	      pos);
#endif
	if (pos->writeBufferSize == 0) {
	  if (pos->writeQueueSize > 0) {
	    unsigned int len;
	    len = ntohs(pos->writeQueue[0]->size);
	    pos->writeBuffer = (char*)pos->writeQueue[0];
	    pos->writeBufferSize = len;
	    for (len=0;len<pos->writeQueueSize-1;len++)
	      pos->writeQueue[len] = pos->writeQueue[len+1];
	    GROW(pos->writeQueue,
		 pos->writeQueueSize,
		 pos->writeQueueSize-1);
	  } else {
	    LOG(LOG_WARNING,
		"WARNING: assertion failed: entry in write set but no messages pending!\n");
	  }
	}
	ret = SEND_NONBLOCKING(sock,
			       pos->writeBuffer,
			       pos->writeBufferSize);
	if (ret == SYSERR) {
	  ClientHandle ch
	    = pos->next;
	  LOG(LOG_WARNING,
	      "WARNING: send failed on socket %d (%s), closing session.\n",
	      sock, 
	      STRERROR(errno));
	  destroySession(pos);
	  pos = ch;
	  continue;
	}
	if (ret == 0) {
	  ClientHandle ch
	    = pos->next;
          /* send only returns 0 on error (other side closed connection),
	     so close the session */
	  destroySession(pos); 
	  pos = ch;
	  continue;
	}
#if VERBOSE_STATS
	statChange(octets_total_tcp_out,
		   ret);
#endif
	if ((unsigned int)ret == pos->writeBufferSize) {
	  FREENONNULL(pos->writeBuffer);
	  pos->writeBuffer = NULL;
	  pos->writeBufferSize = 0;
	} else {
	  memmove(pos->writeBuffer,
		  &pos->writeBuffer[ret],
		  pos->writeBufferSize - ret);
	  pos->writeBufferSize -= ret;
	}
      }

      if (FD_ISSET(sock, &errorSet)) {
#if DEBUG_TCPHANDLER
	  LOG(LOG_DEBUG,
	      "DEBUG: tcpserver error on connection %d\n",
	      pos);
#endif
	ClientHandle ch
	  = pos->next;
	destroySession(pos); 
	pos = ch;
	continue;
      }

      pos = pos->next;
    }
  } /* while tcpserver_keep_running */

  /* shutdown... */
  CLOSE(listenerFD);

  /* close all sessions */
  while (clientList != NULL) 
    destroySession(clientList); 

  MUTEX_UNLOCK(&clientlock);
  SEMAPHORE_UP(serverSignal);  /* signal shutdown */
  return NULL;
} 


/**
 * Handle a request to see if a particular client server message 
 * is supported.
 **/
static int handleCSMessageSupported(ClientHandle sock,
				    CS_HEADER * message) {
  unsigned short type;
  int supported;
  STATS_CS_GET_MESSAGE_SUPPORTED * cmsg;

  if (ntohs(message->size) != sizeof(STATS_CS_GET_MESSAGE_SUPPORTED)) {
    LOG(LOG_WARNING,
	"WARNING: message received from client is invalid.\n");
    return SYSERR;
  }
  cmsg = (STATS_CS_GET_MESSAGE_SUPPORTED *) message;
  type = ntohs(cmsg->tcpType);

  supported = isCSHandlerRegistered( type );

  return sendTCPResultToClient(sock, supported);
}

static int sendStatistics_(ClientHandle sock,
			   CS_HEADER * message) {
  return sendStatistics(sock,
			message,
			&sendToClient);
}

static int handleGetOption(ClientHandle sock,
			   CS_HEADER * message) {
  CS_GET_OPTION_REQUEST * req;
  CS_GET_OPTION_REPLY * rep;
  char * val;
  int ret;

  if (ntohs(message->size) != sizeof(CS_GET_OPTION_REQUEST))
    return SYSERR;
  req = (CS_GET_OPTION_REQUEST*)message;
  req->section[CS_GET_OPTION_REQUEST_OPT_LEN-1] = '\0';
  req->option[CS_GET_OPTION_REQUEST_OPT_LEN-1] = '\0';
  val = getConfigurationString(req->section,
			       req->option);
  if (val == NULL) {
    int ival = getConfigurationInt(req->section,
				   req->option);
    val = MALLOC(12);
    sprintf(val,
	    "%d",
	    ival);
  }
  rep = MALLOC(sizeof(CS_HEADER) + strlen(val) + 1);
  rep->header.size = htons(sizeof(CS_HEADER) + strlen(val) + 1);
  memcpy(rep->value,
	 val,
	 strlen(val)+1);
  rep->header.tcpType = htons(CS_PROTO_GET_OPTION_REPLY);
  ret = sendToClient(sock,
		     &rep->header);
  FREE(rep);
  FREE(val);
  return ret;
}

/**
 * Initialize the TCP port and listen for incoming client connections.
 **/
int initTCPServer() {
  if (tcpserver_keep_running == YES) {
    LOG(LOG_FATAL,
	"FATAL: initTCPServer called, but TCPserver is already running\n");
    return SYSERR;
  }
  PIPE(signalingPipe);
  /* important: make signalingPipe non-blocking
     to avoid stalling on signaling! */
  setBlocking(signalingPipe[1], NO);

#if VERBOSE_STATS
  octets_total_tcp_in 
    = statHandle("# bytes received from clients");
  octets_total_tcp_out
    = statHandle("# bytes sent to clients");
#endif
  MUTEX_CREATE_RECURSIVE(&handlerlock);
  MUTEX_CREATE_RECURSIVE(&clientlock);
  tcpserver_keep_running = YES;
  serverSignal = SEMAPHORE_NEW(0);
  if (0 == PTHREAD_CREATE(&TCPLISTENER_listener_, 
			  (PThreadMain)&tcpListenMain, 
			  NULL,
			  64*1024)) {
    SEMAPHORE_DOWN(serverSignal);
  } else {
    LOG(LOG_FAILURE, 
	"FAILURE: could not start TCP server (pthread error!?)\n");
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    tcpserver_keep_running = NO;
    MUTEX_DESTROY(&handlerlock);
    MUTEX_DESTROY(&clientlock);
    return SYSERR;
  }
  /* register default handlers */
  registerCSHandler(STATS_CS_PROTO_GET_STATISTICS,
		    &sendStatistics_);
  registerCSHandler(STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED,
		    &handleCSMessageSupported);
  registerCSHandler(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED,
		    &handlep2pMessageSupported);
  registerCSHandler(CS_PROTO_GET_OPTION_REQUEST,
		    &handleGetOption);
  return OK;
}

/**
 * Shutdown the module.
 **/ 
int stopTCPServer() {
  void * unused;

  if ( ( tcpserver_keep_running == YES) &&
       ( serverSignal != NULL) ) {
#if DEBUG_TCPHANDLER
    LOG(LOG_DEBUG,
	"DEBUG: stopping TCP server\n");
#endif
    /* stop server thread */
    tcpserver_keep_running = NO;
    signalSelect();
    SEMAPHORE_DOWN(serverSignal);
    SEMAPHORE_FREE(serverSignal);  
    serverSignal = NULL;
    PTHREAD_JOIN(&TCPLISTENER_listener_, &unused);
    return OK;
  } else
    return SYSERR;
}

int doneTCPServer() {
#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "DEBUG: entering doneTCPServer\n");
#endif
  CLOSE(signalingPipe[0]);
  CLOSE(signalingPipe[1]);
  /* free data structures */
  MUTEX_DESTROY(&handlerlock);
  MUTEX_DESTROY(&clientlock);
  GROW(handlers,
       max_registeredType,
       0);
  GROW(exitHandlers,
       exitHandlerCount,
       0);
  return OK;
}

/**
 * Register a method as a handler for specific message
 * types. 
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is already a
 *         handler for that type
 **/
int registerCSHandler(const unsigned short type,
		      CSHandler callback) {
  MUTEX_LOCK(&handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(&handlerlock);
      LOG(LOG_WARNING,
	  "WARNING: registerCSHandler failed, slot %d used\n",
	  type);
      return SYSERR;
    } 
  } else
    GROW(handlers,
	 max_registeredType,
	 type + 8);
  handlers[type] = callback;
  MUTEX_UNLOCK(&handlerlock);
  return OK; 
}

/**
 * Return wheter or not there is a method handler 
 * registered for a specific Client-Server message type.
 *
 * @param type the message type
 * @return YES if there is a handler for the type,
 * 	NO if there isn't
 **/
int isCSHandlerRegistered(const unsigned short type) {
    int registered = NO;

    if ((type < max_registeredType) &&
    	(handlers[type] != NULL)) {
        registered = YES;
    }

    return registered;
}

  
/**
 * Unregister a method as a handler for specific message
 * types. 
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is no or another
 *         handler for that type
 **/
int unregisterCSHandler(const unsigned short type,
			CSHandler callback) {
  MUTEX_LOCK(&handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != callback) {
      MUTEX_UNLOCK(&handlerlock);
      return SYSERR; /* another handler present */
    } else {
      handlers[type] = NULL;
      MUTEX_UNLOCK(&handlerlock);
      return OK; /* success */
    }
  } else {  /* can't be there */
    MUTEX_UNLOCK(&handlerlock);
    return SYSERR;
  }
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 **/
int sendTCPResultToClient(ClientHandle sock,
			  int ret) {
  CS_RETURN_VALUE rv;
  
  rv.header.size 
    = htons(sizeof(CS_RETURN_VALUE));
  rv.header.tcpType 
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value 
    = htonl(ret);
  return sendToClient(sock,
		      &rv.header);
}
				   


/* end of tcpserver.c */
