/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file server/handler.c
 * @brief demultiplexer for incoming peer-to-peer packets.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"

#include "core.h"
#include "handler.h"
#include "connection.h"
#include "tcpserver.h"

#define DEBUG_HANDLER NO

/**
 * How many incoming packages do we have in the buffer
 * (max.). Must be >= THREAD_COUNT to make sense.
 */
#define QUEUE_LENGTH 16

/**
 * How many threads do we start?
 */
#define THREAD_COUNT 2

/**
 * Transport service
 */
static Transport_ServiceAPI * transport;

/**
 * Identity service
 */
static Identity_ServiceAPI * identity;


static P2P_PACKET * bufferQueue_[QUEUE_LENGTH];
static int bq_firstFree_;
static int bq_lastFree_;
static int bq_firstFull_;
static int threads_running = NO;

static Semaphore * bufferQueueRead_;
static Semaphore * bufferQueueWrite_;
static Mutex globalLock_;
static Semaphore * mainShutdownSignal = NULL;
static PTHREAD_T threads_[THREAD_COUNT];


/**
 * Array of arrays of message handlers.
 */
static MessagePartHandler ** handlers = NULL;

/**
 * Number of handlers in the array (max, there
 * may be NULL pointers in it!)
 */
static unsigned int max_registeredType = 0;

/**
 * Array of arrays of the message handlers for plaintext messages.
 */
static PlaintextMessagePartHandler ** plaintextHandlers = NULL;

/**
 * Number of handlers in the plaintextHandlers array (max, there
 * may be NULL pointers in it!)
 */
static unsigned int plaintextmax_registeredType = 0;

/**
 * Mutex to guard access to the handler array.
 */
static Mutex handlerLock;


/**
 * Register a method as a handler for specific message types.  Note
 * that it IS possible to register multiple handlers for the same
 * message.  In that case, they will ALL be executed in the order of
 * registration, unless one of them returns SYSERR in which case the
 * remaining handlers and the rest of the message are ignored.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if core threads are running
 *        and updates to the handler list are illegal!
 */
int registerp2pHandler(unsigned short type,
		       MessagePartHandler callback) {
  unsigned int last;

  MUTEX_LOCK(&handlerLock);
  if (threads_running == YES) {
    BREAK();
    MUTEX_UNLOCK(&handlerLock);
    return SYSERR;
  }
  if (type >= max_registeredType) {
    unsigned int ort = max_registeredType;
    GROW(handlers,
	 max_registeredType,
	 type + 32);
    while (ort < max_registeredType) {
      unsigned int zero = 0;
      GROW(handlers[ort],
	   zero,
	   1);
      ort++;
    }
  }
  last = 0;
  while (handlers[type][last] != NULL) last++;
  last++;
  GROW(handlers[type], last, last+1);
  handlers[type][last-2] = callback;
  MUTEX_UNLOCK(&handlerLock);
  return OK;
}

/**
 * Unregister a method as a handler for specific message types. Only
 * for encrypted messages!
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *        handler for that type or if core threads are running
 *        and updates to the handler list are illegal!
 */
int unregisterp2pHandler(unsigned short type,
			 MessagePartHandler callback) {
  unsigned int pos;
  unsigned int last;

  MUTEX_LOCK(&handlerLock);
  if (threads_running == YES) {
    BREAK();
    MUTEX_UNLOCK(&handlerLock);
    return SYSERR;
  }
  if (type < max_registeredType) {
    pos = 0;
    while ( (handlers[type][pos] != NULL) &&
	    (handlers[type][pos] != callback) )
      pos++;
    last = pos;
    while (handlers[type][last] != NULL)
      last++;
    if (last == pos) {
      MUTEX_UNLOCK(&handlerLock);
      return SYSERR;
    } else {
      handlers[type][pos] = handlers[type][last-1];
      handlers[type][last-1] = NULL;
      last++;
      GROW(handlers[type], last, last-1);
      MUTEX_UNLOCK(&handlerLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&handlerLock);
  return SYSERR;
}

/**
 * Register a method as a handler for specific message types.  Note
 * that it IS possible to register multiple handlers for the same
 * message.  In that case, they will ALL be executed in the order of
 * registration, unless one of them returns SYSERR in which case the
 * remaining handlers and the rest of the message are ignored.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if core threads are running
 *        and updates to the handler list are illegal!
 */
int registerPlaintextHandler(unsigned short type,
			     PlaintextMessagePartHandler callback) {
  unsigned int last;

  MUTEX_LOCK(&handlerLock);
  if (threads_running == YES) {
    MUTEX_UNLOCK(&handlerLock);
    BREAK();
    return SYSERR;
  }
  if (type >= plaintextmax_registeredType) {
    unsigned int ort = plaintextmax_registeredType;
    GROW(plaintextHandlers,
	 plaintextmax_registeredType,
	 type + 32);
    while (ort < plaintextmax_registeredType) {
      unsigned int zero = 0;
      GROW(plaintextHandlers[ort],
	   zero,
	   1);
      ort++;
    }
  }
  last = 0;
  while (plaintextHandlers[type][last] != NULL) last++;
  last++;
  GROW(plaintextHandlers[type], last, last+1);
  plaintextHandlers[type][last-2] = callback;
  MUTEX_UNLOCK(&handlerLock);
  return OK;
}

/**
 * Unregister a method as a handler for specific message types. Only
 * for plaintext messages!
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *        handler for that type or if core threads are running
 *        and updates to the handler list are illegal!
 */
int unregisterPlaintextHandler(unsigned short type,
			       PlaintextMessagePartHandler callback) {
  unsigned int pos;
  unsigned int last;

  MUTEX_LOCK(&handlerLock);
  if (threads_running == YES) {
    BREAK();
    MUTEX_UNLOCK(&handlerLock);
    return SYSERR;
  }
  if (type < plaintextmax_registeredType) {
    pos = 0;
    while ( (plaintextHandlers[type][pos] != NULL) &&
	    (plaintextHandlers[type][pos] != callback) )
      pos++;
    last = pos;
    while (plaintextHandlers[type][last] != NULL)
      last++;
    if (last == pos) {
      MUTEX_UNLOCK(&handlerLock);
      return SYSERR;
    } else {
      plaintextHandlers[type][pos] = plaintextHandlers[type][last-1];
      plaintextHandlers[type][last-1] = NULL;
      last++;
      GROW(plaintextHandlers[type], last, last-1);
      MUTEX_UNLOCK(&handlerLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&handlerLock);
  return SYSERR;
}



/**
 * Unregister a method as a handler for specific message types. Only
 * for plaintext messages!
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *        handler for that type or if core threads are running
 *        and updates to the handler list are illegal!
 */
int isHandlerRegistered(unsigned short type,
			unsigned short handlerType) {
  int pos;
  int ret;

  if (handlerType == 3)
    return isCSHandlerRegistered(type);
  if (handlerType > 3) {
    BREAK();
    return SYSERR;
  }
  ret = 0;
  MUTEX_LOCK(&handlerLock);
  if (type < plaintextmax_registeredType) {
    pos = 0;
    while (plaintextHandlers[type][pos] != NULL)
      pos++;
    if ( (handlerType == 0) ||
	 (handlerType == 2) )
      ret += pos;
  }
  if (type < max_registeredType) {
    pos = 0;
    while (handlers[type][pos] != NULL)
      pos++;
    if ( (handlerType == 1) ||
	 (handlerType == 2) )
      ret += pos;
  }
  MUTEX_UNLOCK(&handlerLock);
  return ret;
}


/**
 * Handle a message (that was decrypted if needed).
 * Processes the message by calling the registered
 * handler for each message part.
 *
 * @param encrypted YES if it was encrypted,
 *    NO if plaintext,
 * @param session NULL if not available
 */
void injectMessage(const PeerIdentity * sender,
		   const char * msg,
		   unsigned int size,
		   int wasEncrypted,
		   TSession * session) {
  unsigned int pos;
  const P2P_MESSAGE_HEADER * part;
  P2P_MESSAGE_HEADER cpart;
  P2P_MESSAGE_HEADER * copy;
  int last;
  EncName enc;

  pos = 0;
  copy = NULL;
  while (pos < size) {
    unsigned short plen;
    unsigned short ptyp;

    memcpy(&cpart,
	   &msg[pos],
	   sizeof(P2P_MESSAGE_HEADER));
    plen = htons(cpart.size);
    if (pos + plen > size) {
      IFLOG(LOG_WARNING,
	    hash2enc(&sender->hashPubKey,
		     &enc));
      LOG(LOG_WARNING,
	  _("Received corrupt message from peer `%s'in %s:%d.\n"),
	  &enc,
	  __FILE__, __LINE__);
      return;
    }
    if ( (pos % sizeof(int)) != 0) {
      /* correct misalignment; we allow messages to _not_ be a
	 multiple of 4 bytes (if absolutely necessary; it should be
	 avoided where the cost for doing so is not prohibitive);
	 however we also (need to) guaranteed word-alignment for the
	 handlers; so we must re-align the message if it is
	 misaligned. */
      copy = MALLOC(plen);
      memcpy(copy,
	     &msg[pos],
	     plen);
      part = copy;
    } else {
      part = (const P2P_MESSAGE_HEADER*) &msg[pos];
    }
    pos += plen;

    ptyp = htons(part->type);
#if DEBUG_HANDLER
    IFLOG(LOG_DEBUG,
	  hash2enc(&sender->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"Received %s message of type %u from peer `%s'\n",
	wasEncrypted ? "encrypted" : "plaintext",
	ptyp,
	&enc);
#endif
    if (YES == wasEncrypted) {
      MessagePartHandler callback;

      if ( (ptyp >= max_registeredType) ||
	   (NULL == handlers[ptyp][0]) ) {
	LOG(LOG_EVERYTHING,
	    "Encrypted message of type '%d' not understood (no handler registered).\n",
	    ptyp);
	continue; /* no handler registered, go to next part */
      }
      last = 0;
      while (NULL != (callback = handlers[ptyp][last])) {
	if (SYSERR == callback(sender,
			       part)) {
	  LOG(LOG_DEBUG,
	      "Handler aborted message processing after receiving message of type '%d'.\n",
	      ptyp);
	  return; /* handler says: do not process the rest of the message */
	}
	last++;
      }
    } else { /* isEncrypted == NO */
      PlaintextMessagePartHandler callback;

      if ( (ptyp >= plaintextmax_registeredType) ||
	   (NULL == plaintextHandlers[ptyp][0]) ) {
	LOG(LOG_EVERYTHING,
	    "Plaintext message of type '%d' not understood (no handler registered).\n",
	    ptyp);
	continue; /* no handler registered, go to next part */
      }
      last = 0;
      while (NULL != (callback = plaintextHandlers[ptyp][last])) {
	if (SYSERR == callback(sender,
			       part,
			       session)) {
	  LOG(LOG_DEBUG,
	      "Handler aborted message processing after receiving message of type '%d'.\n",
	      ptyp);
	  return; /* handler says: do not process the rest of the message */
	}
	last++;
      }
    } /* if plaintext */
    FREENONNULL(copy);
    copy = NULL;
  } /* while loop */
}

/**
 * Message dispatch/handling.
 *
 * @param tsession transport session that received the message (maybe NULL)
 * @param sender the sender of the message
 * @param msg the message that was received. caller frees it on return
 * @param size the size of the message
 */
static void handleMessage(TSession * tsession,
			  const PeerIdentity * sender,
			  const char * msg,
			  unsigned int size) {
  int ret;

  if (YES == identity->isBlacklistedStrict(sender) ) {
    EncName enc;
    IFLOG(LOG_DEBUG,
          hash2enc(&sender->hashPubKey,
                   &enc));
    LOG(LOG_DEBUG,
    	"Strictly blacklisted peer `%s' sent message, dropping for now.\n",
	(char*)&enc);
    return;
  }
  ret = checkHeader(sender,
		    (P2P_PACKET_HEADER*) msg,
		    size);
  if (ret == SYSERR)
    return; /* message malformed */
  if ( (ret == YES) && (tsession != NULL) )
    if (OK == transport->associate(tsession))
      considerTakeover(sender, tsession);
  injectMessage(sender,
		&msg[sizeof(P2P_PACKET_HEADER)],
		size - sizeof(P2P_PACKET_HEADER),
		ret,
		tsession);
    
  confirmSessionUp(sender);
}

/**
 * This is the main loop of each thread.  It loops *forever* waiting
 * for incomming packets in the packet queue. Then it calls "handle"
 * (defined in handler.c) on the packet.
 */
static void * threadMain(int id) {
  P2P_PACKET * mp;

  while (mainShutdownSignal == NULL) {
    SEMAPHORE_DOWN(bufferQueueRead_);
    /* handle buffer entry */
    /* sync with other handlers to get buffer */
    if (mainShutdownSignal != NULL)
      break;
    MUTEX_LOCK(&globalLock_);
    mp = bufferQueue_[bq_firstFull_++];
    bufferQueue_[bq_lastFree_++] = NULL;
    if (bq_firstFull_ == QUEUE_LENGTH)
      bq_firstFull_ = 0;
    if (bq_lastFree_ == QUEUE_LENGTH)
      bq_lastFree_ = 0;
    MUTEX_UNLOCK(&globalLock_);
    /* end of sync */
    SEMAPHORE_UP(bufferQueueWrite_);

    /* handle buffer - now out of sync */
    handleMessage(mp->tsession,
		  &mp->sender,
		  mp->msg,
		  mp->size);
    if (mp->tsession != NULL)
      transport->disconnect(mp->tsession);
    FREE(mp->msg);
    FREE(mp);
  }
  SEMAPHORE_UP(mainShutdownSignal);
  return NULL;
} /* end of threadMain */

/**
 * Processing of a message from the transport layer
 * (receive implementation).
 */
void core_receive(P2P_PACKET * mp) {
  if ( (threads_running == NO) ||
       (mainShutdownSignal != NULL) ||
       (SYSERR == SEMAPHORE_DOWN_NONBLOCKING(bufferQueueWrite_)) ) {
    /* discard message, buffer is full or
       we're shut down! */
    FREE(mp->msg);
    FREE(mp);
    return;
  }
  /* aquire buffer */
  if (SYSERR == transport->associate(mp->tsession))
    mp->tsession = NULL;

  MUTEX_LOCK(&globalLock_);
  if (bq_firstFree_ == QUEUE_LENGTH)
    bq_firstFree_ = 0;
  bufferQueue_[bq_firstFree_++] = mp;
  MUTEX_UNLOCK(&globalLock_);
  SEMAPHORE_UP(bufferQueueRead_);
}

/**
 * Start processing p2p messages.
 */
void enableCoreProcessing() {
  int i;

  MUTEX_CREATE(&globalLock_);
  for (i=0;i<QUEUE_LENGTH;i++)
    bufferQueue_[i] = NULL;
  bq_firstFree_ = 0;
  bq_lastFree_ = 0;
  bq_firstFull_ = 0;

  /* create message handling threads */
  MUTEX_LOCK(&handlerLock);
  threads_running = YES;
  MUTEX_UNLOCK(&handlerLock);
  for (i=0;i<THREAD_COUNT;i++) {
    PTHREAD_CREATE(&threads_[i],
		   (PThreadMain) &threadMain,
		   (void *) &i,
		   8 * 1024);
  }
}

/**
 * Stop processing (p2p) messages.
 */
void disableCoreProcessing() {
  int i;
  void * unused;

  /* shutdown processing of inbound messages... */
  mainShutdownSignal = SEMAPHORE_NEW(0);
  for (i=0;i<THREAD_COUNT;i++) {
    SEMAPHORE_UP(bufferQueueRead_);
    SEMAPHORE_DOWN(mainShutdownSignal);
  }
  for (i=0;i<THREAD_COUNT;i++)
    PTHREAD_JOIN(&threads_[i], &unused);
  MUTEX_LOCK(&handlerLock);
  threads_running = NO;
  MUTEX_UNLOCK(&handlerLock);
  SEMAPHORE_FREE(mainShutdownSignal);
  mainShutdownSignal = NULL;
  MUTEX_DESTROY(&globalLock_);
}

/**
 * Initialize message handling module.
 */
void initHandler() {
  MUTEX_CREATE(&handlerLock);
  transport = requestService("transport");
  GNUNET_ASSERT(transport != NULL);
  identity  = requestService("identity");
  GNUNET_ASSERT(identity != NULL);
  /* initialize sync mechanisms for message handling threads */
  bufferQueueRead_ = SEMAPHORE_NEW(0);
  bufferQueueWrite_ = SEMAPHORE_NEW(QUEUE_LENGTH);
}

/**
 * Shutdown message handling module.
 */
void doneHandler() {
  unsigned int i;

  /* free datastructures */
  SEMAPHORE_FREE(bufferQueueRead_);
  SEMAPHORE_FREE(bufferQueueWrite_);
  for (i=0;i<QUEUE_LENGTH;i++) {
    if (bufferQueue_[i] != NULL) {
      FREENONNULL(bufferQueue_[i]->msg);
    }
    FREENONNULL(bufferQueue_[i]);
  }

  MUTEX_DESTROY(&handlerLock);
  for (i=0;i<max_registeredType;i++) {
    unsigned int last = 0;
    while (handlers[i][last] != NULL)
      last++;
    last++;
    GROW(handlers[i],
	 last,
	 0);
  }
  GROW(handlers,
       max_registeredType,
       0);
  for (i=0;i<plaintextmax_registeredType;i++) {
    unsigned int last = 0;
    while (plaintextHandlers[i][last] != NULL)
      last++;
    GROW(plaintextHandlers[i],
	 last,
	 0);
  }
  GROW(plaintextHandlers,
       plaintextmax_registeredType,
       0);
  releaseService(transport);
  transport = NULL;
  releaseService(identity);
  identity = NULL;
}


/* end of handler.c */
