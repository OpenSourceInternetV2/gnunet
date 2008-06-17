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
 * @file server/handler.c
 * @brief demultiplexer for incoming peer-to-peer packets.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"

#include "policy.h"
#include "pingpong.h"
#include "heloexchange.h"
#include "traffic.h"
#include "handler.h"
#include "connection.h"
#include "knownhosts.h"
#include "tcpserver.h"

/**
 * Array of the message handlers.
 */
static MessagePartHandler * handlers = NULL;

/**
 * Number of handlers in the array (max, there
 * may be NULL pointers in it!)
 */
static int max_registeredType = 0;

/**
 * Mutex to guard access to the handler array.
 */
static Mutex handlerLock;

/**
 * Noise received-stats.
 */
static int stat_bytes_noise_received;

static int stat_decryptFailed;

/**
 * What percentage of inbound messages
 * should be randomly dropped? (for testing
 * unreliability of the network).
 */
static int percentRandomInboundDrop = 0;

void setPercentRandomInboundDrop(int value) {
  percentRandomInboundDrop = value;
}

/**
 * Handler for processing noise.
 */
static int processNoise(const HostIdentity * sender,
			const p2p_HEADER * msg) {
  statChange(stat_bytes_noise_received,
	     ntohs(msg->size));
  return OK;
}

/**
 * Initialize message handling module.
 */
void initHandler() {
  MUTEX_CREATE(&handlerLock);
  stat_bytes_noise_received 
    = statHandle(_("# bytes of noise received"));
  stat_decryptFailed 
    = statHandle(_("# bytes received and decryption failed"));
  if (SYSERR == registerp2pHandler(p2p_PROTO_NOISE,
				   &processNoise))
    GNUNET_ASSERT(0);
}

/**
 * Shutdown message handling module.
 */
void doneHandler() {
  MUTEX_DESTROY(&handlerLock);
  GROW(handlers,
       max_registeredType,
       0);
}

/**
 * Handle a message (that was decrypted if needed).  Checks the CRC
 * and if that's ok, processes the message by calling the registered
 * handler for each message part.
 */
void handleHelper(const char * msg,
		  const HostIdentity * sender,
		  const unsigned int size,
		  const int crc) {
  unsigned int pos;
  p2p_HEADER * part;

  if (crc32N(msg, size) != crc) {
    EncName enc;
    IFLOG(LOG_INFO,
    	hash2enc(&sender->hashPubKey,
		 &enc));
    LOG(LOG_WARNING, 
	_("Received corrupt message claiming to be from peer '%s'in %s:%d.\n"),
	&enc, __FILE__, __LINE__);
    return;
  }
  trafficReceivedFrom(sender, size);
  pos = 0;
  while (pos < size) {
    unsigned short plen;
    unsigned short ptyp;
    MessagePartHandler callback;

    part = (p2p_HEADER *) &msg[pos];
    plen = htons(part->size);
    if (pos + plen > size) {
      EncName enc;
      IFLOG(LOG_INFO,
	    hash2enc(&sender->hashPubKey,
		     &enc));      
      LOG(LOG_WARNING, 
	  _("Received corrupt message from peer '%s'in %s:%d.\n"),
	  &enc, __FILE__, __LINE__);
      break; /* exit */
    }
    pos += plen;

    ptyp = htons(part->requestType);
    updateTrafficReceiveCounter(ptyp,
				plen);
    if (ptyp > max_registeredType) {
      LOG(LOG_EVERYTHING, 
	  "Encrypted message of type %d not understood (no handler registered).\n",
	  ptyp);
      continue; /* no handler registered, go to next part */
    }
    callback = handlers[ptyp];
    if (callback == NULL) {
      LOG(LOG_EVERYTHING, 
	  "Encrypted message of type %d not understood (no handler registered).\n",
	  ptyp);
      continue; /* no handler registered, go to next part */
    }
    trafficReceive(part, sender);
    if (SYSERR == callback(sender,
			   part)) {
      LOG(LOG_DEBUG,
	  "Handler aborted message processing after receiving message of type %d.\n",
	  ptyp);
      break; /* handler says: do not process the rest of the message */
    }
  }
}

/**
 * Handle a message (that was decrypted if needed).  Checks the CRC
 * and if that's ok, processes the message by calling the registered
 * handler for each message part.
 */
static void handlePlaintext(const char * msg,
			    TSession * tsession,
			    const HostIdentity * sender,
			    const unsigned int size,
			    const int crc) {
  unsigned int pos;
  p2p_HEADER * part;

  if (crc32N(msg, size) != crc) {
    EncName enc;
    
    IFLOG(LOG_WARNING,
	  hash2enc(&sender->hashPubKey,
		   &enc));
    LOG(LOG_WARNING, 
	_("Plaintext message claiming to be from peer '%s' failed CRC check.\n"),
	&enc);
    return; /* drop */
  }
  pos = 0;
  while (pos < size) {
    unsigned short plen;
    unsigned short ptyp;

    part = (p2p_HEADER *) &msg[pos];
    plen = ntohs(part->size);
    if ( (pos + plen > size) || (plen < sizeof(p2p_HEADER)) ) {
      EncName enc;

      IFLOG(LOG_WARNING,
	    hash2enc(&sender->hashPubKey,
		     &enc));
      LOG(LOG_WARNING, 
	  _("Received corrupt plaintext message claiming to be from peer '%s'in %s:%d.\n"),
	  &enc, __FILE__, __LINE__);
      break; /* exit */
    }
    pos += plen;
    
    ptyp = htons(part->requestType);
    updateTrafficReceiveCounter(ptyp,
				plen);
    switch (ptyp) {
    case p2p_PROTO_HELO: 
      receivedHELO(part);
      break;    
    case p2p_PROTO_SKEY:
      /* establish session if slot not busy,
	 challenge with (encrypted) ping! */
      acceptSessionKey(sender,
		       tsession,
		       part);
      break;
    case p2p_PROTO_PING:
      /* challenge: send back reply - NOW! */
      plaintextPingReceived(sender, tsession, part);
      break;
    case p2p_PROTO_PONG:
      /* this confirms a PING => add a HELO to
	 knownhosts. */
      plaintextPongReceived(sender, tsession, part);
      break;
    default:
      LOG(LOG_EVERYTHING, 
	  "Plaintext message of type %d not supported.\n",
	  ptyp);
      break;
    }
  }
}

/**
 * Message dispatch/handling.
 *
 * @param tsession transport session that received the message (maybe NULL)
 * @param sender the sender of the message
 * @param msg the message that was received. caller frees it on return
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC32 checksum of the plaintext
 */
void handleMessage(TSession * tsession,
		   const HostIdentity * sender,
		   const void * msg,
		   const unsigned int size,
		   int isEncrypted,
		   const int crc) {
  if ( (percentRandomInboundDrop > 0) &&
       (percentRandomInboundDrop > randomi(100)) )
    return;
  
  if (YES == isBlacklistedStrict(sender) ) {
    EncName enc;
    IFLOG(LOG_DEBUG,
          hash2enc(&sender->hashPubKey,
                   &enc));
    LOG(LOG_DEBUG,
    	"Strictly blacklisted peer '%s' sent message, dropping for now.\n",
	(char*)&enc);
    return;
  }

  if ( (isEncrypted == YES) || (isEncrypted == LOOPBACK) ) {
    char * plaintext;
    
    plaintext = MALLOC(size);
    if (isEncrypted == YES) {
      if (SYSERR == decryptFromHost(msg, 
				    size,
				    sender,
				    plaintext)) {
	statChange(stat_decryptFailed,
		   size);
	FREE(plaintext);
	return;
      } 
    } else { /* loopback */
      memcpy(plaintext,
	     msg,
	     size);
    }
    /* we may be able to use this transport-session to reduce our
       cost to send replies to the sender, let's check */
    if (tsession != NULL)
      considerTakeover(tsession, sender);
    handleHelper(plaintext, sender, size, crc);
    FREE(plaintext);
  } else {
    handlePlaintext(msg, tsession, sender, size, crc);
  }
}

/**
 * Register a method as a handler for specific message types.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is already a
 *         handler for that type
 */
int registerp2pHandler(const unsigned short type,
		       MessagePartHandler callback) {
  MUTEX_LOCK(&handlerLock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(&handlerLock);
      LOG(LOG_WARNING,
	  _("Could not register handler for type %d (slot used).\n"),
	  type);
      return SYSERR;
    } 
  } else {
    GROW(handlers,
	 max_registeredType,
	 type + 32);
  }
  handlers[type] = callback;
  MUTEX_UNLOCK(&handlerLock);
  return OK;    
}

/**
 * Return wheter or not there is a method handler registered for a
 * specific p2p message type.
 *
 * @param type the message type
 * @return YES if there is a handler for the type,
 * 	NO if there isn't
 */
int isp2pHandlerRegistered(const unsigned short type) {
    int registered = NO;
    if ( (type < max_registeredType) && 
	 (handlers[type] != NULL) ) {
        registered = YES;
    } 
    return registered;
}
  
/**
 * Unregister a method as a handler for specific message types. Only
 * for encrypted messages!
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *         handler for that type
 */
int unregisterp2pHandler(const unsigned short type,
			 MessagePartHandler callback) {
  MUTEX_LOCK(&handlerLock);
  if (type < max_registeredType) {
    if (handlers[type] != callback) {
      MUTEX_UNLOCK(&handlerLock);
      return SYSERR;
    } else {
      handlers[type] = NULL;
      MUTEX_UNLOCK(&handlerLock);
      return OK;
    }
  } 
  MUTEX_UNLOCK(&handlerLock);
  return SYSERR; 
}


/**
 * Handle a request to see if a particular p2p message is supported.
 */
int handlep2pMessageSupported(ClientHandle sock,
			      const CS_HEADER * message) {
  unsigned short type;
  int supported;
  STATS_CS_GET_MESSAGE_SUPPORTED * cmsg;

  if (ntohs(message->size) != sizeof(STATS_CS_GET_MESSAGE_SUPPORTED)) {
    BREAK();
    return SYSERR;
  }
  cmsg = (STATS_CS_GET_MESSAGE_SUPPORTED *) message;
  type = ntohs(cmsg->tcpType);
  supported = isp2pHandlerRegistered(type);
  return sendTCPResultToClient(sock, supported);
}

/* end of handler.c */
