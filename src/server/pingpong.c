/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file server/pingpong.c
 * @brief Pings a host and triggers an action if a reply is received.
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "handler.h"
#include "traffic.h"
#include "knownhosts.h"

#define DEBUG_PINGPONG NO

#define MAX_PING_PONG 64

#if VERBOSE_STATS
static int stat_ping_sent;
static int stat_pong_sent;
static int stat_ping_received;
static int stat_pong_received;
#endif

typedef struct {
  HostIdentity receiverIdentity;
  int challenge;
  TIME_T sendTime;
  CronJob method;
  void * data;
} PingPongEntry;

static PingPongEntry * pingPongs;
static Mutex * pingPongLock;


/**
 * We received a PING message, send the PONG reply and notify the
 * connection module that the session is still life.
 **/	
static int pingReceived(HostIdentity * sender,
			p2p_HEADER * msg) {
  PINGPONG_Message * pmsg;
  
#if DEBUG_PINGPONG
  LOG(LOG_DEBUG,
      "DEBUG: received encrypted ping\n");
#endif
  if (ntohs(msg->size) != sizeof(PINGPONG_Message) )
    return SYSERR;
#if VERBOSE_STATS
  statChange(stat_ping_received, 1);
#endif
  pmsg = (PINGPONG_Message *) msg;
  if (!hostIdentityEquals(&myIdentity,
			  &pmsg->receiver))
    return SYSERR; /* not for us */
  pmsg->header.requestType = htons(p2p_PROTO_PONG);
#if VERBOSE_STATS
  statChange(stat_pong_sent, 1);
#endif
  notifyPING(sender); /* special! we want to know about all pings! */
  sendToNode(sender,
	     &pmsg->header,
	     getConnectPriority(),
	     0); /* send now! */
  return OK;
}

/**
 * We received a PING message, send the PONG reply and notify the
 * connection module that the session is still life.
 **/	
int plaintextPingReceived(HostIdentity * sender,
			  TSession * tsession,
			  p2p_HEADER * msg) {
  PINGPONG_Message * pmsg;

#if DEBUG_PINGPONG  
  LOG(LOG_DEBUG,
      "DEBUG: received plaintext ping\n");
#endif
  if (ntohs(msg->size) != sizeof(PINGPONG_Message) )
    return SYSERR;
#if VERBOSE_STATS
  statChange(stat_ping_received, 1);
#endif
  pmsg = (PINGPONG_Message *) msg;
  if (!hostIdentityEquals(&myIdentity,
			  &pmsg->receiver)) {
    LOG(LOG_INFO,
	"INFO: received PING not destined for us!\n");
    return SYSERR; /* not for us */
  }
  pmsg->header.requestType = htons(p2p_PROTO_PONG);
#if VERBOSE_STATS
  statChange(stat_pong_sent, 1);
#endif

  /* allow using a different transport for sending the reply, the
     transport may have been uni-directional! */
  if (SYSERR == transportSend(tsession,
			      msg,
			      sizeof(PINGPONG_Message),
			      NO,
			      crc32N(msg, sizeof(PINGPONG_Message)))) {
    HELO_Message * helo;
    TSession * mytsession;
    /* ok, try fresh connect */
    
    if (SYSERR == identity2Helo(sender,
				ANY_PROTOCOL_NUMBER, 
				YES,
				&helo)) {
#if DEBUG_PINGPONG
      HexName hn;
      
      IFLOG(LOG_INFO,
	    hash2hex(&sender->hashPubKey, &hn));
      LOG(LOG_INFO,
	  "INFO: received PING, can not send PONG, no transport known for peer %s\n",
	  &hn);
#endif
      return SYSERR;
    }
    if (SYSERR == transportConnect(helo, &mytsession)) {
      FREE(helo);
      return SYSERR;
    }
    if (SYSERR == transportSend(mytsession,
				msg,
				sizeof(PINGPONG_Message),
				NO,
				crc32N(msg, sizeof(PINGPONG_Message)))) {
      transportDisconnect(mytsession);
      return SYSERR;
    } else 
      updateTrafficSendCounter(p2p_PROTO_PONG,
			       sizeof(PINGPONG_Message));
    transportDisconnect(mytsession);
  } else
    updateTrafficSendCounter(p2p_PROTO_PONG,
			     sizeof(PINGPONG_Message));
  return OK;
}

/**
 * Handler for a pong.
 **/ 	
static int pongReceived(HostIdentity * sender,
			p2p_HEADER * msg) {
  int i;
  PINGPONG_Message * pmsg;
  PingPongEntry * entry;
  int success = NO;

  pmsg = (PINGPONG_Message *) msg;
  if ( (ntohs(msg->size) != sizeof(PINGPONG_Message)) ||
       !hostIdentityEquals(sender,
			   &pmsg->receiver))
    return SYSERR; /* bad pong */
#if VERBOSE_STATS
  statChange(stat_pong_received, 1);
#endif
  MUTEX_LOCK(pingPongLock);   
  for (i=0;i<MAX_PING_PONG;i++) {
    entry = &pingPongs[i];
    if ( ((int)ntohl(pmsg->challenge) == entry->challenge) &&
	 hostIdentityEquals(sender,
			    &entry->receiverIdentity) ) {
#if DEBUG_PINGPONG
      LOG(LOG_DEBUG, 
	  "DEBUG: received pong, triggering action\n");
#endif
      success = YES;
      entry->method(entry->data);
      FREENONNULL(entry->data);
      /* entry was valid for one time only */
      memset(entry,
      	     0,
	     sizeof(PingPongEntry));
    }
  }
#if DEBUG_PINGPONG
  if (NO == success)
    LOG(LOG_DEBUG, 
	"DEBUG: no handler found for pong\n");
#endif
  MUTEX_UNLOCK(pingPongLock);   
  return OK;
}

/**
 * Handler for a pong.
 **/ 	
int plaintextPongReceived(HostIdentity * sender,
			  TSession * tsession,
			  p2p_HEADER * msg) {
  return pongReceived(sender, msg);
}

/**
 * Initialize the pingpong module.
 **/
void initPingPong() {
  pingPongLock = getConnectionModuleLock();
  pingPongs = (PingPongEntry*) MALLOC(sizeof(PingPongEntry)*MAX_PING_PONG);
  memset(pingPongs,
  	 0,
	 sizeof(PingPongEntry)*MAX_PING_PONG);
#if VERBOSE_STATS
  stat_ping_sent 
    = statHandle("# ping messages sent");
  stat_ping_received 
    = statHandle("# ping messages received");
  stat_pong_sent 
    = statHandle("# pong messages sent");
  stat_pong_received 
    = statHandle("# pong messages received");
#endif
  registerp2pHandler(p2p_PROTO_PING,
		     &pingReceived);
  registerp2pHandler(p2p_PROTO_PONG,
		     &pongReceived);
}

/**
 * Shutdown the pingpong module.
 **/
void donePingPong() {
  int i;

  for (i=0;i<MAX_PING_PONG;i++)
    FREENONNULL(pingPongs[i].data);
  FREE(pingPongs);
}

/**
 * Ping a host an call a method if a reply comes back.
 *
 * @param receiver the identity to fill into the ping
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @param pmsg the ping-message, pingAction just fills it in,
 *        the caller is responsible for sending it!
 * @returns OK on success, SYSERR on error
 **/
int pingAction(HostIdentity * receiver,
	       CronJob method,
	       void * data,
	       PINGPONG_Message * pmsg) {
  int i;
  int j;
  TIME_T min;
  PingPongEntry * entry;
  TIME_T now;

  MUTEX_LOCK(pingPongLock);   
  now = TIME(&min); /* set both, tricky... */
  
  j = -1;
  for (i=0;i<MAX_PING_PONG;i++) 
    if (min > pingPongs[i].sendTime) {
      min = pingPongs[i].sendTime;
      j = i;
    }
  if (j == -1) { /* all send this second!? */
    MUTEX_UNLOCK(pingPongLock);     
    return SYSERR;  
  }
  entry = &pingPongs[j];
  entry->sendTime = now;
  entry->method = method;
  FREENONNULL(entry->data);
  entry->data = data;
  memcpy(&entry->receiverIdentity,
	 receiver,
	 sizeof(HostIdentity));
  pmsg->header.size = htons(sizeof(PINGPONG_Message));
  pmsg->header.requestType = htons(p2p_PROTO_PING);
#if VERBOSE_STATS
  statChange(stat_ping_sent, 1);
#endif
  memcpy(&pmsg->receiver,
	 receiver,
	 sizeof(HostIdentity));
  entry->challenge = rand();
  pmsg->challenge = htonl(entry->challenge);
  MUTEX_UNLOCK(pingPongLock);     
  return OK;
}

/* end of pingpong.c */
