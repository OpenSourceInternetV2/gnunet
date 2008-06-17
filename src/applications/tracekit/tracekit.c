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
 * @file applications/tracekit/tracekit.c
 * @author Christian Grothoff
 */

#include "tracekit.h"
#include "platform.h"

static CoreAPIForApplication * coreAPI = NULL;
static Mutex lock;
static int clientCount = 0;
static ClientHandle* clients = NULL;

#if VERBOSE_STATS
static int stat_cs_requests;
static int stat_cs_replies;
static int stat_p2p_requests;
static int stat_p2p_replies;
#endif

typedef struct {
  HostIdentity initiator;
  HostIdentity replyTo;
  TIME_T timestamp;  
  unsigned int priority;
} RTE;

#define MAXROUTE 16

static RTE routeTable[MAXROUTE];

static int handlep2pReply(const HostIdentity * sender,
			  const p2p_HEADER * message) {
  unsigned int i;
  unsigned int hostCount;
  TRACEKIT_p2p_REPLY * reply;
  EncName initiator;

#if VERBOSE_STATS
  statChange(stat_p2p_replies, 1);
#endif
  LOG(LOG_DEBUG,
      " TRACEKIT: receving reply\n");
  hostCount = (ntohs(message->size)-sizeof(TRACEKIT_p2p_REPLY))/sizeof(HostIdentity);
  if (ntohs(message->size) !=
      sizeof(TRACEKIT_p2p_REPLY)+hostCount*sizeof(HostIdentity))
    return SYSERR;
  reply = (TRACEKIT_p2p_REPLY*)message;
  hash2enc(&reply->initiatorId.hashPubKey,
	   &initiator);
  LOG(LOG_DEBUG,
      "sending reply back to initiator %s\n",
      &initiator);
  MUTEX_LOCK(&lock);
  for (i=0;i<MAXROUTE;i++) {
    if ( (routeTable[i].timestamp == (TIME_T)ntohl(reply->initiatorTimestamp)) &&
	 (equalsHashCode160(&routeTable[i].initiator.hashPubKey,
			    &reply->initiatorId.hashPubKey) ) ) {
      LOG(LOG_INFO,
	  " found matching entry in routing table\n");
      if (equalsHashCode160(&coreAPI->myIdentity->hashPubKey,
			    &routeTable[i].replyTo.hashPubKey) ) {
	int idx;
	TRACEKIT_CS_REPLY * csReply;

	idx = ntohl(reply->clientId);
	LOG(LOG_DEBUG,
	    " I am initiator, sending to client %d\n",
	    idx);
	if (idx >= clientCount) 
	  continue; /* discard */
	if (clients[idx] == NULL)
	  continue; /* discard */
	
	csReply = MALLOC(sizeof(TRACEKIT_CS_REPLY)+hostCount*sizeof(HostIdentity));
	/* build msg */
	csReply->header.size 
	  = htons(sizeof(TRACEKIT_CS_REPLY)+hostCount*sizeof(HostIdentity));
	csReply->header.tcpType 
	  = htons(TRACEKIT_CS_PROTO_REPLY);
	memcpy(&csReply->responderId,
	       &reply->responderId,
	       sizeof(HostIdentity));
	memcpy(&((TRACEKIT_CS_REPLY_GENERIC*)csReply)->peerList[0],
	       &((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[0],
	       hostCount * sizeof(HostIdentity));
#if VERBOSE_STATS
	statChange(stat_cs_replies, 1);
#endif
	coreAPI->sendToClient(clients[idx],
			      &csReply->header);
	FREE(csReply);
      } else {
	EncName hop;

	hash2enc(&routeTable[i].replyTo.hashPubKey,
		 &hop);
	LOG(LOG_DEBUG,
	    "forwarding to next hop %s\n",
	    &hop);
#if VERBOSE_STATS
	statChange(stat_p2p_replies, 1);
#endif
	coreAPI->sendToNode(&routeTable[i].replyTo,
			    message,
			    routeTable[i].priority,
			    0);
      }
    }
  }
  MUTEX_UNLOCK(&lock);
  return OK;
}


typedef struct {
  TRACEKIT_p2p_REPLY * reply;
  int max;
  int pos;
} Closure;

static void getPeerCallback(const HostIdentity * id,
			    Closure * closure) {
  if (closure->pos < closure->max) 
    memcpy(&((TRACEKIT_p2p_REPLY_GENERIC*)(closure->reply))->peerList[closure->pos++],
	   id,
	   sizeof(HostIdentity));
}

static int handlep2pProbe(const HostIdentity * sender,
			  const p2p_HEADER * message) {
  TRACEKIT_p2p_REPLY * reply;
  TRACEKIT_p2p_PROBE * msg;
  Closure closure;
  int i;
  int sel;
  int hops;
  TIME_T oldest;
  int count;
  unsigned int size;
  EncName init;

#if VERBOSE_STATS
  statChange(stat_p2p_requests, 1);
#endif
  LOG(LOG_DEBUG,
      "TRACEKIT: received probe\n");
  if (ntohs(message->size) != 
      sizeof(TRACEKIT_p2p_PROBE)) {
    LOG(LOG_WARNING,
	"received invalid TRACEKIT-PROBE message\n");
    return SYSERR;
  }
  msg = (TRACEKIT_p2p_PROBE*) message;
  if ((TIME_T)ntohl(msg->timestamp) > 3600 + TIME(NULL)) {
    LOG(LOG_INFO,
	"probe has timestamp in the future (%d >> %d), dropping\n",
	ntohl(msg->timestamp), 
	TIME(NULL));
    return SYSERR; /* timestamp is more than 1h
		      in the future. Cheaters! */
  }
  hash2enc(&msg->initiatorId.hashPubKey,
	   &init);
  MUTEX_LOCK(&lock);
  /* test if already processed */
  for (i=0;i<MAXROUTE;i++) 
    if ( (routeTable[i].timestamp ==
	  (TIME_T)ntohl(msg->timestamp)) &&
	 equalsHashCode160(&routeTable[i].initiator.hashPubKey,
			   &msg->initiatorId.hashPubKey) ) {

      LOG(LOG_DEBUG,
	  " TRACEKIT-PROBE %d from %s received twice (slot %d), ignored\n",
	  ntohl(msg->timestamp),
	  &init,
	  i);
      MUTEX_UNLOCK(&lock);
      return OK;
    }  
  /* no, find and kill oldest entry */
  oldest = ntohl(msg->timestamp);
  sel = -1;
  for (i=0;i<MAXROUTE;i++)
    if (oldest > routeTable[i].timestamp) {
      oldest = routeTable[i].timestamp;
      sel = i;
    }
  if (sel == -1) {
    MUTEX_UNLOCK(&lock);
    LOG(LOG_INFO,
	"request routing table full, trace request dropped\n");
    return OK;
  }
  routeTable[sel].timestamp 
    = ntohl(msg->timestamp);
  routeTable[sel].priority
    = ntohl(msg->priority);
  memcpy(&routeTable[sel].initiator,
	 &msg->initiatorId,
	 sizeof(HostIdentity));
  memcpy(&routeTable[sel].replyTo,
	 sender,
	 sizeof(HostIdentity));
  /* check if seen, if not, update routing
     table entries */
  MUTEX_UNLOCK(&lock);
  LOG(LOG_DEBUG,
      "TRACEKIT-PROBE %d from %s received, processing in slot %d\n",
      ntohl(msg->timestamp),
      &init,
      sel);
  
  hops = ntohl(msg->hopsToGo);
  count = coreAPI->forAllConnectedNodes(NULL, NULL);
  if (hops > 0) {
    msg->hopsToGo = htonl(hops-1);
    coreAPI->broadcastToConnected(message,
				  ntohl(msg->priority),
				  0);
#if VERBOSE_STATS
    statChange(stat_p2p_requests, 
	       count);
#endif
  }
  size = sizeof(TRACEKIT_p2p_REPLY)+count*sizeof(HostIdentity);
  reply = MALLOC(size);
  closure.reply = reply;
  closure.max = count;
  closure.pos = 0;
  coreAPI->forAllConnectedNodes((PerNodeCallback)&getPeerCallback,
				&closure);
  reply->header.requestType 
    = htons(TRACEKIT_p2p_PROTO_REPLY);
  memcpy(&reply->initiatorId,
	 &msg->initiatorId,
	 sizeof(HostIdentity));
  memcpy(&reply->responderId,
	 coreAPI->myIdentity,
	 sizeof(HostIdentity));
  reply->initiatorTimestamp 
    = msg->timestamp;
  reply->clientId
    = msg->clientId;
  while (size >= sizeof(TRACEKIT_p2p_REPLY)) {
    int rest;
    int max;

    if (size > 1024)
      max = (1024 - sizeof(TRACEKIT_p2p_REPLY)) / sizeof(HostIdentity);    
    else
      max = (size - sizeof(TRACEKIT_p2p_REPLY)) / sizeof(HostIdentity); 
    reply->header.size
      = htons(sizeof(TRACEKIT_p2p_REPLY) + max * sizeof(HostIdentity));
    if (equalsHashCode160(&coreAPI->myIdentity->hashPubKey,
			  &sender->hashPubKey))
      handlep2pReply(coreAPI->myIdentity,
		     &reply->header);
    else {
      coreAPI->sendToNode(sender,
			  &reply->header,
			  ntohl(msg->priority),
			  0);
#if VERBOSE_STATS
      statChange(stat_p2p_replies, 1);
#endif
    }
    rest = size - (sizeof(TRACEKIT_p2p_REPLY) + max * sizeof(HostIdentity)); 
    memcpy(&((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[0],
	   &((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[max],
	   rest);
    if (max * sizeof(HostIdentity) > size) {
	LOG(LOG_ERROR,
	    " assertion violated at %s:%u\n",
	    __FILE__, __LINE__);
	break;
    }
    size -= max * sizeof(HostIdentity);
    if (rest == 0)
      break;
  }
  FREE(reply);
  return OK;
}

static int csHandle(ClientHandle client,
		    CS_HEADER * message) {
  int i;
  int idx;
  TRACEKIT_CS_PROBE * csProbe;
  TRACEKIT_p2p_PROBE p2pProbe;

#if VERBOSE_STATS
  statChange(stat_cs_requests, 1);
#endif
  LOG(LOG_DEBUG,
      " TRACEKIT: client sends probe request\n");
  MUTEX_LOCK(&lock);
  idx = -1;
  for (i=0;i<clientCount;i++) {
    if (clients[i] == NULL)
      idx = i;
    if (clients[i] == client) {
      idx = i;
      break;
    }
  }
  if (idx == -1) {
    GROW(clients,
	 clientCount,
	 clientCount+1);
    idx = clientCount-1;
    clients[clientCount-1] = client;
  } else
    clients[idx] = client;
  MUTEX_UNLOCK(&lock);

  /* build probe, broadcast */
  csProbe = (TRACEKIT_CS_PROBE*) message;
  if (ntohs(csProbe->header.size) != 
      sizeof(TRACEKIT_CS_PROBE) ) {
    LOG(LOG_WARNING,
	" TRACEKIT_CS_PROBE message from client is invalid\n");
    return SYSERR;
  }
  p2pProbe.header.size = htons(sizeof(TRACEKIT_p2p_PROBE));
  p2pProbe.header.requestType = htons(TRACEKIT_p2p_PROTO_PROBE);
  p2pProbe.clientId = htonl(idx);
  p2pProbe.hopsToGo = csProbe->hops;
  p2pProbe.timestamp = htonl(TIME(NULL));
  p2pProbe.priority = csProbe->priority;
  memcpy(&p2pProbe.initiatorId,
	 coreAPI->myIdentity,
	 sizeof(HostIdentity));
  handlep2pProbe(coreAPI->myIdentity,
		 &p2pProbe.header); /* FIRST send to myself! */
  coreAPI->broadcastToConnected(&p2pProbe.header,
				ntohl(csProbe->priority),
				0);
#if VERBOSE_STATS
  statChange(stat_p2p_requests,
	     coreAPI->forAllConnectedNodes(NULL, NULL));
#endif
  return OK;
}

static void clientExitHandler(ClientHandle c) {
  int i;

  MUTEX_LOCK(&lock);
  for (i=0;i<clientCount;i++)
    if (clients[i] == c)
      clients[i] = NULL;
  MUTEX_UNLOCK(&lock);
}

int initialize_tracekit_protocol(CoreAPIForApplication * capi) {
  int ok = OK;

  MUTEX_CREATE(&lock);
  coreAPI = capi;
#if VERBOSE_STATS
  stat_cs_requests 
    = statHandle("# client trace requests received");
  stat_cs_replies
    = statHandle("# client trace replies sent");
  stat_p2p_requests
    = statHandle("# p2p trace requests received");
  stat_p2p_replies
    = statHandle("# p2p trace replies sent");
#endif
  LOG(LOG_DEBUG,
      " TRACEKIT registering handlers %d %d and %d\n",
      TRACEKIT_p2p_PROTO_PROBE,
      TRACEKIT_p2p_PROTO_REPLY,
      TRACEKIT_CS_PROTO_PROBE);
  memset(routeTable, 
	 0, 
	 MAXROUTE*sizeof(RTE));
  if (SYSERR == capi->registerHandler(TRACEKIT_p2p_PROTO_PROBE,
				      &handlep2pProbe))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(TRACEKIT_p2p_PROTO_REPLY,
				      &handlep2pReply))
    ok = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&clientExitHandler))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(TRACEKIT_CS_PROTO_PROBE,
					    (CSHandler)&csHandle))
    ok = SYSERR;
  return ok;
}

void done_tracekit_protocol() {
  coreAPI->unregisterHandler(TRACEKIT_p2p_PROTO_PROBE,
			     &handlep2pProbe);
  coreAPI->unregisterHandler(TRACEKIT_p2p_PROTO_REPLY,
			     &handlep2pReply);
  coreAPI->unregisterClientExitHandler(&clientExitHandler);
  coreAPI->unregisterClientHandler(TRACEKIT_CS_PROTO_PROBE,
				   (CSHandler)&csHandle);
  GROW(clients,
       clientCount,
       0);
  MUTEX_DESTROY(&lock);
  coreAPI = NULL;
}

/* end of tracekit.c */
