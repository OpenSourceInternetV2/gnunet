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
 * @file server/traffic.c
 * @brief tracks current traffic patterns
 * @author Christian Grothoff
 * 
 * Module to keep track of recent amounts of p2p traffic on the local
 * GNUnet node. Uses roughly 6 kb of memory given the current
 * settings. The current settings allow the minimal anonymity
 * requirements that can be confirmed to reach 15 peers in the last 32
 * minutes (for any given message type). If significantly higher
 * levels are required, the current code would need to be recompiled
 * with different values. I currently do not belive we should make
 * better traffic tracking even an option.
 */

#include "gnunet_util.h"
#include "traffic.h"
#include "tcpserver.h"

#define KEEP_TRANSMITTED_STATS YES
#define KEEP_RECEIVE_STATS YES

#if KEEP_RECEIVE_STATS
static int stat_traffic_received_by_type[MAX_p2p_PROTO_USED];
#endif

#if KEEP_TRANSMITTED_STATS
static int stat_traffic_transmitted_by_type[MAX_p2p_PROTO_USED];
#endif

/**
 * Macro to access the slot at time "t" in the history.
 */
#define HS_SLOT(a) ((a) % HISTORY_SIZE)

/**
 * Of how many peers do we keep track per message type
 * about "recent" interactions? The memory impact of
 * this value n is 8 * 3 * MAX_MESSAGE_ID * n. The current
 * number of messages is roughly a dozen, so the memory
 * impact is about 200 bytes * n, or for the default
 * of n=15 it is 3kb.
 */
#define MAX_PEER_IDs 15

/**
 * Information about when a peer was last involved
 * in a message of the given type.
 */
typedef struct {
  
  /**
   * The ".a" member of the Host identity of the peer.
   */ 
  int peerIdentity_a;

  /**
   * The time of the interaction.
   */
  unsigned int time;

} PeerDate;

/**
 * Numbers for one receive/send/self-send type.
 */
typedef struct {
  
  /**
   * When was this record last updated?
   */
  cron_t lastUpdate;

  /**
   * Time slots for processing (shifted bitvector)
   */
  unsigned int slots;

  /**
   * "peerCount" identities of the peers that we interacted with
   * most recently (abreviated identities plus timestamps)
   */
  PeerDate peers[MAX_PEER_IDs];

  /**
   * How many messages were processed? (rotating buffer)
   */ 
  unsigned int count[HISTORY_SIZE];

  /**
   * Average sizes (rotating buffer)
   */
  double avgSize[HISTORY_SIZE];

} DirectedTrafficCounter;

/**
 * Type of the internal traffic counters.
 */
typedef struct {
  
  /**
   * Statistics for sending 
   */ 
  DirectedTrafficCounter send;

  /**
   * Statistics for receiving
   */ 
  DirectedTrafficCounter receive;

} TrafficCounter;

/**
 * Lock to synchronize access.
 */
static Mutex lock;

/**
 * Highest message type seen so far.
 */
static unsigned int max_message_type = 0;

/**
 * The actual counters.
 */
static TrafficCounter ** counters = NULL;

/**
 * Update the use table dtc. A message of the given
 * size was processed interacting with a peer with
 * the given peerId.
 */
static void updateUse(DirectedTrafficCounter * dtc,
		      unsigned short size,
		      int peerId,
		      int expireOnly) {
  cron_t now;
  cron_t delta;
  unsigned int unitNow;
  unsigned int deltaUnits;
  unsigned int minPeerId;
  unsigned int minPeerTime;
  unsigned int i;
  unsigned int slot;

  cronTime(&now);
  unitNow = now / TRAFFIC_TIME_UNIT;
  delta = now - dtc->lastUpdate;
  dtc->lastUpdate = now;
  deltaUnits = delta / TRAFFIC_TIME_UNIT;

  if (NO == expireOnly) {
    /* update peer identities */
    minPeerTime = 0;
    minPeerId = 0;
    for (i=0;i<MAX_PEER_IDs;i++) {
      if (dtc->peers[i].time < minPeerTime)
	minPeerId = i;
      if (dtc->peers[i].peerIdentity_a == peerId) {
	minPeerId = i;
	break; /* if the peer is already listed, re-use
		  that slot & update the time! */
      }
    }
    dtc->peers[minPeerId].time = unitNow;
    dtc->peers[minPeerId].peerIdentity_a = peerId;
  }

  /* update expired slots: set appropriate slots to 0 */
  if (deltaUnits > HISTORY_SIZE)
    deltaUnits = HISTORY_SIZE;
  for (i=0;i<deltaUnits;i++) {
    dtc->count[HS_SLOT(unitNow - HISTORY_SIZE - i)] = 0;
    dtc->avgSize[HS_SLOT(unitNow - HISTORY_SIZE - i)] = 0.0;
  }
  
  if (NO == expireOnly) {
    int devideBy;
    
    /* update slots */
    dtc->slots = 0x80000000 | (dtc->slots >> deltaUnits);
    
    /* recompute average, increment count */
    slot = HS_SLOT(unitNow);
    dtc->count[slot]++;
    devideBy = dtc->count[slot];
    if (devideBy <= 0)
      dtc->avgSize[slot] = 0; /* how can this happen? */
    else
      dtc->avgSize[slot] 
        = ((dtc->avgSize[slot] * (dtc->count[slot]-1)) + size) / devideBy; 
  }
}

/**
 * Build the traffic counter summary to send it over
 * the network.
 * @param res where to write the summary to
 * @param dtc the internal traffic counter to convert
 * @param tcType the type of the counter (for the flags)
 * @param countTimeUnits for how long ago should we take
 *    the history into consideration (max is HISTORY_SIZE).
 * @param msgType what is the requestType of the message that the dtc is for?
 */
static void buildSummary(TRAFFIC_COUNTER * res,
			 DirectedTrafficCounter * dtc,
			 unsigned int tcType,
			 unsigned int countTimeUnits,
			 unsigned short msgType) {
  unsigned int i;
  unsigned short peerCount;
  cron_t now;
  unsigned int unitNow;
  unsigned short msgCount;
  unsigned int totalMsgSize;

  updateUse(dtc, 0, 0, YES); /* expire old entries */
  cronTime(&now);
  unitNow = now / TRAFFIC_TIME_UNIT;

  /* count number of peers that we interacted with in
     the last countTimeUnits */
  peerCount = 0;
  for (i=0;i<MAX_PEER_IDs;i++)
    if (dtc->peers[i].time > now - countTimeUnits)
      peerCount++;
  res->flags = htons(tcType|peerCount);

  /* determine number of messages and average size */
  msgCount = 0;
  totalMsgSize = 0;
  for (i=0;i<countTimeUnits;i++) {
    unsigned int slot = HS_SLOT(unitNow - i);
    totalMsgSize += dtc->count[slot] * dtc->avgSize[slot];
    msgCount += dtc->count[slot];
  }

  res->count = htons(msgCount);
  res->type = htons(msgType);
  if (msgCount > 0)
    res->avrg_size = htons(totalMsgSize / msgCount);
  else
    res->avrg_size = 0;
  res->time_slots = htonl(dtc->slots);
}

/**
 * Build a reply message for the client.
 */ 
static CS_TRAFFIC_INFO * buildReply(unsigned int countTimeUnits) {
  CS_TRAFFIC_INFO * reply;
  unsigned int count;
  unsigned int i;

  MUTEX_LOCK(&lock);
  count = 0;
  for (i=0;i<max_message_type;i++) 
    if (counters[i] != NULL) {
      if (counters[i]->send.slots != 0)
	count++;
      if (counters[i]->receive.slots != 0)
	count++;
    }
  reply = MALLOC(sizeof(CS_TRAFFIC_INFO)+
		 count * sizeof(TRAFFIC_COUNTER));
  reply->header.tcpType = htons(CS_PROTO_TRAFFIC_INFO);
  reply->header.size = htons(sizeof(CS_TRAFFIC_INFO)+
			    count * sizeof(TRAFFIC_COUNTER));
  reply->count = htonl(count);
  count = 0;
  for (i=0;i<max_message_type;i++) 
    if (counters[i] != NULL) {
      if (counters[i]->send.slots != 0) 
	buildSummary(&((CS_TRAFFIC_INFO_GENERIC*)reply)->counters[count++],
		     &counters[i]->send,
		     TC_SENT, 
		     countTimeUnits,
		     i);
      if (counters[i]->receive.slots != 0)
	buildSummary(&((CS_TRAFFIC_INFO_GENERIC*)reply)->counters[count++],
		     &counters[i]->receive,
		     TC_RECEIVED, 
		     countTimeUnits,
		     i);
    }
  
  MUTEX_UNLOCK(&lock);
  return reply;
}

static int trafficQueryHandler(ClientHandle sock,
			       const CS_HEADER * message) {
  CS_TRAFFIC_REQUEST * msg;
  CS_TRAFFIC_INFO * reply;
  int ret;

  if (sizeof(CS_TRAFFIC_REQUEST) != ntohs(message->size))
    return SYSERR;
  msg = (CS_TRAFFIC_REQUEST*) message;
  reply = buildReply(ntohl(msg->timePeriod));
  ret = sendToClient(sock, &reply->header);
  FREE(reply);
  return ret;
}



/**
 * Initialize the traffic module.
 */
void initTraffic() {
#if KEEP_RECEIVE_STATS || KEEP_TRANSMITTED_STATS
  int i;
#endif
  
#if KEEP_TRANSMITTED_STATS
  for (i=0;i<MAX_p2p_PROTO_USED;i++)
    stat_traffic_transmitted_by_type[i] = 0;
#endif
#if KEEP_RECEIVE_STATS
  for (i=0;i<MAX_p2p_PROTO_USED;i++)
    stat_traffic_received_by_type[i] = 0;
#endif

  GNUNET_ASSERT(counters == NULL);
  MUTEX_CREATE(&lock);
  if (SYSERR == registerCSHandler(CS_PROTO_TRAFFIC_QUERY,
				  &trafficQueryHandler)) 
    GNUNET_ASSERT(0);
}

/**
 * Shutdown the traffic module.
 */
void doneTraffic() {
  unsigned int i;
  
  for (i=0;i<max_message_type;i++)
    FREENONNULL(counters[i]);
  GROW(counters,
       max_message_type,
       0);
  if (SYSERR == unregisterCSHandler(CS_PROTO_TRAFFIC_QUERY,
				    &trafficQueryHandler))
    GNUNET_ASSERT(0);
  MUTEX_DESTROY(&lock);
}

/**
 * Ensure that the counters array has the appropriate
 * size and a valid traffic counter allocated for the
 * given port.
 */
static void checkPort(unsigned short port) {
  if (port >= max_message_type) 
    GROW(counters,
	 max_message_type,
	 port + 1);
  if (counters[port] == NULL) {
    counters[port] = MALLOC(sizeof(TrafficCounter));
    memset(counters[port],
	   0,
	   sizeof(TrafficCounter));
  }
}

/**
 * A message was received.  Update traffic stats.
 *
 * @param header the header of the message
 * @param sender the identity of the sender 
 */
void trafficReceive(const p2p_HEADER * header,
		    const HostIdentity * sender) {
  unsigned short port;

  port = ntohs(header->requestType);
  MUTEX_LOCK(&lock);
  checkPort(port);
  updateUse(&counters[port]->receive,
	    ntohs(header->size),
	    sender->hashPubKey.a,
	    NO);
  MUTEX_UNLOCK(&lock);
}

/**
 * A message is send.  Update traffic stats.
 * 
 * @param header the header of the message
 * @param receiver the identity of the receiver
 */
void trafficSend(const p2p_HEADER * header,
		 const HostIdentity * receiver) {
  unsigned short port;

  port = ntohs(header->requestType);
  MUTEX_LOCK(&lock);
  checkPort(port);
  updateUse(&counters[port]->send,
	    ntohs(header->size),
	    receiver->hashPubKey.a,
	    NO);
  MUTEX_UNLOCK(&lock);
}


/**
 * Get statistics over the number of messages that
 * were received or send of a given type.
 *
 * @param messageType the type of the message
 * @param sendReceive TC_SENT for sending, TC_RECEIVED for receiving
 * @param timePeriod how many TRAFFIC_TIME_UNITs to take
 *        into consideration (limited by HISTORY_SIZE)
 * @param avgMessageSize average size of the messages (set)
 * @param messageCount number of messages (set)
 * @param peerCount number of peers engaged (set)
 * @param timeDistribution bit-vector giving times of interactions,
 *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
 * @return OK on success, SYSERR on error
 */
int getTrafficStats(const unsigned short messageType,
		    const int sendReceive,
		    const unsigned int timePeriod,
		    unsigned short * avgMessageSize,
		    unsigned short * messageCount,
		    unsigned int * peerCount,
		    unsigned int * timeDistribution) {
  DirectedTrafficCounter * dtc;
  unsigned int i;
  unsigned int nowUnit;
  double totSize;

  if (counters == NULL)
    return SYSERR;
  MUTEX_LOCK(&lock);
  if ( (messageType >= max_message_type) ||
       (counters[messageType] == NULL) ) {
    *avgMessageSize = 0;
    *messageCount = 0;
    *peerCount = 0;
    *timeDistribution = 0;
    MUTEX_UNLOCK(&lock);
    return OK;
  }

  if (sendReceive == TC_SENT)
    dtc = &counters[messageType]->send;
  else
    dtc = &counters[messageType]->receive;
  updateUse(dtc, 0, 0, YES);

  nowUnit = cronTime(NULL) / TRAFFIC_TIME_UNIT;
  *peerCount = 0;
  *messageCount = 0;
  totSize = 0;
  for (i=0;i<MAX_PEER_IDs;i++) 
    if (dtc->peers[i].time > nowUnit - timePeriod)
      (*peerCount)++;
  for (i=0;i<timePeriod;i++) {
    unsigned int slot;

    slot = HS_SLOT(nowUnit-i);
    (*messageCount) += dtc->count[slot];
    totSize += dtc->count[slot] * dtc->avgSize[slot];
  }
  if (*messageCount>0)
    *avgMessageSize = (unsigned short) (totSize / (*messageCount));
  else
    *avgMessageSize = 0;
  *timeDistribution = dtc->slots;
  MUTEX_UNLOCK(&lock);
  return OK;
}



void updateTrafficSendCounter(unsigned short ptyp,
			      unsigned short plen) {
#if KEEP_TRANSMITTED_STATS
  if (ptyp >= MAX_p2p_PROTO_USED) 
    return; /* not tracked */
  if (0 == stat_traffic_transmitted_by_type[ptyp]) {
    char * s;
    s = MALLOC(256);
    SNPRINTF(s, 
	     256,
	     _("# bytes transmitted of type %d"),
	     ptyp);
    stat_traffic_transmitted_by_type[ptyp]
      = statHandle(s);
    FREE(s);
  }
  statChange(stat_traffic_transmitted_by_type[ptyp],
	     plen);
#endif
}

void updateTrafficReceiveCounter(unsigned short ptyp,
				 unsigned short plen) {
  if (ptyp < MAX_p2p_PROTO_USED) {
    if (0 == stat_traffic_received_by_type[ptyp]) {
      char * s;
      s = MALLOC(256);
      SNPRINTF(s, 
	       256,
	       _("# bytes received of type %d"),
	       ptyp);
      stat_traffic_received_by_type[ptyp]
	= statHandle(s);
      FREE(s);
    }
    statChange(stat_traffic_received_by_type[ptyp],
	       plen);
  }
}


/* end of traffic.c */
