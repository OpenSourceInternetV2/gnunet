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
 * @file gap/gap.c
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 *
 * The code roughly falls into two main functionality groups:
 *
 * - keeping track of queries that have been routed,
 *   sending back replies along the path, deciding
 *   which old queries to drop from the routing table
 * - deciding when to forward which query to which
 *   set of peers; this includes tracking from where
 *   we receive responses to make an educated guess
 *   (also called 'hot path' routing).
 *
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_gap_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_traffic_service.h"
#include "gnunet_topology_service.h"

#define DEBUG_GAP NO

#define EXTRA_CHECKS YES


/* ***************** policy constants **************** */

/**
 * Until which load do we consider the peer idle and do not
 * charge at all?
 */
#define IDLE_LOAD_THRESHOLD 50

/**
 * By which amount do we decrement the TTL for simple forwarding /
 * indirection of the query; in milli-seconds.  Set somewhat in
 * accordance to your network latency (above the time it'll take you
 * to send a packet and get a reply).
 */
#define TTL_DECREMENT 5 * cronSECONDS

/**
 * Send answer if local files match
 */
#define QUERY_ANSWER   0x00020000

/**
 * Forward the query, priority is encoded in QUERY_PRIORITY_BITMASK
 */
#define QUERY_FORWARD  0x00040000

/**
 * Indirect the query (use this as the originating node)
 */
#define QUERY_INDIRECT 0x00080000

/**
 * Drop the query if & with this bitmask is 0
 */
#define QUERY_DROPMASK (QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT)

/**
 * Bandwidth value of an (effectively) 0-priority query.
 */
#define QUERY_BANDWIDTH_VALUE 0.01

/**
 * Bandwidth value of a 0-priority content (must be
 * fairly high compared to query since content is
 * typically significantly larger -- and more valueable
 * since it can take many queries to get one piece of
 * content).
 */
#define CONTENT_BANDWIDTH_VALUE 0.8

/**
 * Default size of the bitmap that we use for marking to which
 * peers a query has already been sent to.  16 byte = 128 bits
 */
#define BITMAP_SIZE 16

/**
 * Of how many outbound queries do we simultaneously keep track?
 */
#define QUERY_RECORD_COUNT 512

/**
 * How much is a query worth 'in general' (even
 * if there is no trust relationship between
 * the peers!).  Multiplied by the number of queries
 * in the request.  20 is for '20 bytes / hash',
 * so this is kind of the base unit.
 */
#define BASE_QUERY_PRIORITY 20

/**
 * How much is a response worth 'in general'.  Since replies are
 * roughly 1k and should be much (factor of 4) preferred over queries
 * (which have a base priority of 20, which yields a base unit of
 * roughly 1 per byte).  Thus if we set this value to 4092 we'd rather
 * send a reply instead of a query unless the queries have (on
 * average) a priority that is more than double the reply priority
 * (note that querymanager multiplies the query priority with 2 to
 * compute the scheduling priority).
 */
#define BASE_REPLY_PRIORITY 4092

/**
 * minimum indirection table size, defaults to 8192 entries, reduce if
 * you have very little memory, enlarge if you start to overflow often
 * and have memory available.<p>
 *
 * If the average query lives for say 1 minute (10 hops), and you have
 * a 56k connection (= 420 kb/minute, or approximately 8000
 * queries/minute) the maximum reasonable routing table size would
 * thus be 8192 entries.  Every entry takes about 68 bytes.<p>
 *
 * The larger the value is that you pick here, the greater your
 * anonymity can become.  It also can improve your download speed.<p>
 *
 * Memory consumption:
 * <ul>
 * <li>8192 => 560k indirection table => approx. 6 MB gnunetd</li>
 * <li>65536 => 4456k indirection table => approx. 10 MB gnuentd</li>
 * </ul>
 * <p>
 * THE VALUE YOU PICK MUST BE A POWER OF 2, for example:
 * 128, 256, 512, 1024, 2048, 4092, 8192, 16384, 32768, 65536
 */
#define MIN_INDIRECTION_TABLE_SIZE 1024
/* #define MIN_INDIRECTION_TABLE_SIZE 8 */

/**
 * Under certain cirumstances, two peers can interlock in their
 * routing such that both have a slot that is blocked exactly until
 * the other peer will make that slot available.  This is the
 * probability that one will give in.  And yes, it's a hack.  It
 * may not be needed anymore once we add collision-resistance to
 * the routing hash table.
 */
#define TIE_BREAKER_CHANCE 4

/**
 * For how many _local_ requests do we track the current, non-zero
 * request priorities for rewarding peers that send replies?  If this
 * number is too low, we will 'forget' to reward peers for good
 * replies (and our routing will degrade).  If it is too high, we'll
 * scan though a large array for each content message and waste
 * memory.<p>
 *
 * A good value reflects the number of concurrent, local queries that
 * we expect to see.
 */
#define MAX_REWARD_TRACKS 128

/**
 * ITE modes for addToSlot.
 */
#define ITE_REPLACE 0
#define ITE_GROW 1


/* **************** Types ****************** */

/**
 * Type of the results of the polciy module
 */
typedef unsigned int QUERY_POLICY;

/**
 * Request for content. The number of queries can
 * be determined from the header size.
 */
typedef struct {
  P2P_MESSAGE_HEADER header;

  /**
   * Type of the query (block type).
   */
  unsigned int type;

  /**
   * How important is this request (network byte order)
   */
  unsigned int priority;

  /**
   * Relative time to live in cronMILLIS (network byte order)
   */
  int ttl;

  /**
   * To whom to return results?
   */
  PeerIdentity returnTo;

  /**
   * Hashcodes of the file(s) we're looking for.
   * Details depend on the query type.
   */
  HashCode512 queries[1];

} P2P_gap_query_MESSAGE;

/**
 * Return message for search result.
 */
typedef struct {
  P2P_MESSAGE_HEADER header;

  HashCode512 primaryKey;

} P2P_gap_reply_MESSAGE;

/**
 * In this struct, we store information about a
 * query that is being send from the local node to
 * optimize the sending strategy.
 */
typedef struct {

  /**
   * How often did we send this query so far?
   */
  unsigned int sendCount;

  /**
   * How many nodes were connected when we initated sending this
   * query?
   */
  unsigned int activeConnections;

  /**
   * What is the total distance of the query to the connected nodes?
   */
  unsigned long long totalDistance;

  /**
   * The message that we are sending.
   */
  P2P_gap_query_MESSAGE * msg;

  /**
   * How important would it be to send the message to all peers in
   * this bucket?
   */
  int * rankings;

  /**
   * When do we stop forwarding (!) this query?
   */
  cron_t expires;

  /**
   * To which peer will we never send this message?
   */
  PeerIdentity noTarget;

  /**
   * Bit-map marking the hostIndices (computeIndex) of nodes that have
   * received this query already.  Note that the bit-map has a maximum
   * size, if the index is out-of-bounds, it is hashed into the
   * smaller size of the bitmap. There may thus be nodes with
   * identical indices, in that case, only one of the nodes will
   * receive the query.
   */
  unsigned char bitmap[BITMAP_SIZE];

  /**
   * To how many peers has / will this query be transmitted?
   */
  unsigned int transmissionCount;

} QueryRecord;

/**
 * Indirection table entry. Lists what we're looking for,
 * where to forward it, and how long to keep looking for it.
 * Keep this struct as small as possible -- an array of these
 * takes 80% of GNUnet's memory.
 */
typedef struct {
  /**
   * What are we waiting for?
   */
  HashCode512 primaryKey;

  /**
   * For what type of reply are we waiting?
   */
  unsigned int type;

  /**
   * How much is this query worth to us, that is, how much would
   * this node be willing to "pay" for an answer that matches the
   * hash stored in this ITE? (This is NOT the inbound priority,
   * it is the trust-adjusted inbound priority.)
   */
  unsigned int priority;

  /**
   * When can we forget about this entry?
   */
  cron_t ttl;

  /**
   * Which replies have we already seen?
   */
  unsigned int seenIndex;

  int seenReplyWasUnique; /* YES/NO, only valid if seenIndex == 1 */

  /**
   * Hashcodes of the encrypted (!) replies that we have forwarded so far
   */
  HashCode512 * seen;

  /**
   * Who are these hosts?
   */
  PeerIdentity * destination;

  /**
   * How many hosts are waiting for an answer to this query (length of
   * destination array)
   */
  unsigned int hostsWaiting;

  /**
   * Do we currently have a response in the delay loop (delays are
   * introduced to make traffic analysis harder and thus enable
   * anonymity)?  This marker is set to avoid looking up content again
   * before the first content exits the delay loop.  Since this *not*
   * looking up content again is not externally visible, it is ok to
   * do this optimization to reduce disk accesses (see Mantis bug
   * #407).
   */
  int successful_local_lookup_in_delay_loop;

} IndirectionTableEntry;

/**
 * Avoiding concurrent lookups for the same ITE: lock to grant
 * access to peers to perform a lookup that matches this ITE entry.
 */
static Mutex lookup_exclusion;


/**
 * @brief structure to keep track of which peers send responses
 *  to queries from a certain peer at the moment
 * Linked list of peer ids with number of replies received.
 */
typedef struct RL_ {
  struct RL_ * next;
  PeerIdentity responder;
  unsigned int responseCount;
} ResponseList;

/**
 * Structure for tracking from which peer we got valueable replies for
 * which clients / other peers.
 */
typedef struct RTD_ {

  /**
   * This is a linked list.
   */
  struct RTD_ * next;

  /**
   * For which client does this entry track replies?
   */
  PeerIdentity queryOrigin;

  /**
   * Linked list of peers that responded, with
   * number of responses.
   */
  ResponseList * responseList;

  /**
   * Time at which we received the last reply
   * for this client.  Used to discard old entries
   * eventually.
   */
  TIME_T lastReplyReceived;
} ReplyTrackData;

/**
 * Tracking of just reward data (how much trust a peer
 * can gain for a particular reply).
 */
typedef struct {
  HashCode512 query;
  unsigned int prio;
} RewardEntry;



/* ********************** GLOBALS ******************** */

/**
 * GNUnet core.
 */
static CoreAPIForApplication * coreAPI;

/**
 * Identity service.
 */
static Identity_ServiceAPI * identity;

/**
 * Topology service.
 */
static Topology_ServiceAPI * topology;

/**
 * Traffic service.
 */
static Traffic_ServiceAPI * traffic;

/**
 * For migration / local stores, local lookup and
 * content verification.
 */
static Blockstore * bs;

/**
 * Function that can be used to identify unique
 * replies.
 */
static UniqueReplyIdentifier uri;

static ReplyHashFunction rhf;

/**
 * The routing table. This table has entries for all
 * queries that we have recently send out. It helps
 * GNUnet to route the replies back to the respective
 * sender.
 */
static IndirectionTableEntry * ROUTING_indTable_;

/**
 * Size of the indirection table specified in gnunet.conf
 */
static unsigned int indirectionTableSize;

/**
 * Constant but peer-dependent value that randomizes the construction
 * of the indices into the routing table.  See
 * computeRoutingIndex.
 */
static unsigned int random_qsel;

/**
 * Array of the queries we are currently sending out.
 */
static QueryRecord queries[QUERY_RECORD_COUNT];

/**
 * Mutex for all gap structures.
 */
static Mutex * lock;

/**
 * Linked list tracking reply statistics.  Synchronize access using
 * the queryManagerLock!
 */
static ReplyTrackData * rtdList = NULL;

static RewardEntry * rewards = NULL;
static unsigned int rewardSize = 0;
static unsigned int rewardPos = 0;


/* ****************** helper functions ***************** */

/**
 * Adjust the TTL (priority limitation heuristic)
 */
static int adjustTTL(int ttl, unsigned int prio) {
  if ( (ttl > 0) &&
       (ttl > (int)(prio+3)*TTL_DECREMENT) )
    ttl = (int) (prio+3)*TTL_DECREMENT; /* bound! */
  return ttl;
}

/**
 * A query has been received. The question is, if it should be
 * forwarded and if with which priority. Routing decisions(to whom)
 * are to be taken elsewhere.  <p>
 *
 * @param sender the host sending us the query
 * @param priority the priority the query had when it came in,
 *        may be an arbitrary number if the
 *        sender is malicious! Cap by trustlevel first!
 *        Set to the resulting priority.
 * @return binary encoding: QUERY_XXXX constants
 */
static QUERY_POLICY
evaluateQuery(const PeerIdentity * sender,
	      unsigned int * priority) {
  unsigned int netLoad = getNetworkLoadUp();

  if ( (netLoad == (unsigned int) -1) ||
       (netLoad < IDLE_LOAD_THRESHOLD) ) {
    *priority = 0; /* minimum priority, no charge! */
    return QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
  }
  /* charge! */
  (*priority) = - identity->changeHostTrust(sender, -(*priority));
  if (netLoad < IDLE_LOAD_THRESHOLD + (*priority))
    return QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
  else if (netLoad < 90 + 10 * (*priority))
    return QUERY_ANSWER | QUERY_FORWARD;
  else if (netLoad < 100)
    return QUERY_ANSWER;
  else
    return 0; /* drop entirely */
}

/**
 * Map the id to an index into the bitmap array.
 */
static int getIndex(const PeerIdentity * id) {
  unsigned int index;

  index = coreAPI->computeIndex(id);
  if (index >= 8*BITMAP_SIZE)
    index = index & (8*BITMAP_SIZE-1);
  return index;
}

static void setBit(QueryRecord * qr,
		   int bit) {
  unsigned char theBit = (1 << (bit & 7));
  qr->bitmap[bit>>3] |= theBit;
}

static int getBit(const QueryRecord * qr,
		  int bit) {
  unsigned char theBit = (1 << (bit & 7));
  return (qr->bitmap[bit>>3] & theBit) > 0;
}

/* ************* tracking replies, routing queries ********** */

/**
 * Cron job that ages the RTD data and that frees
 * memory for entries that reach 0.
 */
static void ageRTD(void * unused) {
  ReplyTrackData * pos;
  ReplyTrackData * prev;
  ResponseList * rpos;
  ResponseList * rprev;

  MUTEX_LOCK(lock);
  prev = NULL;
  pos = rtdList;
  while (pos != NULL) {
    /* after 10 minutes, always discard everything */
    if (pos->lastReplyReceived < TIME(NULL) - 600) {
      while (pos->responseList != NULL) {
	rpos = pos->responseList;
	pos->responseList = rpos->next;
	FREE(rpos);
      }
    }
    /* otherwise, age reply counts */
    rprev = NULL;
    rpos = pos->responseList;
    while (rpos != NULL) {
      rpos->responseCount = rpos->responseCount / 2;
      if (rpos->responseCount == 0) {	
	if (rprev == NULL)
	  pos->responseList = rpos->next;
	else
	  rprev->next = rpos->next;
	FREE(rpos);
	if (rprev == NULL)
	  rpos = pos->responseList;
	else
	  rpos = rprev->next;
	continue;
      }
    }
    /* if we have no counts for a peer anymore,
       free pos entry */
    if (pos->responseList == NULL) {
      if (prev == NULL)
	rtdList = pos->next;
      else
	prev->next = pos->next;
      FREE(pos);
      if (prev == NULL)
	pos = rtdList;
      else
	pos = prev->next;
      continue;
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(lock);
}

/**
 * We received a reply from 'responder' to a query received from
 * 'origin'.  Update reply track data!
 *
 * @param origin
 * @param responder peer that send the reply
 */
static void updateResponseData(const PeerIdentity * origin,
			       const PeerIdentity * responder) {
  ReplyTrackData * pos;
  ReplyTrackData * prev;
  ResponseList * rpos;
  ResponseList * rprev;

  if (responder == NULL)
    return; /* we don't track local responses */
  MUTEX_LOCK(lock);
  pos = rtdList;
  prev = NULL;
  while (pos != NULL) {
    if (hostIdentityEquals(origin,
			   &pos->queryOrigin))
      break; /* found */
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL) {
    pos = MALLOC(sizeof(ReplyTrackData));
    pos->next = NULL;
    pos->responseList = NULL;
    if (prev == NULL)
      rtdList = pos;
    else
      prev->next = pos;
  }
  TIME(&pos->lastReplyReceived);
  rpos = pos->responseList;
  rprev = NULL;
  while (rpos != NULL) {
    if (0 == memcmp(responder,
		    &rpos->responder,
		    sizeof(PeerIdentity))) {
      rpos->responseCount++;
      MUTEX_UNLOCK(lock);
      return;
    }
    rprev = rpos;
    rpos = rpos->next;
  }
  rpos = MALLOC(sizeof(ResponseList));
  rpos->responseCount = 1;
  rpos->responder = *responder;
  rpos->next = NULL;
  if (rprev == NULL)
    pos->responseList = rpos;
  else
    rprev->next = rpos;
  MUTEX_UNLOCK(lock);
}

/**
 * Callback method for filling buffers. This method is invoked by the
 * core if a message is about to be send and there is space left for a
 * QUERY.  We then search the pending queries and fill one (or more)
 * in if possible.
 *
 * Note that the same query is not transmitted twice to a peer and that
 * queries are not queued more frequently than 2 TTL_DECREMENT.
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
fillInQuery(const PeerIdentity * receiver,
	    void * position,
	    unsigned int padding) {
  static unsigned int pos = 0;
  unsigned int start;
  unsigned int delta;
  cron_t now;
  QueryRecord * qr;

  cronTime(&now);
  MUTEX_LOCK(lock);
  start = pos;
  delta = 0;
  while (padding - delta > sizeof(P2P_gap_query_MESSAGE)) {
    qr = &queries[pos];
    if ( (qr->expires > now) &&
	 (0 == getBit(qr, getIndex(receiver))) &&
	 (! (equalsHashCode512(&receiver->hashPubKey,
			       &qr->noTarget.hashPubKey)) ) &&
	 (! (equalsHashCode512(&receiver->hashPubKey,
			       &qr->msg->returnTo.hashPubKey)) ) &&
	 (padding - delta >= ntohs(qr->msg->header.size) ) ) {
      setBit(&queries[pos],
	     getIndex(receiver));
      memcpy(&((char*)position)[delta],
	     qr->msg,
	     ntohs(qr->msg->header.size));
      qr->sendCount++;
      delta += ntohs(qr->msg->header.size);
    }
    pos++;
    if (pos >= QUERY_RECORD_COUNT)
      pos = 0;
    if (pos == start)
      break;
  }
  MUTEX_UNLOCK(lock);
  return delta;
}

/**
 * Select a subset of the peers for forwarding.  Called
 * on each connected node by the core.
 */
static void hotpathSelectionCode(const PeerIdentity * id,
				 void * cls) {
  QueryRecord * qr = cls;
  ReplyTrackData * pos;
  ResponseList * rp;
  int ranking = 0;
  int distance;

  /* compute some basic ranking based on historical
     queries from the same origin */
  pos = rtdList;
  while (pos != NULL) {
    if (equalsHashCode512(&pos->queryOrigin.hashPubKey,
			  &qr->noTarget.hashPubKey))
      break;
    pos = pos->next;
  }
  if (pos != NULL) {
    rp = pos->responseList;
    while (rp != NULL) {
      if (equalsHashCode512(&rp->responder.hashPubKey,
			    &id->hashPubKey))
	break;
      rp = rp->next;
    }
    if (rp != NULL) {
      if (rp->responseCount < 0xFFFF)
	ranking = 0x7FFF * rp->responseCount;
      else
	ranking = 0x7FFFFFF;
    }
  }
  distance
    = distanceHashCode512(&qr->msg->queries[0],
			  &id->hashPubKey);
  if (distance <= 0)
    distance = 1;
  ranking += 0xFFFF / (1 + weak_randomi(distance));
  ranking += 1 + weak_randomi(0xFF); /* small random chance for everyone */
  if (equalsHashCode512(&id->hashPubKey,
			&qr->noTarget.hashPubKey))
    ranking = 0; /* no chance for blocked peers */
  qr->rankings[getIndex(id)] = ranking; 
}

/**
 * A "PerNodeCallback" method that forwards the query to the selected
 * nodes.
 */
static void sendToSelected(const PeerIdentity * id,
			   void * cls) {
  const QueryRecord * qr = cls;
#if DEBUG_GAP
  EncName encq;
  EncName encp;
#endif

  if ( (equalsHashCode512(&id->hashPubKey,
			  &qr->noTarget.hashPubKey)) ||
       (equalsHashCode512(&id->hashPubKey,
			  &qr->msg->returnTo.hashPubKey)) )
    return; /* never send back to source */

  if (getBit(qr, getIndex(id)) == 1) {
#if DEBUG_GAP
    IFLOG(LOG_DEBUG,
	  hash2enc(&id->hashPubKey,
		   &encp);
	  hash2enc(&qr->msg->queries[0],
		   &encq));
    LOG(LOG_DEBUG,
	"Sending query `%s' to `%s'\n",
	&encq,
	&encp);
#endif
    coreAPI->unicast(id,
		     &qr->msg->header,
		     BASE_QUERY_PRIORITY
		     * ntohl(qr->msg->priority) * 2,
		     TTL_DECREMENT);
  }
}

/**
 * Take a query and forward it to the appropriate number of nodes
 * (depending on load, queue, etc).
 */
static void forwardQuery(const P2P_gap_query_MESSAGE * msg,
			 const PeerIdentity * excludePeer) {
  cron_t now;
  QueryRecord * qr;
  QueryRecord dummy;
  cron_t oldestTime;
  cron_t expirationTime;
  int oldestIndex;
  int i;
  int noclear = NO;

  cronTime(&now);
  MUTEX_LOCK(lock);

  oldestIndex = -1;
  expirationTime = now + ntohl(msg->ttl);
  oldestTime = expirationTime;
  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    if (queries[i].expires < oldestTime) {
      oldestTime = queries[i].expires;
      oldestIndex = i;
    }
    if (queries[i].msg == NULL)
      continue;
    if ( (queries[i].msg->header.size == msg->header.size) &&
	 (0 == memcmp(&queries[i].msg->queries[0],
		      &msg->queries[0],
		      ntohs(msg->header.size)
		      - sizeof(P2P_gap_query_MESSAGE)
		      + sizeof(HashCode512))) ) {
      /* We have exactly this query pending already.
	 Replace existing query! */
      oldestIndex = i;
      if ( (queries[i].expires > now - 4 * TTL_DECREMENT) && /* not long expired */
	   (weak_randomi(4) != 0) ) {
	/* do not clear the bitmap describing which peers we have
	   forwarded the query to already; but do this only with high
	   probability since we may want to try again if the query is
	   retransmitted lots (this can happen if this is the only
	   query; we may forward it to all connected peers and get no
	   reply.  If the initiator keeps retrying, we want to
	   eventually forward it again.

	   Note that the initial probability here (0.6.0/0.6.1) was
	   very low (1:64), which is far too low considering that the
	   clients do an exponential back-off.  The rule is a pure
	   optimization, and as such the probability that we
	   eventually forward must be significant.  25% seems to work
	   better... (extra-note: in small testbeds, the problem
	   is bigger than in a larger network where the case that
	   a query stays in the QM indefinitely might be much more
           rare; so don't just trust a micro-scale benchmark when
           trying to figure out an 'optimal' threshold). */
	noclear = YES;
      }
      break; /* this is it, do not scan for other
		'oldest' entries */
    }
  }
  if (oldestIndex == -1) {				
    qr = &dummy;
  } else {
    qr = &queries[oldestIndex];
    FREENONNULL(qr->msg);
    qr->msg = NULL;
  }
  qr->expires = expirationTime;
  qr->transmissionCount = 0;
  qr->msg = MALLOC(ntohs(msg->header.size));
  memcpy(qr->msg,
	 msg,
	 ntohs(msg->header.size));
  if (noclear == NO) {
    int j;
    unsigned long long rankingSum;
    memset(&qr->bitmap[0],
	   0,
	   BITMAP_SIZE);
    if (excludePeer != NULL)
      qr->noTarget = *excludePeer;
    else
      qr->noTarget = *coreAPI->myIdentity;
    qr->totalDistance = 0;
    qr->rankings = MALLOC(sizeof(int)*8*BITMAP_SIZE);
    qr->activeConnections
      = coreAPI->forAllConnectedNodes
      (&hotpathSelectionCode,
       qr);
    /* actual selection, proportional to rankings
       assigned by hotpathSelectionCode ... */
    rankingSum = 0;
    for (i=0;i<8*BITMAP_SIZE;i++)
      rankingSum += qr->rankings[i];
    if (qr->activeConnections > 0) {
      /* select 4 peers for forwarding */
      for (i=0;i<4;i++) {
	unsigned long long sel;
	unsigned long long pos;

	if (rankingSum == 0)
	  break;
	sel = weak_randomi64(rankingSum);
	pos = 0;	
	for (j=0;j<8*BITMAP_SIZE;j++) {
	  pos += qr->rankings[j];
	  if (pos > sel) {
	    setBit(qr, j);
	    GNUNET_ASSERT(rankingSum >= qr->rankings[j]);
	    rankingSum -= qr->rankings[j];
	    qr->rankings[j] = 0;
	    break;
	  }
	}
      }
    }
    FREE(qr->rankings);
    qr->rankings = NULL;
    /* now forward to a couple of selected nodes */
    coreAPI->forAllConnectedNodes
      (&sendToSelected,
       qr);
    if (qr == &dummy)
      FREE(dummy.msg);
  }
  MUTEX_UNLOCK(lock);
}

/**
 * Stop transmitting a certain query (we don't route it anymore or
 * we have learned the answer).
 */
static int dequeueQuery(const HashCode512 * query) {
  int i;
  int ret;
  QueryRecord * qr;

  ret = SYSERR;
  MUTEX_LOCK(lock);
  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    qr = &queries[i];
    if( qr->msg != NULL ) {
      if (equalsHashCode512(query,
			    &qr->msg->queries[0])) {
	qr->expires = 0; /* expire NOW! */
	ret = OK;
	break;
      }
    }
  }
  MUTEX_UNLOCK(lock);
  return ret;
}

/* ********** tracking queries, forwarding replies ********** */

/**
 * Compute the hashtable index of a host id.
 */
static unsigned int computeRoutingIndex(const HashCode512 * query) {
  unsigned int res
    = (((unsigned int*)query)[0] +
       ((unsigned int*)query)[1] * random_qsel)
    % indirectionTableSize;
  GNUNET_ASSERT(res < indirectionTableSize);
  return res;
}

/**
 * Use content (forward to whoever sent the query).
 * @param hostId the peer from where the content came,
 *     NULL for the local peer
 */
static int useContent(const PeerIdentity * hostId,
		      const P2P_gap_reply_MESSAGE * pmsg);

/**
 * Call useContent "later" and then free the pmsg.
 */
static void useContentLater(void * data) {
  P2P_gap_reply_MESSAGE * pmsg = data;
  useContent(NULL,
	     pmsg);
  FREE(pmsg);
}

/**
 * Queue a reply with cron to simulate
 * another peer returning the response with
 * some latency (and then route as usual).
 *
 * @param sender the next hop
 * @param result the content that was found
 * @param data is a DataContainer which
 *  wraps the content in the format that
 *  can be passed to the FS module (GapWrapper),
 *  which in turn wraps the DBlock (including
 *  the type ID).
 */
static void queueReply(const PeerIdentity * sender,
		       const HashCode512 * primaryKey,
		       const DataContainer * data) {
  P2P_gap_reply_MESSAGE * pmsg;
  IndirectionTableEntry * ite;
  unsigned int size;
#if DEBUG_GAP
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(primaryKey,
		 &enc));
  LOG(LOG_DEBUG,
      "Gap queues reply to query `%s' for later use.\n",
      &enc);
#endif

#if EXTRA_CHECKS
  /* verify data is valid */
  uri(data,
      ANY_BLOCK,
      primaryKey);
#endif

  ite = &ROUTING_indTable_[computeRoutingIndex(primaryKey)];
  if (! equalsHashCode512(&ite->primaryKey,
			  primaryKey) ) {
#if DEBUG_GAP
    LOG(LOG_DEBUG,
	"GAP: Dropping reply, routing table has no query associated with it (anymore)\n");
#endif
    return; /* we don't care for the reply (anymore) */
  }
  if (YES == ite->successful_local_lookup_in_delay_loop) {
#if DEBUG_GAP
    LOG(LOG_DEBUG,
	"GAP: Dropping reply, found reply locally during delay\n");
#endif
    return; /* wow, really bad concurrent DB lookup and processing for
	       the same query.  Well, at least we should not also
	       queue the delayed reply twice... */
  }
  size = sizeof(P2P_gap_reply_MESSAGE) + ntohl(data->size) - sizeof(DataContainer);
  if (size >= MAX_BUFFER_SIZE) {
    BREAK();
    return;
  }
  ite->successful_local_lookup_in_delay_loop = YES;
  pmsg = MALLOC(size);
  pmsg->header.size
    = htons(size);
  pmsg->header.type
    = htons(P2P_PROTO_gap_RESULT);
  pmsg->primaryKey
    = *primaryKey;
  memcpy(&pmsg[1],
	 &data[1],
	 size - sizeof(P2P_gap_reply_MESSAGE));
  /* delay reply, delay longer if we are busy (makes it harder
     to predict / analyze, too). */
  addCronJob(&useContentLater,
	     weak_randomi(TTL_DECREMENT),
	     0,
	     pmsg);
}

static void addReward(const HashCode512 * query,
		      unsigned int prio) {
  if (prio == 0)
    return;
  MUTEX_LOCK(lock);
  rewards[rewardPos].query = *query;
  rewards[rewardPos].prio = prio;
  rewardPos++;
  if (rewardPos == rewardSize)
    rewardPos = 0;
  MUTEX_UNLOCK(lock);
}

static unsigned int claimReward(const HashCode512 * query,
				const PeerIdentity * peer) {
  int i;
  unsigned int ret;

  ret = 0;
  MUTEX_LOCK(lock);
  for (i=0;i<rewardSize;i++) {
    if (equalsHashCode512(query,
			  &rewards[i].query)) {
      ret += rewards[i].prio;
      rewards[i].prio = 0;
    }
  }
  MUTEX_UNLOCK(lock);
  return ret;
}


/**
 * Add an entry to the routing table. The lock on the ite
 * must be held.
 *
 * @param mode replace or extend an existing entry?
 * @param ite slot in the routing table that is manipulated
 * @param query the query to look for
 * @param ttl how long to keep the new entry, relative ttl
 * @param priority how important is the new entry
 * @param sender for which node is the entry
 * @return OK if sender was added, SYSERR if existed already
 *            in the queue
 */
static int addToSlot(int mode,
		     IndirectionTableEntry * ite,
		     const HashCode512 * query,
		     int ttl,
		     unsigned int priority,
		     const PeerIdentity * sender) {
  unsigned int i;
  cron_t now;
#if DEBUG__GAP
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(query,
		 &enc));
  LOG(LOG_DEBUG,
      "GAP: Queueing query '%s' in slot %p\n",
      &enc,
      ite);
#endif
  GNUNET_ASSERT(sender != NULL); /* do NOT add to RT for local clients! */
  cronTime(&now);
  if (mode == ITE_REPLACE) {
    GROW(ite->seen,
	 ite->seenIndex,
	 0);
    ite->seenReplyWasUnique = NO;
    if (equalsHashCode512(query,
			  &ite->primaryKey)) {
      ite->ttl = now + ttl;
      ite->priority += priority;
      for (i=0;i<ite->hostsWaiting;i++)
	if (equalsHashCode512(&ite->destination[i].hashPubKey,
			      &sender->hashPubKey))
	  return SYSERR;
    } else {
      ite->successful_local_lookup_in_delay_loop = NO;
      /* different request, flush pending queues */
      dequeueQuery(&ite->primaryKey);
      ite->primaryKey = *query;
      GROW(ite->destination,
	   ite->hostsWaiting,
	   0);
      ite->ttl = now + ttl;
      ite->priority = priority;
    }
  } else { /* GROW mode */
    GNUNET_ASSERT(equalsHashCode512(query,
				    &ite->primaryKey));
    for (i=0;i<ite->hostsWaiting;i++)
      if (equalsHashCode512(&sender->hashPubKey,
			    &ite->destination[i].hashPubKey))
	return SYSERR; /* already there! */
    /* extend lifetime */
    if (ite->ttl < now + ttl)
      ite->ttl = now + ttl;
    ite->priority += priority;
  }
  GROW(ite->destination,
       ite->hostsWaiting,
       ite->hostsWaiting+1);
  ite->destination[ite->hostsWaiting-1] = *sender;
  /* again: new listener, flush seen list */
  GROW(ite->seen,
       ite->seenIndex,
       0);
  ite->seenReplyWasUnique = NO;
  return OK;
}

/**
 * Find out, if this query is already pending. If the ttl of
 * the new query is higher than the ttl of an existing query,
 * NO is returned since we should re-send the query.<p>
 *
 * If YES is returned, the slot is also marked as used by
 * the query and the sender (HostId or socket) is added.<p>
 *
 * This method contains a heuristic that attempts to do its best to
 * route queries without getting too many cycles, send a query and
 * then drop it from the routing table without sending a response,
 * etc.  Before touching this code, definitely consult Christian
 * (christian@grothoff.org) who has put more bugs in these five lines
 * of code than anyone on this planet would think is possible.
 *
 *
 * @param query the hash to look for
 * @param ttl how long would the new query last
 * @param priority the priority of the query
 * @param sender which peer transmitted the query?
 * @param isRouted set to OK if we can route this
 *        query, SYSERR if we can not
 * @param doForward is set to OK if we should
 *        forward the query, SYSERR if not
 * @return a case ID for debugging
 */
static int needsForwarding(const HashCode512 * query,
			   int ttl,
			   unsigned int priority,
			   const PeerIdentity * sender,
			   int * isRouted,
			   int * doForward) {
  IndirectionTableEntry * ite;
  cron_t now;

  cronTime(&now);
  ite = &ROUTING_indTable_[computeRoutingIndex(query)];

  if ( ( ite->ttl < now - TTL_DECREMENT * 10) &&
       ( ttl > - TTL_DECREMENT * 5) ) {
    addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
    *isRouted = YES;
    *doForward = YES;
    return 21;
  }
  if ( ( ttl < 0) &&
       (equalsHashCode512(query,
			  &ite->primaryKey) ) ) {
    /* if ttl is "expired" and we have
       the exact query pending, route
       replies but do NOT forward _again_! */
    addToSlot(ITE_GROW, ite, query, ttl, priority, sender);
    *isRouted = NO;
    /* don't go again, we are not even going to reset the seen
       list, so why bother looking locally again, if we would find
       something, the seen list would block sending the reply anyway
       since we're not resetting that (ttl too small!)! */
    *doForward = NO;
    return 0;
  }

  if ( (ite->ttl + (TTL_DECREMENT * topology->estimateNetworkSize()) <
	(cron_t)(now + ttl)) &&
       (ite->ttl < now) ) {
    /* expired AND is significantly (!)
       longer expired than new query */
    /* previous entry relatively expired, start using the slot --
       and kill the old seen list!*/
    GROW(ite->seen,
	 ite->seenIndex,
	 0);
    ite->seenReplyWasUnique = NO;
    if ( equalsHashCode512(query,
			   &ite->primaryKey) &&
	 (YES == ite-> successful_local_lookup_in_delay_loop) ) {
      *isRouted = NO;
      *doForward = NO;
      addToSlot(ITE_GROW, ite, query, ttl, priority, sender);
      return 1;
    } else {
      *isRouted = YES;
      *doForward = YES;
      addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
      return 2;
    }
  }
  if (equalsHashCode512(query,
			&ite->primaryKey) ) {
    if (ite->seenIndex == 0) {
      if (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl)) {
	/* ttl of new is SIGNIFICANTLY longer? */
	/* query again */
	addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
	if (YES == ite->successful_local_lookup_in_delay_loop) {
	  *isRouted = NO; /* don't go again, we are already
			     processing a local lookup! */
	  *doForward = NO;
	  return 3;
	} else {
	  *isRouted = YES;
	  *doForward = YES;
	  return 4;
	}
      } else {
	/* new TTL is lower than the old one, thus
	   just wait for the reply that may come back */
	if (OK == addToSlot(ITE_GROW, ite, query, ttl, priority, sender)) {
	  if (YES == ite->successful_local_lookup_in_delay_loop) {
	    *isRouted = NO;
	    /* don't go again, we are already processing a
	       local lookup! */
	    *doForward = NO;
	    return 5;
	  } else {
	    *isRouted = YES;
	    *doForward = NO;
	    return 6;
	  }
	} else {
	  *isRouted = NO; /* same query with _higher_ TTL has already been
			     processed FOR THE SAME recipient! Do NOT do
			     the lookup *again*. */
	  *doForward = NO;
	  return 7;
	}
      }
    }
    /* ok, we've seen at least one reply before, replace
       more agressively */

    /* pending == new! */
    if (ite->seenReplyWasUnique) {
      if (ite->ttl < (cron_t)(now + ttl)) { /* ttl of new is longer? */
	/* go again */
	GROW(ite->seen,
	     ite->seenIndex,
	     0);
	ite->seenReplyWasUnique = NO;
	addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
	if (YES == ite->successful_local_lookup_in_delay_loop) {
	  *isRouted = NO;
	  /* don't go again, we are already processing a local lookup! */
	  *doForward = NO;
	  return 8;
	} else {
	  *isRouted = YES;
	  /* only forward if new TTL is significantly higher */
	  if (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl))
	    *doForward = YES;
	  else
	    *doForward = NO;
	  return 9;
	}
      } else {
	/* new TTL is lower than the old one, thus
	   just wait for the reply that may come back */
	if (OK == addToSlot(ITE_GROW, ite, query, ttl, priority, sender)) {
	  if (YES == ite->successful_local_lookup_in_delay_loop) {
	    *isRouted = NO;
	    *doForward = NO;
	    return 10;
	  } else {
	    *isRouted = YES;
	    *doForward = NO;
	    return 11;
	  }
	} else {
	  *isRouted = NO;
	  *doForward = NO;
	  return 12;
	}
      }
    } else { /* KSK or SKS, multiple results possible! */
      /* It's a pending KSK or SKS that can have multiple
	 replies.  Do not re-send, just forward the
	 answers that we get from now on to this additional
	 receiver */
      int isttlHigher;
      if (ite->ttl < (cron_t) now+ttl)
	isttlHigher = NO;
      else
	isttlHigher = YES;
      if (OK == addToSlot(ITE_GROW, ite, query, ttl, priority, sender)) {
	*isRouted = YES;
	*doForward = NO;
	return 13;
      } else {
	*isRouted = isttlHigher;
	/* receiver is the same as the one that already got the
	   answer, do not bother to do this again, IF
	   the TTL is not higher! */
	*doForward = NO;
	return 14;
      }
    }
  }
  /* a different query that is expired a bit longer is using
     the slot; but if it is a query that has received
     a unique response already, we can eagerly throw it out
     anyway, since the request has been satisfied
     completely */
  if ( (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl) ) &&
       (ite->ttl < now) &&
       (ite->seenReplyWasUnique) ) {
    /* we have seen the unique answer, get rid of it early */
    addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
    *isRouted = YES;
    *doForward = YES;
    return 15;
  }
  /* Another still valid query is using the slot.  Now we need a _really_
     good reason to discard it... */
  if (ttl < 0) {
    *isRouted = NO;
    *doForward = NO;
    return 16; /* if new ttl is "expired", don't bother with priorities */
  }

  /* Finally try to find a _strong_ reason looking at priority/ttl
     relationships to replace the existing query. A low ttl with high
     priority should be preferred, so we do a cross-multiplication
     (!). Also, we want a _strong_ reason, so we add a "magic" factor
     of 10 for the additional work that the replacement would make
     (the network needs a certain amount of resilience to changes in
     the routing table, otherwise it might happen that query A
     replaces query B which replaces query A which could happen so
     quickly that no response to either query ever makes it through...
  */
  if ( (long long)((ite->ttl - now) * priority) >
       (long long) 10 * (ttl * ite->priority) ) {
    addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
    *isRouted = YES;
    *doForward = YES;
    return 17;
  }
  if (weak_randomi(TIE_BREAKER_CHANCE) == 0) {
    addToSlot(ITE_REPLACE, ite, query, ttl, priority, sender);
    *isRouted = YES;
    *doForward = YES;
    return 20;
  }
  /* sadly, the slot is busy with something else; we can
     not even add ourselves to the reply set */
  *isRouted = NO;
  *doForward = NO;

  return 18;
}

/**
 * Send a reply to a host.
 *
 * @param ite the matching slot in the indirection table
 * @param msg the message to route
 */
static void sendReply(IndirectionTableEntry * ite,
		      const P2P_MESSAGE_HEADER * msg) {
  unsigned int j;
  unsigned int maxDelay;
  cron_t now;
#if DEBUG_GAP
  EncName enc;
#endif

  cronTime(&now);
  if (now < ite->ttl)
    maxDelay = ite->ttl - now;
  else
    maxDelay = TTL_DECREMENT; /* for expired queries */
  /* send to peers */
  for (j=0;j<ite->hostsWaiting;j++) {
#if DEBUG_GAP
    IFLOG(LOG_DEBUG,
	  hash2enc(&ite->destination[j].hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"GAP sending reply to `%s'\n",
	&enc);
#endif
    coreAPI->unicast(&ite->destination[j],
		     msg,
		     BASE_REPLY_PRIORITY *
		     (ite->priority+1),
		     /* weigh priority */
		     maxDelay);
  }
}

struct qLRC {
  const PeerIdentity * sender;
  DataContainer ** values;
  unsigned int valueCount;
};

/**
 * Callback for processing local results.
 * Inserts all results into the qLRC closure.
 *
 * @param primaryKey is the key needed to decrypt
 *  the block
 * @param value is a DataContainer which
 *  wraps the content in the format that
 *  can be passed to the FS module (GapWrapper),
 *  which in turn wraps the DBlock (including
 *  the type ID).
 */
static int
queryLocalResultCallback(const HashCode512 * primaryKey,
			 const DataContainer * value,
			 void * closure) {
  struct qLRC * cls = closure;
  HashCode512 hc;
  HashCode512 hc1;
  int i;
  IndirectionTableEntry * ite;

#if EXTRA_CHECKS
  /* verify data is valid */
  uri(value,
      ANY_BLOCK,
      primaryKey);
#endif

  /* check seen */
  ite = &ROUTING_indTable_[computeRoutingIndex(primaryKey)];
  if (rhf == NULL)
    return OK; /* drop, not fully initialized! */
  rhf(value,
      &hc);
  for (i=0;i<ite->seenIndex;i++)
    if (equalsHashCode512(&hc,
			  &ite->seen[i]))
      return OK; /* drop, duplicate result! */
  for (i=0;i<cls->valueCount;i++) {
    hash(&cls->values[i][1],
	 ntohl(cls->values[i]->size) - sizeof(DataContainer),
	 &hc1);
    if (equalsHashCode512(&hc,
			  &hc1))
      return OK; /* drop, duplicate entry in DB! */
  }
  GROW(cls->values,
       cls->valueCount,
       cls->valueCount+1);
  cls->values[cls->valueCount-1]
    = MALLOC(ntohl(value->size));
  memcpy(cls->values[cls->valueCount-1],
	 value,
	 ntohl(value->size));
  return OK;
}

/**
 * Execute a single query. Tests if the query can be routed. If yes,
 * the query is added to the routing table and the content is looked
 * for locally. If the content is available locally, a deferred
 * response is simulated with a cron job and the local content is
 * marked as valueable. The method returns OK if the query should
 * subsequently be routed to other peers.
 *
 * @param sender next hop in routing of the reply, NULL for us
 * @param prio the effective priority of the query
 * @param ttl the relative ttl of the query
 * @param query the query itself
 * @return OK/YES if the query will be routed further,
 *         NO if we already found the one and only response,
 *         SYSERR if not (out of resources)
 */
static int execQuery(const PeerIdentity * sender,
		     unsigned int prio,
		     QUERY_POLICY policy,
		     int ttl,
		     const P2P_gap_query_MESSAGE * query) {
  IndirectionTableEntry * ite;
  int isRouted;
  struct qLRC cls;
  int i;
  int max;
  int * perm;
  int doForward;
#if DEBUG_GAP
  EncName enc;
#endif

  ite = &ROUTING_indTable_[computeRoutingIndex(&query->queries[0])];
  MUTEX_LOCK(&lookup_exclusion);
  i = -1;
  if (sender != NULL) {
    if ((policy & QUERY_INDIRECT) > 0) {
      i = needsForwarding(&query->queries[0],
			  ttl,
			  prio,
			  sender,
			  &isRouted,
			  &doForward);
    } else {
      isRouted = NO;
      doForward = YES;
    }
  } else {
    addReward(&query->queries[0],
	      prio);
    isRouted = YES;
    doForward = YES;
  }
  if ( (policy & QUERY_FORWARD) == 0)
    doForward = NO;

#if DEBUG_GAP
  IFLOG(LOG_DEBUG,
        hash2enc(&query->queries[0],
		 &enc));
  LOG(LOG_DEBUG,
      "GAP is executing request for `%s':%s%s (%d)\n",
      &enc,
      doForward ? " forwarding" : "",
      isRouted ? " routing" : "",
      i);
#endif
  cls.values = NULL;
  cls.valueCount = 0;
  cls.sender = sender;
  if ( (isRouted == YES) && /* if we can't route, lookup useless! */
       ( (policy & QUERY_ANSWER) > 0) ) {
    bs->get(bs->closure,
	    ntohl(query->type),
	    prio,
	    1 + ( ntohs(query->header.size)
		  - sizeof(P2P_gap_query_MESSAGE)) / sizeof(HashCode512),
	    &query->queries[0],
	    &queryLocalResultCallback,
	    &cls);
  }

  if (cls.valueCount > 0) {
    perm = permute(WEAK, cls.valueCount);
    max = getNetworkLoadDown();
    if (max > 100)
      max = 100;
    if (max == -1)
      max = 50; /* we don't know the load, assume middle-of-the-road */
    max = max / 10; /* 1 reply per 10% free capacity */
    max = 1 + (10 - max);
    if (max > cls.valueCount)
      max = cls.valueCount; /* can't send more back then
				what we have */

    for (i=0;i<cls.valueCount;i++) {
      if (i < max) {
	if (cls.sender != NULL)
	  queueReply(cls.sender,
		     &query->queries[0],
		     cls.values[perm[i]]);
      }
      /* even for local results, always do 'put'
	 (at least to give back results to local client &
	 to update priority; but only do this for
	 the first result */
      bs->put(bs->closure,
	      &query->queries[0],
	      cls.values[perm[i]],
	      ite->priority);

      if (uri(cls.values[perm[i]],
	      ite->type,
	      &query->queries[0]))
	doForward = NO; /* we have the one and only answer,
				do not bother to forward... */

      FREE(cls.values[perm[i]]);
    }
    FREE(perm);
  }
  GROW(cls.values,
       cls.valueCount,
       0);



  MUTEX_UNLOCK(&lookup_exclusion);
  if (doForward)
    forwardQuery(query,
		 sender);
  return doForward;
}

/**
 * Content has arrived. We must decide if we want to a) forward it to
 * our clients b) indirect it to other nodes. The routing module
 * should know what to do.  This method checks the routing table if we
 * have a matching route and if yes queues the reply. It also makes
 * sure that we do not send the same reply back on the same route more
 * than once.
 *
 * @param hostId who sent the content? NULL
 *        for locally found content.
 * @param msg the p2p reply that was received
 * @return how good this content was (effective
 *         priority of the original request)
 */
static int useContent(const PeerIdentity * hostId,
		      const P2P_gap_reply_MESSAGE * msg) {
  unsigned int i;
  HashCode512 contentHC;
  IndirectionTableEntry * ite;
  unsigned int size;
  int ret;
  unsigned int prio;
  DataContainer * value;
  double preference;
#if DEBUG_GAP
  EncName enc;

  IFLOG(LOG_DEBUG,
	if (hostId != NULL)
	  hash2enc(&hostId->hashPubKey,
		   &enc));
  LOG(LOG_DEBUG,
      "GAP received content from `%s'\n",
      (hostId != NULL) ? (const char*)&enc : "myself");
#endif
  if (ntohs(msg->header.size) < sizeof(P2P_gap_reply_MESSAGE)) {
    BREAK();
    return SYSERR; /* invalid! */
  }
	
  ite = &ROUTING_indTable_[computeRoutingIndex(&msg->primaryKey)];
  ite->successful_local_lookup_in_delay_loop = NO;
  size = ntohs(msg->header.size) - sizeof(P2P_gap_reply_MESSAGE);
  prio = 0;

  if (rhf == NULL)
    return OK; /* not fully initialized! */
  value = MALLOC(size + sizeof(DataContainer));
  value->size = htonl(size + sizeof(DataContainer));
  memcpy(&value[1],
	 &msg[1],
	 size);
  rhf(value,
      &contentHC);

  /* FIRST: check if seen */
  MUTEX_LOCK(&lookup_exclusion);
  for (i=0;i<ite->seenIndex;i++) {
    if (equalsHashCode512(&contentHC,
			  &ite->seen[i])) {
      MUTEX_UNLOCK(&lookup_exclusion);
      FREE(value);
      return 0; /* seen before, useless */
    }
  }
  MUTEX_UNLOCK(&lookup_exclusion);

  /* SECOND: check if valid */
  ret = bs->put(bs->closure,
		&msg->primaryKey,
		value,
		0);
  if (ret == SYSERR) {
    BREAK();
    uri(value,
	ANY_BLOCK,
	&contentHC);
    FREE(value);
    return SYSERR; /* invalid */
  }

  /* THIRD: compute content priority/value and
     send remote reply (ITE processing) */
  MUTEX_LOCK(&lookup_exclusion);
  if (equalsHashCode512(&ite->primaryKey,
			&msg->primaryKey) ) {	
    prio = ite->priority;
    ite->priority = 0;
    /* remove the sender from the waiting list
       (if the sender was waiting for a response) */
    if (hostId != NULL) {
      for (i=0;i<ite->hostsWaiting;i++) {
	if (equalsHashCode512(&hostId->hashPubKey,
			      &ite->destination[i].hashPubKey)) {
	  ite->destination[i] = ite->destination[ite->hostsWaiting-1];
	  GROW(ite->destination,
	       ite->hostsWaiting,
	       ite->hostsWaiting - 1);
	}			
      }
    }
    GROW(ite->seen,
	 ite->seenIndex,
	 ite->seenIndex+1);
    ite->seen[ite->seenIndex-1] = contentHC;
    if (ite->seenIndex == 1) {
      ite->seenReplyWasUnique
	= uri(value,
	      ite->type,
	      &ite->primaryKey);
    } else {
      ite->seenReplyWasUnique = NO;
    }
    sendReply(ite,
	      &msg->header);
  }
  MUTEX_UNLOCK(&lookup_exclusion);
  prio += claimReward(&msg->primaryKey, hostId);

  /* FOURTH: update content priority in local datastore */
  if (prio > 0) {
    bs->put(bs->closure,
	    &msg->primaryKey,
	    value,
	    prio);
  }

  /* FIFTH: if unique reply, stopy querying */
  if (uri(value,
	  ite->type,
	  &ite->primaryKey)) {
    /* unique reply, stop forwarding! */
    dequeueQuery(&ite->primaryKey);
  }
  FREE(value);

  /* SIXTH: adjust traffic preferences */
  if (hostId != NULL) { /* if we are the sender, hostId will be NULL */
    preference = (double) prio;
    identity->changeHostTrust(hostId,
			      prio);
    for (i=0;i<ite->hostsWaiting;i++)
      updateResponseData(&ite->destination[i],
			 hostId);
    if (preference < CONTENT_BANDWIDTH_VALUE)
      preference = CONTENT_BANDWIDTH_VALUE;
    coreAPI->preferTrafficFrom(hostId,
			       preference);
  }
  return OK;
}

/* ***************** GAP API implementation ***************** */

/**
 * Start GAP.
 *
 * @param datastore the storage callbacks to use for storing data
 * @return SYSERR on error, OK on success
 */
static int init(Blockstore * datastore,
		UniqueReplyIdentifier uid,
		ReplyHashFunction rh) {
  if (bs != NULL) {
    BREAK();
    return SYSERR;
  }
  bs = datastore;
  uri = uid;
  rhf = rh;
  return OK;
}

/**
 * Perform a GET operation using 'key' as the key.  Note that no
 * callback is given for the results since GAP just calls PUT on the
 * datastore on anything that is received, and the caller will be
 * listening for these puts.
 *
 * @param type the type of the block that we're looking for
 * @param anonymityLevel how much cover traffic is required? 1 for none
 *        (0 does not require GAP, 1 requires GAP but no cover traffic)
 * @param keys the keys to query for
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @return OK if we will start to query, SYSERR if all of our
 *  buffers are full or other error, NO if we already
 *  returned the one and only reply (local hit)
 */
static int get_start(unsigned int type,
		     unsigned int anonymityLevel,
		     unsigned int keyCount,
		     const HashCode512 * keys,
		     cron_t timeout,
		     unsigned int prio) {
  P2P_gap_query_MESSAGE * msg;
  unsigned int size;
  int ret;

  size = sizeof(P2P_gap_query_MESSAGE) + (keyCount-1) * sizeof(HashCode512);
  if (size >= MAX_BUFFER_SIZE) {
    BREAK();
    return SYSERR; /* too many keys! */
  }

  /* anonymity level considerations:
     check cover traffic availability! */
  if (anonymityLevel > 0) {
    unsigned int count;
    unsigned int peers;
    unsigned int sizes;
    unsigned int timevect;

    anonymityLevel--;
    if (traffic == NULL) {
      LOG(LOG_ERROR,
	  _("Cover traffic requested but traffic service not loaded.  Rejecting request.\n"));
      return SYSERR;
    }
    if (OK != traffic->get((TTL_DECREMENT + timeout) / TRAFFIC_TIME_UNIT,
			   P2P_PROTO_gap_QUERY,
			   TC_RECEIVED,
			   &count,
			   &peers,
			   &sizes,
			   &timevect)) {
      LOG(LOG_WARNING,
	  _("Failed to get traffic stats.\n"));
      return SYSERR;
    }
    if (anonymityLevel > 1000) {
      if (peers < anonymityLevel / 1000) {
	LOG(LOG_WARNING,
	    _("Cannot satisfy desired level of anonymity, ignoring request.\n"));
	return SYSERR;
      }
      if (count < anonymityLevel % 1000) {
	LOG(LOG_WARNING,
	    _("Cannot satisfy desired level of anonymity, ignoring request.\n"));
	return SYSERR;
      }
    } else {
      if (count < anonymityLevel) {
	LOG(LOG_WARNING,
	    _("Cannot satisfy desired level of anonymity, ignoring request.\n"));
	return SYSERR;
      }
    }
  }


  msg = MALLOC(size);
  msg->header.size
    = htons(size);
  msg->header.type
    = htons(P2P_PROTO_gap_QUERY);
  msg->type
    = htonl(type);
  msg->priority
    = htonl(prio);
  msg->ttl
    = htonl(adjustTTL((int)timeout - cronTime(NULL),
		      prio));
  memcpy(&msg->queries[0],
	 keys,
	 sizeof(HashCode512) * keyCount);
  msg->returnTo
    = *coreAPI->myIdentity;
  ret = execQuery(NULL,
		  prio,
		  QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT,
		  timeout - cronTime(NULL),
		  msg);
  FREE(msg);
  return ret;
}

/**
 * Stop sending out queries for a given key.  GAP will automatically
 * stop sending queries at some point, but this method can be used to
 * stop it earlier.
 */
static int get_stop(unsigned int type,
		    unsigned int keyCount,
		    const HashCode512 * keys) {
  if (keyCount < 1)
    return SYSERR;
  return dequeueQuery(&keys[0]);
}

/**
 * Try to migrate the given content.
 *
 * @param data the content to migrate
 * @param position where to write the message
 * @param padding the maximum size that the message may be
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
tryMigrate(const DataContainer * data,
	   const HashCode512 * primaryKey,
	   char * position,
	   unsigned int padding) {
  P2P_gap_reply_MESSAGE * reply;
  unsigned int size;

  size = sizeof(P2P_gap_reply_MESSAGE) + ntohl(data->size) - sizeof(DataContainer);
  if (size > padding)
    return 0;
  if (size >= MAX_BUFFER_SIZE)
    return 0;
  reply = (P2P_gap_reply_MESSAGE*) position;
  reply->header.type
    = htons(P2P_PROTO_gap_RESULT);
  reply->header.size
    = htons(size);
  reply->primaryKey
    = *primaryKey;
  memcpy(&reply[1],
	 &data[1],
	 size - sizeof(P2P_gap_reply_MESSAGE));
  return size;
}

/**
 * Handle query for content. Depending on how we like the sender,
 * lookup, forward or even indirect.
 */
static int handleQuery(const PeerIdentity * sender,
		       const P2P_MESSAGE_HEADER * msg) {
  QUERY_POLICY policy;
  P2P_gap_query_MESSAGE * qmsg;
  unsigned int queries;
  int ttl;
  unsigned int prio;
  double preference;
#if DEBUG_GAP
  EncName enc;
#endif

  if (bs == NULL) {
    BREAK();
    return 0;
  }

  queries = 1 + (ntohs(msg->size) - sizeof(P2P_gap_query_MESSAGE))
    / sizeof(HashCode512);
  if ( (queries <= 0) ||
       (ntohs(msg->size) < sizeof(P2P_gap_query_MESSAGE)) ||
       (ntohs(msg->size) != sizeof(P2P_gap_query_MESSAGE) +
	(queries-1) * sizeof(HashCode512)) ) {
    BREAK();
    return SYSERR; /* malformed query */
  }
  qmsg = MALLOC(ntohs(msg->size));
  memcpy(qmsg, msg, ntohs(msg->size));
  if (equalsHashCode512(&qmsg->returnTo.hashPubKey,
			&coreAPI->myIdentity->hashPubKey)) {
    /* A to B, B sends to C without source rewriting,
       C sends back to A again without source rewriting;
       (or B directly back to A; also should not happen)
       in this case, A must just drop; however, this
       should not happen (peers should check). */
    BREAK();
    FREE(qmsg);
    return OK;
  }


  /* decrement ttl (always) */
  ttl = ntohl(qmsg->ttl);
  if (ttl < 0) {
    ttl = ttl - 2*TTL_DECREMENT - weak_randomi(TTL_DECREMENT);
    if (ttl > 0) {
      FREE(qmsg);
      return OK; /* just abort */
    }
  } else {
    ttl = ttl - 2*TTL_DECREMENT - weak_randomi(TTL_DECREMENT);
  }
  prio = ntohl(qmsg->priority);
  policy = evaluateQuery(sender,
			 &prio);
#if DEBUG_GAP
  IFLOG(LOG_DEBUG,
	hash2enc(&qmsg->queries[0],
		 &enc));
  LOG(LOG_DEBUG,
      "Received GAP query `%s'.\n",
      &enc);
#endif
  if ((policy & QUERY_DROPMASK) == 0) {
    FREE(qmsg);
#if DEBUG_GAP
    if (sender != NULL) {
      IFLOG(LOG_DEBUG,
	    hash2enc(&sender->hashPubKey,
		     &enc));
    }
    LOG(LOG_DEBUG,
	"Dropping query from %s, policy decided that this peer is too busy.\n",
	sender == NULL ? "localhost" : &enc);
#endif
    return OK; /* straight drop. */
  }
  preference = (double) prio;
  if ((policy & QUERY_INDIRECT) > 0) {
    qmsg->returnTo
      = *coreAPI->myIdentity;
  } else {
    /* otherwise we preserve the original sender
       and kill the priority (since we cannot benefit) */
    prio = 0;
  }

  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);
  /* adjust priority */
  qmsg->priority
    = htonl(prio);
  qmsg->ttl
    = htonl(adjustTTL(ttl, prio));

  ttl = ntohl(qmsg->ttl);
  if (ttl < 0)
    ttl = 0;
  execQuery(sender,	
	    prio,
	    policy,
	    ttl,
	    qmsg);
  FREE(qmsg);
  return OK;
}

static unsigned int getAvgPriority() {
  IndirectionTableEntry * ite;
  unsigned long long tot;
  int i;
  unsigned int active;

  tot = 0;
  active = 0;
  for (i=indirectionTableSize-1;i>=0;i--) {
    ite = &ROUTING_indTable_[i];
    if ( (ite->hostsWaiting > 0) &&
	 (ite->seenIndex == 0) ) {
      tot += ite->priority;
      active++;
    }
  }
  if (active == 0)
    return 0;
  else
    return (unsigned int) (tot / active);
}


GAP_ServiceAPI *
provide_module_gap(CoreAPIForApplication * capi) {
  static GAP_ServiceAPI api;
  unsigned int i;

  GNUNET_ASSERT(sizeof(P2P_gap_reply_MESSAGE) == 68);
  GNUNET_ASSERT(sizeof(P2P_gap_query_MESSAGE) == 144);

  coreAPI = capi;
  GROW(rewards,
       rewardSize,
       MAX_REWARD_TRACKS);

  identity = coreAPI->requestService("identity");
  GNUNET_ASSERT(identity != NULL);
  topology = coreAPI->requestService("topology");
  GNUNET_ASSERT(topology != NULL);
  traffic = coreAPI->requestService("traffic");
  if (traffic == NULL) {
    LOG(LOG_WARNING,
	_("Traffic service failed to load; gap cannot ensure cover-traffic availability.\n"));
  }
  random_qsel = weak_randomi(0xFFFF);
  indirectionTableSize =
    getConfigurationInt("GAP",
    			"TABLESIZE");
  if (indirectionTableSize < MIN_INDIRECTION_TABLE_SIZE)
    indirectionTableSize = MIN_INDIRECTION_TABLE_SIZE;
  MUTEX_CREATE(&lookup_exclusion);
  ROUTING_indTable_
    = MALLOC(sizeof(IndirectionTableEntry)
	     * indirectionTableSize);
  memset(ROUTING_indTable_,
	 0,
	 sizeof(IndirectionTableEntry)
	 * indirectionTableSize);	
  for (i=0;i<indirectionTableSize;i++) {
    ROUTING_indTable_[i].successful_local_lookup_in_delay_loop = NO;
  }

  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    queries[i].expires = 0; /* all expired */
    queries[i].msg = NULL;
  }
  lock = coreAPI->getConnectionModuleLock();
  addCronJob(&ageRTD,
	     2 * cronMINUTES,
	     2 * cronMINUTES,
	     NULL);

  LOG(LOG_DEBUG,
      _("`%s' registering handlers %d %d\n"),
      "gap",
      P2P_PROTO_gap_QUERY,
      P2P_PROTO_gap_RESULT);
  capi->registerHandler(P2P_PROTO_gap_QUERY,
			&handleQuery);
  capi->registerHandler(P2P_PROTO_gap_RESULT,
			(MessagePartHandler) &useContent);
  coreAPI->registerSendCallback(sizeof(P2P_gap_query_MESSAGE),
				&fillInQuery);

  api.init = &init;
  api.get_start = &get_start;
  api.get_stop = &get_stop;
  api.tryMigrate = &tryMigrate;
  api.getAvgPriority = &getAvgPriority;
  return &api;
}

void release_module_gap() {
  unsigned int i;
  ResponseList * rpos;
  ReplyTrackData * pos;

  coreAPI->unregisterHandler(P2P_PROTO_gap_QUERY,
			     &handleQuery);
  coreAPI->unregisterHandler(P2P_PROTO_gap_RESULT,
			     (MessagePartHandler) &useContent);
  coreAPI->unregisterSendCallback(sizeof(P2P_gap_query_MESSAGE),
				  &fillInQuery);

  delCronJob(&ageRTD,
	     2 * cronMINUTES,
	     NULL);

  for (i=0;i<indirectionTableSize;i++) {
    GROW(ROUTING_indTable_[i].seen,
	 ROUTING_indTable_[i].seenIndex,
	 0);
    ROUTING_indTable_[i].seenReplyWasUnique = NO;
    GROW(ROUTING_indTable_[i].destination,
	 ROUTING_indTable_[i].hostsWaiting,
	 0);
  }

  MUTEX_DESTROY(&lookup_exclusion);
  while (rtdList != NULL) {
    pos = rtdList;
    rtdList = rtdList->next;
    while (pos->responseList != NULL) {
      rpos = pos->responseList;
      pos->responseList = rpos->next;
      FREE(rpos);
    }
    FREE(pos);
  }
  for (i=0;i<QUERY_RECORD_COUNT;i++)
    FREENONNULL(queries[i].msg);

  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI->releaseService(topology);
  topology = NULL;
  if (traffic != NULL) {
    coreAPI->releaseService(traffic);
    traffic = NULL;
  }
  FREE(ROUTING_indTable_);
  GROW(rewards,
       rewardSize,
       0);
  lock = NULL;
  coreAPI = NULL;
  bs = NULL;
  uri = NULL;
}

/* end of gap.c */
