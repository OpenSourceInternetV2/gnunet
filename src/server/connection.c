/*
     This file is part of GNUnet.
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
 * @file server/connection.c
 * @brief module responsible for the peer-to-peer connections
 *
 * This file contains the connection table which lists all the current
 * connections of the node with other hosts and buffers outgoing
 * packets to these hosts.  The connection table also contains state
 * information such as sessionkeys, credibility and the last time we
 * had host activity.<p>
 *
 * This code is responsible for exchanging a sessionkey with another
 * peer, grouping several messages into a larger packet, padding with
 * noise, encryption and deferred sending of these messages.<p>
 *
 * The file is organized as follows:
 * 
 * a) includes
 * b) defines
 * c) typedefs
 * d) global variables
 * e) code
 * <p>
 *
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 */ 

/* ******************* includes ******************** */
#include "gnunet_util.h"

#include "knownhosts.h"
#include "core.h"
#include "traffic.h"
#include "pingpong.h"
#include "handler.h"
#include "tcpserver.h"
#include "heloexchange.h"
#include "httphelo.h"

/* **************** defines ************ */

/* tuning parameters */

#define DEBUG_CONNECTION NO

/* output knapsack priorities into a file? */
#define DEBUG_COLLECT_PRIO NO

#if DEBUG_CONNECTION == 2
#define ENTRY() LOG(LOG_DEBUG, "Method entry: %s defined in %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
#else
#define ENTRY() ;
#endif

#if DEBUG_COLLECT_PRIO == YES
FILE * prioFile;
#endif

/**
 * If an attempt to establish a connection is not answered
 * within 150s, drop.
 */
#define SECONDS_NOPINGPONG_DROP 150

/**
 * If an established connection is inactive for 5 minutes, 
 * drop.
 */
#define SECONDS_INACTIVE_DROP 300

/**
 * After 2 minutes on an inactive connection, probe the other
 * node with a ping if we have achieved less than 50% of our
 * connectivity goal.
 */
#define SECONDS_PINGATTEMPT 120

/**
 * How big do we estimate should the send buffer be?  (can grow bigger
 * if we have many requests in a short time, but if it is larger than
 * this, we start do discard expired entries.)  Computed as "MTU /
 * querySize" plus a bit with the goal to be able to have at least
 * enough small entries to fill a message completely *and* to have
 * some room to manouver.
 */
#define TARGET_SBUF_SIZE 40

unsigned int MAX_SEND_FREQUENCY = 50 * cronMILLIS;

/**
 * High priority message that needs to go through fast,
 * but not if policies would be disregarded.
 */
#define ADMIN_PRIORITY 0xFFFF

/** 
 * Masks to keep track when the trust has changed and
 * to get the real trust value.
 */
#define TRUST_REFRESH_MASK 0x80000000
#define TRUST_ACTUAL_MASK  0x7FFFFFFF

/**
 * If we under-shoot our bandwidth limitation in one time period, how
 * much of that limit are we allowed to 'roll-over' into the next
 * period?  The number given here is a factor of the total per-minute
 * bandwidth limit.
 */
#define MAX_BUF_FACT 2

/**
 * Expected MTU for a connection (1500 for Ethernet)
 */
#define EXPECTED_MTU 1500

/**
 * Send limit we announce to peers initially, around 1 MTU for most transp.
 */
#define START_TRANSMIT_LIMIT 1500

/**
 * How many MTU size messages to we want to transmit
 * per SECONDS_INACTIVE_DROP interval? (must be >=4 to
 * keep connection alive with reasonable probability).
 */
#define TARGET_MSG_SID 32

/**
 * Minimum number of sample messages (per peer) before we recompute
 * traffic assignments?
 */
#define MINIMUM_SAMPLE_COUNT 8

/**
 * What is the minimum number of bytes per minute that
 * we allocate PER peer? (5 minutes inactivity timeout,
 * 1500 MTU, 128 MSGs => 32 * 1500 / 5 = 38400 bpm [ 160 bps])
 */
#define MIN_BPM_PER_PEER (TARGET_MSG_SID * EXPECTED_MTU * 60 / SECONDS_INACTIVE_DROP)

/**
 * How often do we expect to re-run the traffic allocation
 * code? (depends on MINIMUM_SAMPLE_COUNT and MIN_BPM_PER_PEER
 * and MTU size).
 * With MSC 16 and 5 minutes inactivity timeout and TMSID 32 about every 148s 
 */
#define MIN_SAMPLE_TIME (MINIMUM_SAMPLE_COUNT * cronMINUTES * EXPECTED_MTU / MIN_BPM_PER_PEER)

/**
 * Hard limit on the send buffer size
 */
#define MAX_SEND_BUFFER_SIZE 256

/* status constants */

#define STAT_DOWN             0
#define STAT_WAITING_FOR_PING 1
#define STAT_WAITING_FOR_PONG 2
#define STAT_UP               3

/* ******************** typedefs ******************* */

/**
 * Type of the linked list of send callbacks (to
 * implement a round-robbin invocation chain).
 */
typedef struct SendCallbackList__ {
  /**
   * Minimum number of bytes that must be available
   * to call this callback.
   */
  unsigned int minimumPadding;

  /**
   * The callback method.
   */
  BufferFillCallback callback;

  /**
   * Did we say that this is a linked list?
   */
  struct SendCallbackList__ * next;

} SendCallbackList;

/**
 * Record for state maintanance between scanHelperCount,
 * scanHelperSelect and scanForHosts.
 */
typedef struct {
  unsigned int index;
  unsigned int matchCount;
  int costSelector;  
  HostIdentity match;
} IndexMatch;

typedef struct fENHWrap {
  PerNodeCallback method;
  void * arg;
} fENHWrap;

/* *********** flags for SendEntry.flags ********** */

/* no flags */
#define SE_FLAG_NONE 0
/* place entry at the head of the message */
#define SE_FLAG_PLACE_HEAD 1
/* place entry at the tail of the message */
#define SE_FLAG_PLACE_TAIL 2

#define SE_PLACEMENT_FLAG 3

/**
 * Entry in the send buffer.  Contains the size of the message, the
 * priority, when the message was passed to unicast, a callback to
 * fill in the actual message and a closure (argument to the
 * callback).
 */
typedef struct {
  /** how long is this message part expected to be? */
  unsigned short len;
  /** flags */
  unsigned short flags;
  /** how important is this message part? */
  unsigned int pri;
  /** when did we intend to transmit? */
  cron_t transmissionTime;
  /** callback to call to create the message part */
  BuildMessageCallback callback;
  /** argument to callback, call FREENONNULL(closure) if we
      can not transmit this MessagePart. */
  void * closure;
} SendEntry;

/**
 * Type of the connection table.
 */
typedef struct BufferEntry_ {
  /** Session for the connection */
  Session session;
  /** How much do we trust the host?  signed
      because that makes many operations that go 
      negative easier.  Of course, negative trust makes
      no sense. */
  int trust;
  /** the current session key */
  SESSIONKEY skey;
  /** at which time was the sessionkey created (by whichever party) */
  TIME_T created;
  /** is this host alive? timestamp of the time of the last-active point */
  cron_t isAlive; 
  /**  Status of the connection (STAT_XXX) */
  unsigned int status;


  /** last sequence number received on this connection (highest) */
  unsigned int lastSequenceNumberReceived;
  /** bit map indicating which of the 32 sequence numbers before the last
      were received (good for accepting out-of-order packets and
      estimating reliability of the connection) */
  unsigned int lastPacketsBitmap;
  /** last sequence number transmitted */
  unsigned int lastSequenceNumberSend;

  /** number of entries in the send buffer */
  unsigned int sendBufferSize;
  
  /** buffer of entries waiting to be transmitted */
  SendEntry ** sendBuffer;

  /** time of the last send-attempt (to avoid
      solving knapsack's too often) */
  cron_t lastSendAttempt;
  
  /**
   * How frequent (per connection!) may we attempt to solve the knapsack
   * problem and send a message out? Note that setting this value higher
   * reduces the CPU overhead while a lower value can improve thoughput.
   *
   * The value is adjusted according to how fast we perceive the CPU
   * to be (and is also proportional too how much bandwidth we have)...
   */
  cron_t MAX_SEND_FREQUENCY;

  /** a hash collision overflow chain */
  struct BufferEntry_ * overflowChain;


  /* *********** outbound bandwidth limits ********** */

  /** byte-per-minute limit for this connection */
  unsigned int max_bpm;
  /** current bps (actually bytes per minute) for this connection
      (incremented every minute by max_bpm,
       bounded by max_bpm * secondsInactive/2;
       may get negative if we have VERY high priority
       content) */
  long long available_send_window;
  /** time of the last increment of available_send_window */
  cron_t last_bps_update;

  /* *********** inbound bandwidth accounting ******** */

  /* how much traffic (bytes) did we receive on this connection since
     the last update-round? */
  long long recently_received;

  /** How valueable were the messages of this peer recently? */
  double current_connection_value;

  /* what is the limit that we communicated last? (byte per minute) */
  unsigned int transmitted_limit;
  /* the highest bandwidth limit that a well-behaved peer
     must have received by now */
  unsigned int max_transmitted_limit;
  /* what is the limit that we are currently shooting for? (byte per minute) */
  unsigned int idealized_limit;

} BufferEntry;

/**
 * Type of a callback method on every buffer.
 * @param be the buffer entry
 * @param data context for callee
 */
typedef void (*BufferEntryCallback)(BufferEntry * be,
				    void * data);

/* ***************** globals ********************** */

/**
 * The buffer containing all current connections.
 */
static BufferEntry ** CONNECTION_buffer_;

/**
 * Size of the CONNECTION_buffer_
 */
static unsigned int CONNECTION_MAX_HOSTS_;

/**
 * The DirContents array for scanning the hosts/ directory.
 */
static unsigned int CONNECTION_currentActiveHosts;

/**
 * Experimental configuration: disable random padding of encrypted
 * messages.
 */
static int disable_random_padding = NO;

/**
 * Send callbacks for making better use of noise padding...
 */
static SendCallbackList * scl_nextHead;
static SendCallbackList * scl_nextTail;

/**
 * statistics handles
 */
static int stat_number_of_connections;
static int stat_number_of_bytes_noise_send;
static int stat_number_of_bytes_send;
static int stat_number_of_bytes_received;
static int stat_MsgsExpired;
#if VERBOSE_STATS
static int stat_sessionkeys_received;
static int stat_sessionkeys_verified;
static int stat_sessionkeys_transmitted;
static int stat_connections_shutdown;
#endif
static int stat_total_messages_queued;

/**
 * Lock for the connection module.
 */
static Mutex lock;

/**
 * Where do we store trust information?
 */
static char * trustDirectory;

/**
 * What is the available downstream bandwidth (in bytes
 * per minute)?
 */
static long long max_bpm;

/* ******************** CODE ********************* */

/** 
 * This allocates and initializes a BufferEntry.
 * @return the initialized BufferEntry
 */
static BufferEntry * initBufferEntry() {
  BufferEntry * be;

  be = (BufferEntry*) MALLOC(sizeof(BufferEntry));
  be->trust 
    = 0;
  be->isAlive 
    = 0;
  be->status 
    = STAT_DOWN;
  be->sendBuffer
    = NULL;
  be->sendBufferSize
    = 0;
  be->overflowChain
    = NULL;
  be->session.tsession
    = NULL;
  be->max_bpm
    = START_TRANSMIT_LIMIT; /* about 1 MTU for most transports */
  be->available_send_window
    = be->max_bpm;
  be->recently_received
    = 0;
  be->current_connection_value
    = 0.0;
  be->transmitted_limit
    = START_TRANSMIT_LIMIT;
  be->max_transmitted_limit
    = START_TRANSMIT_LIMIT * 10; /* FIXME: "* 10" ONLY for 0.6.2c version
				    to make the transition more
				    easier; remove factor in next
				    release! */
  be->lastSendAttempt
    = 0; /* never */
  be->MAX_SEND_FREQUENCY
    = 50 * cronMILLIS * getCPULoad();
  cronTime(&be->last_bps_update); /* now */
  return be;
}

/**
 * Update available_send_window.  Call only when already synchronized.
 * @param be the connection for which to update available_send_window
 */
void updateCurBPS(BufferEntry * be) {
  cron_t now;
  cron_t delta;

  cronTime(&now);
  if (now <= be->last_bps_update)
    return;
  delta = now - be->last_bps_update;
  if (be->max_bpm * delta < cronMINUTES)
    return; 
  be->available_send_window =
    be->available_send_window + be->max_bpm * delta / cronMINUTES;
  if (be->available_send_window > (long long) be->max_bpm * MAX_BUF_FACT)
    be->available_send_window = (long long) be->max_bpm * MAX_BUF_FACT;
  be->last_bps_update = now;    
}

/**
 * From time to time, do a recount on how many hosts are connected.
 */
static void cronCountConnections() {
  unsigned int act;
  unsigned int i;
  BufferEntry * root;
  BufferEntry * tmp;

  act = 0;
  MUTEX_LOCK(&lock);
  for (i=0;i< CONNECTION_MAX_HOSTS_;i++) {
    root = CONNECTION_buffer_[i];

    tmp = root;
    while(NULL != tmp) {
      if (tmp->status == STAT_UP)
        act++;
      tmp = tmp->overflowChain;
    }
    
  }
  CONNECTION_currentActiveHosts = act;
  statSet(stat_number_of_connections,
	  act);
  MUTEX_UNLOCK(&lock);
}


/**
 * Write host-infromation to a file - flush the buffer entry!
 * Assumes synchronized access.
 */
static void flushHostCredit(BufferEntry * be,
			    void * unused) {
  EncName fil;
  char * fn;

  if ((be->trust & TRUST_REFRESH_MASK) == 0)
    return; /* unchanged */
  be->trust = be->trust & TRUST_ACTUAL_MASK;
  hash2enc(&be->session.sender.hashPubKey,
	   &fil);
  fn = MALLOC(strlen((char*)trustDirectory)+sizeof(EncName)+1);
  buildFileName(trustDirectory,
		&fil,
		fn);
  if (be->trust == 0) {
    if (0 != UNLINK(fn)) {
      if (errno != ENOENT)
	LOG(LOG_INFO,
	    "'%s' of file '%s' at %s:%d failed: %s\n",
	    "unlink",
	    fn,
	    __FILE__, __LINE__,
	    STRERROR(errno));
    }
  } else {
    writeFile(fn, 
	      &be->trust, 
	      sizeof(unsigned int), 
	      "644");
  }
  FREE(fn);
}

/**
 * Compute the greatest common denominator (Euklid).
 *
 * @param a
 * @param b
 * @return gcd(a,b)
 */
static int gcd(int a, int b) {
  while (a != 0) {
    int t = a;
    a = b % a;
    b = t;
  }
  return b;
}

/**
 * Approximate a solution to the 0-1 knapsack problem
 * using a greedy heuristic.  This function assumes that
 * the entries in the sendBuffer are ALREADY sorted
 * (by priority/len).
 *
 * The code falls back to this function if the CPU is
 * too busy.  As long as the CPU is idle, solveKnapsack 
 * is used.
 *
 * @param be the send buffer that is scheduled
 * @param available what is the maximum length available?
 * @param solution int[count] to store the solution as "YES" and "NO" values
 * @return the overall priority that was achieved 
 */ 
static unsigned int 
approximateKnapsack(BufferEntry * be,
		    unsigned int available,
		    int * solution) {
  unsigned int i;
  unsigned int count;
  SendEntry ** entries;
  int max;
  int left;

  entries = be->sendBuffer;
  count = be->sendBufferSize;
  left = available;
  max = 0;

  for (i=0;i<count;i++) {
    if (entries[i]->len <= left) {
      solution[i] = YES;
      left -= entries[i]->len;
      max += entries[i]->pri;     
    } else {
      solution[i] = NO;
    }    
  }
  return max;
}

/**
 * Solve the 0-1 knapsack problem.  Given "count" "entries" of
 * different "len" and "pri"ority and the amount of space "available",
 * compute the "solution", which is the set of entries to transport.
 * 
 * Solving this problem is NP complete in "count", but given that
 * available is small, the complexity is actually
 * "O(count*available)".
 *
 * @param be the send buffer that is scheduled
 * @param available what is the maximum length available?
 * @param solution int[count] to store the solution as "YES" and "NO" values
 * @return the overall priority that was achieved 
 */
static unsigned int 
solveKnapsack(BufferEntry * be,
	      unsigned int available,
	      int * solution) {
  unsigned int i;
  int j;
  int max;
  long long * v;
  int * efflen;
  cron_t startTime;
  cron_t endTime;
  SendEntry ** entries;
  unsigned int count;
#define VARR(i,j) v[(i)+(j)*(count+1)]

  if (available < 0) {
    BREAK();
    return -1;
  }
  ENTRY();
  entries = be->sendBuffer;
  count = be->sendBufferSize;
  cronTime(&startTime);

  /* fast test: schedule everything? */
  max = 0;
  for (i=0;i<count;i++)
    max += entries[i]->len;
  if (max <= available) {
    /* short cut: take everything! */
    for (i=0;i<count;i++)
      solution[i] = YES;
    max = 0;
    for (i=0;i<count;i++)
      max += entries[i]->pri;
    return max;
  }

  /* division of sizes & available by gcd(sizes,available) 
     to reduce cost to O(count*available/gcd) in terms of
     CPU and memory.  Since gcd is almost always at least 
     4, this is probably a good idea (TM)  :-) */
  efflen = MALLOC(sizeof(int)*count);
  max = available;
  for (i=0;i<count;i++)
    max = gcd(max, entries[i]->len);
  available = available / max;
  for (i=0;i<count;i++)
    efflen[i] = entries[i]->len / max;

  /* dynamic programming: 
     VARR(i,j) stores the maximum value of any subset
     of objects {1, ... i} that can fit into a knapsack
     of weight j. */
  v = MALLOC(sizeof(long long) * (count+1) * (available+1));
  memset(v, 
	 0, 
	 sizeof(long long) * (count+1) * (available+1));
  for (j=1;j<=available;j++)
    VARR(0,j) = -1;
  for (i=1;i<=count;i++) {
    for (j=0;j<=available;j++) {
      int take_val;
      int leave_val;

      take_val = -1;
      leave_val = VARR(i-1,j);
      if (j >= efflen[i-1]) {
	take_val = entries[i-1]->pri + VARR(i-1, j-efflen[i-1]);
	if (leave_val > take_val)
	  VARR(i,j) = leave_val;
	else
	  VARR(i,j) = take_val;
      } else
	VARR(i,j) = leave_val;
      /*
      printf("i: %d j: %d (of %d) efflen: %d take: %d "
             "leave %d e[i-1]->pri %d VAR(i-1,j-eff) %lld VAR(i,j) %lld\n",
	     i, 
	     j, 
	     available,
	     efflen[i-1],
	     take_val, 
	     leave_val,
	     entries[i-1]->pri,
	     VARR(i-1,j-efflen[i-1]),
	     VARR(i,j));
      */
    }
  }

  /* find slot with max value, prefer long messages! */
  max = 0;
  j = -1;
  for (i=0;(int)i<=available;i++) {
    if (VARR(count, i) >= max) {
      j = i;
      max = VARR(count, i);
    }
  }

  /* reconstruct selection */
  for (i=0;i<count;i++)
    solution[i] = NO;
  for (i=count;i>0;i--) {
    if (j >= efflen[i-1]) {
      if (VARR(i-1, j-efflen[i-1]) + entries[i-1]->pri == VARR(i,j)) {
	j -= efflen[i-1];
	solution[i-1] = YES; 
      }
    }
  }
  GNUNET_ASSERT(j == 0);
  FREE(v);
  FREE(efflen);
  cronTime(&endTime);

  return max;
}

#if DEBUG_CONNECTION == 2
/* for debugging... */
#include "gnunet_afs_esed2.h"
#endif

/**
 * Send a buffer; assumes that access is already synchronized.  This
 * message solves the knapsack problem, assembles the message
 * (callback to build parts from knapsack, callbacks for padding,
 * random noise padding, crc, encryption) and finally hands the
 * message to the transport service.
 *
 * @param be connection of the buffer that is to be transmitted
 */
static void sendBuffer(BufferEntry * be) {
  int crc;
  unsigned int i;
  unsigned int j;
  unsigned int p;
  SendCallbackList * pos;
  int priority;
  int * knapsackSolution;
  int * perm;
  char * plaintextMsg;
  void * encryptedMsg;
  cron_t expired;
  int targetSBLEN;
  SEQUENCE_Message * seqMsg;
  int headpos;
  int tailpos;
  int approxProb;
  int remainingBufferSize;

  ENTRY();
  /* fast ways out */
  if (be == NULL) {
    BREAK();
    return;
  }  
  if (be->status == STAT_DOWN)
    return; /* status is down, nothing to send! (should at least be wait-for-ping/pong 
	       or up) */
  if (be->sendBufferSize == 0) {
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"Message queue empty.  Nothing transmitted.\n");
#endif
    return; /* nothing to send */    
  }

  /* recompute max send frequency */
  if (be->max_bpm <= 0)
    be->max_bpm = 1;
  
  be->MAX_SEND_FREQUENCY = /* ms per message */
    be->session.mtu  /* byte per message */
    / (be->max_bpm * cronMINUTES / cronMILLIS) /* bytes per ms */
    / 2; /* some head-room */
  
  /* Also: allow at least MINIMUM_SAMPLE_COUNT knapsack
     solutions for any MIN_SAMPLE_TIME! */
  if (be->MAX_SEND_FREQUENCY > MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT)
    be->MAX_SEND_FREQUENCY = MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT;  

  if ( (be->lastSendAttempt + be->MAX_SEND_FREQUENCY > cronTime(NULL)) &&
       (be->sendBufferSize < MAX_SEND_BUFFER_SIZE/4) ) {
#if DEBUG_CONNECTION 
    LOG(LOG_DEBUG,
	"Send frequency too high (CPU load), send deferred.\n");
#endif
    return; /* frequency too high, wait */
  }
  /* solve knapsack problem, compute accumulated priority */
  knapsackSolution = MALLOC(sizeof(int) * be->sendBufferSize);

  approxProb = getCPULoad();
  if (approxProb > 50) {
    if (approxProb > 100)
      approxProb = 100;
    approxProb = 100 - approxProb; /* now value between 0 and 50 */
    approxProb *= 2; /* now value between 0 [always approx] and 100 [never approx] */
    /* control CPU load probabilistically! */
    if (randomi(1+approxProb) == 0) { 
      priority = approximateKnapsack(be,
				     be->session.mtu - sizeof(SEQUENCE_Message),
				     knapsackSolution);
#if DEBUG_COLLECT_PRIO == YES
      fprintf(prioFile, "%llu 0 %d\n", cronTime(NULL), priority);
#endif
    } else {
      priority = solveKnapsack(be,
			       be->session.mtu - sizeof(SEQUENCE_Message),
			       knapsackSolution);
#if DEBUG_COLLECT_PRIO == YES
      fprintf(prioFile, "%llu 1 %d\n", cronTime(NULL), priority);
#endif
    }
  } else { /* never approximate < 50% CPU load */
    priority = solveKnapsack(be,
			     be->session.mtu - sizeof(SEQUENCE_Message),
			     knapsackSolution);
#if DEBUG_COLLECT_PRIO == YES
      fprintf(prioFile, "%llu 2 %d\n", cronTime(NULL), priority);
#endif
  }
  j = 0;
  for (i=0;i<be->sendBufferSize;i++)
    if (knapsackSolution[i] == YES)
      j++;
  if (j == 0) {
    LOG(LOG_ERROR,
	_("'%s' selected %d out of %d messages (MTU: %d).\n"),
	"solveKnapsack",
	j,
	be->sendBufferSize,
	be->session.mtu - sizeof(SEQUENCE_Message));
    
    for (j=0;j<be->sendBufferSize;j++)
      LOG(LOG_ERROR,
	  _("Message details: %u: length %d, priority: %d\n"),
	  j, 
	  be->sendBuffer[j]->len,
	  be->sendBuffer[j]->pri);
    FREE(knapsackSolution);
    return;
  }
    
  /* test if receiver has enough bandwidth available!  */
  updateCurBPS(be);
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "receiver window available: %lld bytes (MTU: %u)\n",
      be->available_send_window,
      be->session.mtu);
#endif
  if (be->available_send_window < be->session.mtu) {
    /* if we have a very high priority, we may
       want to ignore bandwidth availability (e.g. for HANGUP,
       which  has EXTREME_PRIORITY) */
    if (priority < EXTREME_PRIORITY) {
      FREE(knapsackSolution);
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG,
	  "bandwidth limits prevent sending (send window %u too small).\n",
	  be->available_send_window);
#endif
      return; /* can not send, BPS available is too small */
    }
  }
  
  expired = cronTime(NULL) - SECONDS_PINGATTEMPT * cronSECONDS; 
  /* if it's more than one connection "lifetime" old, always kill it! */

  /* check if we (sender) have enough bandwidth available */
  if (SYSERR == outgoingCheck(priority)) {
    int msgCap;
    FREE(knapsackSolution);
    cronTime(&be->lastSendAttempt);
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"policy prevents sending message (priority too low: %d)\n",
	priority);
#endif
    
    /* cleanup queue */
    if (getCPULoad() > 50)
      msgCap = 4;
    else 
      msgCap = 54 - getCPULoad();    
    if (be->max_bpm > 2)
      msgCap += 2 * (int) log((double)be->max_bpm);
    /* allow at least msgCap msgs in buffer */
    for (i=0;i<be->sendBufferSize;i++) { 	
      SendEntry * entry = be->sendBuffer[i];
      if (be->sendBufferSize <= msgCap)
	break;
      if ( entry->transmissionTime < expired) {
#if DEBUG_CONNECTION 
	LOG(LOG_DEBUG,
	    "expiring message, expired %ds ago, queue size is %u (bandwidth stressed)\n",
	    (int) ((cronTime(NULL) - entry->transmissionTime) / cronSECONDS),
	    be->sendBufferSize);
#endif
	statChange(stat_MsgsExpired, 1);
	FREE(entry->closure);
	FREE(entry);
	be->sendBuffer[i] = be->sendBuffer[be->sendBufferSize-1];
	GROW(be->sendBuffer,
	     be->sendBufferSize,
	     be->sendBufferSize-1);
	statChange(stat_total_messages_queued, -1);
	i--; /* go again for this slot */
      }        
    }
    return; /* deferr further */
  }
  
  /* build message (start with sequence number) */
  plaintextMsg = MALLOC(be->session.mtu);
  seqMsg = (SEQUENCE_Message*) plaintextMsg;
  seqMsg->header.size 
    = htons(sizeof(SEQUENCE_Message));
  seqMsg->header.requestType 
    = htons(p2p_PROTO_SEQUENCE);
  seqMsg->sequenceNumber 
    = htonl(be->lastSequenceNumberSend);
  p = sizeof(SEQUENCE_Message);
  perm = permute(be->sendBufferSize);
  /* change permutation such that SE_FLAGS
     are obeyed */
  headpos = 0;
  tailpos = be->sendBufferSize-1;
  remainingBufferSize = be->sendBufferSize;
  for (i=0;i<be->sendBufferSize;i++) 
    if (knapsackSolution[perm[i]] == YES) {
      remainingBufferSize--;
      switch (be->sendBuffer[perm[i]]->flags & SE_PLACEMENT_FLAG) {
      case SE_FLAG_NONE:
	break;
      case SE_FLAG_PLACE_HEAD:
	/* swap slot with whoever is head now */
	j = perm[headpos];
	perm[headpos++] = perm[i];
	perm[i] = j;
	break;
      case SE_FLAG_PLACE_TAIL:
	/* swap slot with whoever is tail now */
	j = perm[tailpos];
	perm[tailpos--] = perm[i];
	perm[i] = j;
      }
    }

  targetSBLEN = 0; /* how many entries in sendBuffer
		      afterwards? */
  for (i=0;i<be->sendBufferSize;i++) {
    SendEntry * entry = be->sendBuffer[perm[i]];
    if (knapsackSolution[perm[i]] == YES) {
      int ret;

      ret = entry->callback(&plaintextMsg[p],
			    entry->closure,
			    entry->len);
      if (ret == SYSERR) {	
	/* should not happen if everything went well,
	   add random padding instead */
	p2p_HEADER * part;

	part = (p2p_HEADER *) &plaintextMsg[p];
	part->size 
	  = htons(entry->len);
	part->requestType 
	  = htons(p2p_PROTO_NOISE);
	for (i=p+sizeof(p2p_HEADER);i<entry->len+p;i++)
	  plaintextMsg[p] = (char) rand();
	statChange(stat_number_of_bytes_noise_send,
		   entry->len);
      } else {
#if DEBUG_CONNECTION == 2
	p2p_HEADER * msg;
	AFS_p2p_QUERY * qmsg;
	EncName enc;
	EncName enc2;
	int queries;

	IFLOG(LOG_EVERYTHING,
	      msg = (p2p_HEADER*) &plaintextMsg[p];
	      switch (ntohs(msg->requestType)) {
	      case AFS_p2p_PROTO_QUERY:
		qmsg = (AFS_p2p_QUERY*) msg;	
		queries = (ntohs(msg->size) - sizeof(AFS_p2p_QUERY)) / sizeof(HashCode160);
		hash2enc(&qmsg->queries[0],
			 &enc);	      
		hash2enc(&be->session.sender.hashPubKey,
			 &enc2);
		LOG(LOG_EVERYTHING,
		    "sending query %s (%d) TTL %d PR %u to %s\n",
		    &enc,
		    queries,
		    ntohl(qmsg->ttl),
		    ntohl(qmsg->priority),
		    &enc2);
		break;

	      });
#endif
      }
      p += entry->len;
      FREE(entry);
      be->sendBuffer[perm[i]] = NULL;
    } else {
      int msgCap;
      int l = getCPULoad();
      if (l >= 50) {
	msgCap = be->session.mtu / sizeof(HashCode160);
      } else {
	if (l <= 0)
	  l = 1;
	msgCap = be->session.mtu / sizeof(HashCode160)
	  + (MAX_SEND_BUFFER_SIZE - be->session.mtu / sizeof(HashCode160)) / l;
      }
      if (be->max_bpm > 2) {
	msgCap += 2 * (int) log((double)be->max_bpm);
	if (msgCap >= MAX_SEND_BUFFER_SIZE-1)
	  msgCap = MAX_SEND_BUFFER_SIZE-2; /* try to make sure that there 
					      is always room... */
      }
      if ( (remainingBufferSize > msgCap) &&
	   (entry->transmissionTime < expired) ) {
#if DEBUG_CONNECTION 
	LOG(LOG_DEBUG,
	    "expiring message, expired %ds ago, queue size is %u (other messages went through)\n",
	    (int) ((cronTime(NULL) - entry->transmissionTime) / cronSECONDS),
	    remainingBufferSize);
#endif
	statChange(stat_MsgsExpired, 1);
	FREE(entry->closure);
	FREE(entry);
	be->sendBuffer[perm[i]] = NULL;
	remainingBufferSize--;
      } else
	targetSBLEN++;
    }
  }
  FREE(perm);
  FREE(knapsackSolution);

  /* cleanup/compact sendBuffer */
  j = 0;
  for (i=0;i<be->sendBufferSize;i++) 
    if (be->sendBuffer[i] != NULL)
      be->sendBuffer[j++] = be->sendBuffer[i];  
  statChange(stat_total_messages_queued, 
	     targetSBLEN - be->sendBufferSize);
  GROW(be->sendBuffer,
       be->sendBufferSize,
       targetSBLEN);
    
  /* still room left? try callbacks! */
  pos = scl_nextHead;
  while (pos != NULL) {
    if (pos->minimumPadding + p <= be->session.mtu) {
      p += pos->callback(&be->session.sender,
			 &plaintextMsg[p],
			 be->session.mtu - p);
    }
    pos = pos->next;
  }
  
  /* finally padd with noise */  
  if ( (p + sizeof(p2p_HEADER) <= be->session.mtu) &&
       (disable_random_padding == NO) ) {
    p2p_HEADER * part;
    unsigned short noiseLen = be->session.mtu - p;

    statChange(stat_number_of_bytes_noise_send,
	       noiseLen);
    part = (p2p_HEADER *) &plaintextMsg[p];
    part->size 
      = htons(noiseLen);
    part->requestType 
      = htons(p2p_PROTO_NOISE);
    for (i=p+sizeof(p2p_HEADER);
	 i < be->session.mtu;
	 i++)
      plaintextMsg[i] = (char) rand();
    p = be->session.mtu;
  }

  /* prepare for sending... */
  crc = crc32N(plaintextMsg,
	       p);
  encryptedMsg = MALLOC(p);

  j = 0;
  while (j < p) {
    p2p_HEADER * part = (p2p_HEADER*) &plaintextMsg[j];
    unsigned short plen = htons(part->size);
    unsigned short ptyp = htons(part->requestType);
    j += plen;
    updateTrafficSendCounter(ptyp, plen);
  }

  if (p == (unsigned int) encryptBlock(plaintextMsg,
				       p,
				       &be->skey,
				       INITVALUE,
				       encryptedMsg)) {    
    statChange(stat_number_of_bytes_send,
	       p);
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"calling transport layer to send %d bytes with crc %x\n",
	p,
	crc);
#endif
    if (OK == transportSend(be->session.tsession,
			    encryptedMsg,
			    p,
			    YES, /* is encrypted */
			    crc)) {
      if (be->available_send_window > be->session.mtu)
	be->available_send_window -= be->session.mtu;
      else
	be->available_send_window = 0; /* if we overrode limits,
					  reset to 0 at least... */
      be->lastSequenceNumberSend++;
    } else if (priority >= EXTREME_PRIORITY) {
      /* priority is VERY high & transportSend failed; could be
	 that nonblocking send fails but "reliable" send would succeed
	 => try reliable send! */
      if (OK == transportSendReliable(be->session.tsession,
				      encryptedMsg,
				      p,
				      YES,
				      crc)) {
	if (be->available_send_window > be->session.mtu)
	  be->available_send_window -= be->session.mtu;
	else
	  be->available_send_window = 0; /* if we overrode limits,
					    reset to 0 at least... */
	be->lastSequenceNumberSend++;
      }
    }
  } else {
    BREAK();
  }
  FREE(encryptedMsg);
  FREE(plaintextMsg);
}

typedef struct {
  HostIdentity sender;
  unsigned short mtu;
  SendEntry * se;
} FragmentBMC;

/**
 * Send a message that had to be fragmented (right now!).  First grabs
 * the first part of the message (obtained from ctx->se) and stores
 * that in a FRAGMENT_Message envelope.  The remaining fragments are
 * added to the send queue with EXTREME_PRIORITY (to ensure that they
 * will be transmitted next).  The logic here is that if the priority
 * for the first fragment was sufficiently high, the priority should
 * also have been sufficiently high for all of the other fragments (at
 * this time) since they have the same priority.  And we want to make
 * sure that we send all of them since just sending the first fragment
 * and then going to other messages of equal priority would not be
 * such a great idea (i.e. would just waste bandwidth).
 */
static int fragmentBMC(void * buf,
		       FragmentBMC * ctx,
		       unsigned short len) {
  static int idGen = 0;
  char * tmp;
  int ret;
  FRAGMENT_Message * frag;
  unsigned int pos;
  int id;
  unsigned short mlen;

  GNUNET_ASSERT(len > sizeof(FRAGMENT_Message));
  tmp = MALLOC(ctx->se->len);
  ret = ctx->se->callback(tmp, ctx->se->closure, ctx->se->len);
  if (ret == SYSERR) {
    FREE(tmp);
    return SYSERR;
  }
  id = (idGen++) + randomi(512);
  /* write first fragment to buf */
  frag = (FRAGMENT_Message*) buf;
  frag->header.size = htons(len);
  frag->header.requestType = htons(p2p_PROTO_FRAGMENT);
  frag->id = id; 
  frag->off = htons(0);
  frag->len = htons(ctx->se->len);
  memcpy(&((FRAGMENT_Message_GENERIC*)frag)->data[0],
	 tmp,
	 len - sizeof(FRAGMENT_Message));

  /* create remaining fragments, add to queue! */
  pos = len - sizeof(FRAGMENT_Message);
  frag = MALLOC(ctx->mtu);
  while (pos < ctx->se->len) {  
    mlen = sizeof(FRAGMENT_Message) + ctx->se->len - pos;
    if (mlen > ctx->mtu)
      mlen = ctx->mtu;
    GNUNET_ASSERT(mlen > sizeof(FRAGMENT_Message));
    frag->header.size = htons(mlen);
    frag->header.requestType = htons(p2p_PROTO_FRAGMENT);
    frag->id = id;
    frag->off = htons(pos);
    frag->len = htons(ctx->se->len);
    memcpy(&((FRAGMENT_Message_GENERIC*)frag)->data[0],
	   &tmp[pos],
	   mlen - sizeof(FRAGMENT_Message));
    sendToNode(&ctx->sender,
	       &frag->header,
	       EXTREME_PRIORITY,
	       0); /* is 0 a good value here??? */
  }
  FREE(frag);
  FREE(tmp);
  FREE(ctx->se);		
  return OK;
}


/**
 * The given message must be fragmented.  Produce a placeholder that
 * corresponds to the first fragment.  Once that fragment is scheduled
 * for transmission, the placeholder should automatically add all of
 * the other fragments (with very high priority).
 */
static SendEntry * fragmentMessage(SendEntry * se,
				   BufferEntry * be) {
  SendEntry * ret;
  FragmentBMC * bmc;

  bmc = MALLOC(sizeof(FragmentBMC));
  bmc->se = se;
  bmc->mtu = be->session.mtu - sizeof(SEQUENCE_Message);
  bmc->sender = be->session.sender;
  GNUNET_ASSERT(se->len > be->session.mtu - sizeof(SEQUENCE_Message));
  ret = MALLOC(sizeof(SendEntry));
  ret->len = be->session.mtu - sizeof(SEQUENCE_Message);
  GNUNET_ASSERT(se->len != 0);
  ret->flags = se->flags;
  ret->pri = se->pri * ret->len / se->len; /* compute new priority! */
  ret->transmissionTime = se->transmissionTime;
  ret->callback = (BuildMessageCallback) &fragmentBMC;
  ret->closure = bmc;
  return ret;
}

/**
 * Append a message to the current buffer. This method
 * assumes that the access to be is already synchronized.
 * 
 * @param be on which connection to transmit
 * @param se what to transmit (with meta-data)
 */
static void appendToBuffer(BufferEntry * be,
			   SendEntry * se) {
#if DEBUG_CONNECTION
  EncName enc;
#endif  
  float apri;
  unsigned int i;
  SendEntry ** ne;

  ENTRY();
  if ( (se == NULL) || (se->len == 0) ) {
    BREAK();
    return;
  }
  if (se->len > be->session.mtu - sizeof(SEQUENCE_Message)) {
    /* this message is so big that it must be fragmented! */
    se = fragmentMessage(se, be);
  }

#if DEBUG_CONNECTION
  IFLOG(LOG_DEBUG,
	hash2enc(&be->session.sender.hashPubKey, 
		 &enc));
  LOG(LOG_DEBUG, 
      "adding message of size %d to buffer of host %s.\n",
      se->len,
      &enc);
#endif
  if ( (be->sendBufferSize > 0) &&
       (be->status != STAT_UP) ) {
    /* as long as we do not have a confirmed
       connection, do NOT queue messages! */
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"not connected to %s, message dropped\n",
	&enc);
#endif
    statChange(stat_MsgsExpired, 1);
    FREE(se->closure);
    FREE(se);
    return;
  }
  if (be->sendBufferSize >= MAX_SEND_BUFFER_SIZE) { 
    /* first, try to remedy! */
    sendBuffer(be);
    /* did it work? */
    if (be->sendBufferSize >= MAX_SEND_BUFFER_SIZE) { 
      /* we need to enforce some hard limit here, otherwise we may take
	 FAR too much memory (200 MB easily) */
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG,
	  "sendBufferSize >= %d, refusing to queue message.\n",
	  MAX_SEND_BUFFER_SIZE);
#endif
      statChange(stat_MsgsExpired, 1);
      FREE(se->closure);
      FREE(se);
      return;
    }
  }
  /* grow send buffer, insertion sort! */
  ne = MALLOC( (be->sendBufferSize+1) * sizeof(SendEntry*));
  apri = (float) se->pri / (float) se->len;
  i=0;
  while ( (i < be->sendBufferSize) &&
	  ( ((float)be->sendBuffer[i]->pri /
	     (float)be->sendBuffer[i]->len) >= apri) ) {
    ne[i] = be->sendBuffer[i];
    i++;
  }
  ne[i++] = se;
  while (i < be->sendBufferSize+1) {
    ne[i] = be->sendBuffer[i-1];
    i++;
  }
  FREENONNULL(be->sendBuffer);
  be->sendBuffer = ne;
  be->sendBufferSize++;
  statChange(stat_total_messages_queued, 1);
  sendBuffer(be);  
}

/**
 * Look for a host in the table. If the entry is there at the time of
 * checking, returns the entry.
 *
 * @param hostId the ID of the peer for which the connection is returned
 * @return the connection of the host in the table, NULL if not connected
 */
static BufferEntry * lookForHost(const HostIdentity * hostId) {
  BufferEntry * root;

  root = CONNECTION_buffer_[computeIndex(hostId)];
  while (root != NULL) {
    if (equalsHashCode160(&hostId->hashPubKey,
			  &root->session.sender.hashPubKey)) 
      return root;
    root = root->overflowChain;
  }
  return NULL;
}


/**
 * Read host-information from a file.  The connection lock
 * must be held.
 * 
 * @param be connection of the peer for which the trust is to be read
 */
static void initHostTrust(BufferEntry * be) {
  EncName fil;
  char * fn;

  hash2enc(&be->session.sender.hashPubKey,
	   &fil);
  fn = MALLOC(strlen((char*)trustDirectory)+sizeof(EncName)+1);
  buildFileName(trustDirectory, &fil, fn); 
  if (sizeof(unsigned int) !=
      readFile(fn, 
	       sizeof(unsigned int), 
	       &be->trust))
    be->trust = 0;
  FREE(fn);
}

/**
 * Force adding of a host to the buffer. If the node is already in the
 * table, the table entry is returned.  
 *
 * @param hostId for which peer should we get/create a connection
 * @param force if YES, drop another host from the table if the slot
 * is already in use. If NO, return NULL if the slot is busy.  
 * @return the table entry for the host (no keyexchange performed so far)
 */
static BufferEntry * addHost(const HostIdentity * hostId,
			     int force) {
  BufferEntry * root;
  BufferEntry * prev;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_INFO,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
  LOG(LOG_INFO, 
      "Adding host %s to the connection table.\n",
      &enc);
#endif

  ENTRY();
  root = lookForHost(hostId);
  if (root != NULL)
    return root;

  root = CONNECTION_buffer_[computeIndex(hostId)];
  prev = NULL;
  while (NULL != root) {
    /* settle for entry in the linked list that is down */
    if ( (root->status == STAT_DOWN) ||
	 (equalsHashCode160(&hostId->hashPubKey,
			    &root->session.sender.hashPubKey)) ) 
      break;
    prev = root;
    root = root->overflowChain;
  }
  if (root == NULL) {
    root = initBufferEntry();
    if (prev == NULL)
      CONNECTION_buffer_[computeIndex(hostId)] = root;
    else
      prev->overflowChain = root;
  }
  memcpy(&root->session.sender,
	 hostId,
	 sizeof(HostIdentity));	 
  initHostTrust(root);
  return root;
}

/**
 * Perform an operation for all connected hosts.  The BufferEntry
 * structure is passed to the method.  No synchronization or other
 * checks are performed.
 *
 * @param method the method to invoke (NULL for couting only)
 * @param arg the second argument to the method
 * @return the number of connected hosts
 */ 
static int forAllConnectedHosts(BufferEntryCallback method,
				void * arg) {
  unsigned int i;
  int count = 0;
  BufferEntry * be;
  
  ENTRY();
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    be = CONNECTION_buffer_[i];
    while (be != NULL) {
      if (be->status == STAT_UP) {
        if (method != NULL)
  	  method(be, arg);
        count++;
      }
      be = be->overflowChain;
    }
  }
  return count;
}

/**
 * Little helper function for forEachConnectedNode.
 * 
 * @param be the connection 
 * @param arg closure of type fENHWrap giving the function
 *        to call
 */
static void fENHCallback(BufferEntry * be,
			 void * arg) {
  fENHWrap * wrap;

  wrap = (fENHWrap*) arg;
  if (wrap->method != NULL)
    wrap->method(&be->session.sender,
		 wrap->arg);
}


/**
 * Here in this scanning for applicable hosts, we also want to take
 * the protocols into account and prefer "cheap" protocols,
 * i.e. protocols with a low overhead.
 *
 * @param id which peer are we currently looking at
 * @param proto what transport protocol are we looking at
 * @param im updated structure used to select the peer
 */
static void scanHelperCount(const HostIdentity * id,
			    const unsigned short proto,	
			    IndexMatch * im) {
  if (hostIdentityEquals(&myIdentity, id)) 
    return;
  if (computeIndex(id) != im->index)
    return;
  if (YES == isTransportAvailable(proto)) {
    im->matchCount++;  
    im->costSelector += transportGetCost(proto);
  }
#if DEBUG_CONNECTION
  else
    LOG(LOG_DEBUG,
	"transport %d is not available\n",
	proto);
#endif
}

/**
 * Select the peer and transport that was selected based on transport
 * cost.
 * 
 * @param id the current peer
 * @param proto the protocol of the current peer
 * @param im structure responsible for the selection process
 */
static void scanHelperSelect(const HostIdentity * id,
			     const unsigned short proto,
			     IndexMatch * im) {
  if (hostIdentityEquals(&myIdentity, id)) 
    return;
  if (computeIndex(id) != im->index)
    return;
  if (YES == isTransportAvailable(proto)) {
    im->costSelector -= transportGetCost(proto);
    if ( (im->matchCount == 0) ||
	 (im->costSelector < 0) ) {
      memcpy(&im->match,
	     id,
	     sizeof(HostIdentity));
    }
    im->matchCount--;
  }
#if DEBUG_CONNECTION
  else
    LOG(LOG_DEBUG,
	"transport %d is not available\n",
	proto);
#endif
}

/**
 * Force creation of a new Session key for the given host. 
 *
 * @param hostId the identity of the other host 
 * @param sk the SESSIONKEY to use
 * @param created the timestamp to use
 * @param ret the address where to write the signed
 *        session key, first unsigned short_SIZE byte give length
 * @return OK on success, SYSERR on failure
 */
static int makeSessionKeySigned(HostIdentity * hostId,
				SESSIONKEY * sk,
				TIME_T created,
				SKEY_Message * ret) {
  HashCode160 keyHash;
  HostIdentity myId;
  HELO_Message * foreignHelo;
#if EXTRA_CHECKS
  EncName hostName;
#endif

  ENTRY();

  GNUNET_ASSERT((ret != NULL) && (sk != NULL) );
  /* create and encrypt sessionkey */
  if (SYSERR == identity2Helo(hostId, 
			      ANY_PROTOCOL_NUMBER,
			      YES,
			      &foreignHelo)) {
    LOG(LOG_INFO, 
	"%s: cannot encrypt sessionkey, other peer not known!\n",
	__FUNCTION__);  
    return SYSERR; /* other host not known */  
  }
  if (foreignHelo == NULL)
    errexit("identity2Helo violated interface, "
	    "returned OK but did not set helo ptr\n");
  if (SYSERR == encryptHostkey(sk,
			       sizeof(SESSIONKEY),
			       &foreignHelo->publicKey,
			       &ret->body.key)) {
    BREAK();
    FREE(foreignHelo);
    return SYSERR; /* encrypt failed */
  }
  FREE(foreignHelo);
  /* compute hash and sign hash */
  ret->body.creationTime = htonl(created);
  hash(&ret->body, 
       sizeof(RSAEncryptedData) + sizeof(TIME_T),
       &keyHash);
  if (SYSERR == signData(&keyHash, 
			 (unsigned short)sizeof(HashCode160),
			 &ret->body.signature)) {
    BREAK();
  }

  /* complete header */
  ret->header.size = htons(sizeof(SKEY_Message));
  ret->header.requestType = htons(p2p_PROTO_SKEY);
  /* verify signature/SKS */
  getHostIdentity(getPublicHostkey(),
		  &myId); 
#if EXTRA_CHECKS
  hash2enc(&hostId->hashPubKey, &hostName);
  GNUNET_ASSERT(OK == verifySKS(&myId, ret));
#endif
  return OK;
} 

/**
 * Perform a session key exchange for entry be.  First sends a HELO
 * and then the new SKEY (in two plaintext packets). When called, the
 * semaphore of at the given index must already be down
 *
 * @param be connection on which the key exchange is performed
 */
static void exchangeKey(BufferEntry * be) {
  EncName enc;
  HELO_Message * helo;
  HELO_Message * targetHelo;
  SKEY_Message skey;
  unsigned short targetTransport;
  char * sendBuffer;

  ENTRY();
  GNUNET_ASSERT(be != NULL);
  IFLOG(LOG_DEBUG,
	hash2enc(&be->session.sender.hashPubKey, 
		 &enc));
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG, 
      "Beginning of key exchange with '%s'.\n",
      &enc);
#endif
  if (be->status != STAT_DOWN) 
    BREAK();

  makeSessionkey(&be->skey);
  TIME(&be->created); /* set creation time for session key! */
  if (SYSERR == makeSessionKeySigned(&be->session.sender,
				     &be->skey,
				     be->created,
				     &skey))
    return;
  be->isAlive = 0; /* wait a bit */
  be->status = STAT_WAITING_FOR_PING;
  be->lastSequenceNumberReceived = 0;
  be->lastPacketsBitmap = (unsigned int) -1;
  /* send tmp to target */
  if (SYSERR == identity2Helo(&be->session.sender,
			      ANY_PROTOCOL_NUMBER,
			      YES,
			      &targetHelo)) {
    return;
  }
  targetTransport = ntohs(targetHelo->protocol);
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "identity2Helo returned HELO with protocol %d\n",
      targetTransport);
#endif
  if (SYSERR == transportCreateHELO(ANY_PROTOCOL_NUMBER,
				    &helo)) {
    be->status = STAT_DOWN;
    FREE(targetHelo);
    return;
  }
  if (SYSERR == transportConnect(targetHelo, /* callee frees except on SYSERR */
				 &be->session.tsession)) {
    be->status = STAT_DOWN;
    be->session.tsession = NULL;
    FREE(targetHelo);
    FREE(helo);
    return;
  } 
  targetHelo = NULL; /* ensure that we do not use the helo, 
			transportConnect is now the owner! */
  be->session.mtu = transportGetMTU(be->session.tsession->ttype);
  if (be->sendBuffer != NULL)
    BREAK();
  be->lastSequenceNumberSend = 1;
  be->session.isEncrypted = NO;

  sendBuffer = MALLOC(HELO_Message_size(helo)+
		      sizeof(SKEY_Message));
  memcpy(sendBuffer,
	 helo,
	 HELO_Message_size(helo));
  memcpy(&sendBuffer[HELO_Message_size(helo)],
	 &skey,
	 sizeof(SKEY_Message));
  updateTrafficSendCounter(p2p_PROTO_HELO, 
			   HELO_Message_size(helo));
  updateTrafficSendCounter(p2p_PROTO_SKEY,
			   sizeof(SKEY_Message));
  transportSend(be->session.tsession,
		sendBuffer,
		HELO_Message_size(helo)+sizeof(SKEY_Message),
		NO, /* not encrypted */
		crc32N(sendBuffer, HELO_Message_size(helo)+sizeof(SKEY_Message)));
  FREE(sendBuffer);
  FREE(helo);
  be->session.isEncrypted = YES;
#if VERBOSE_STATS
  statChange(stat_sessionkeys_transmitted, 1);
#endif
}

/**
 * Look in the list for known hosts; pick a random host of minimal
 * transport cost for the hosttable at index index. When called, the
 * mutex of at the given index must not be hold.
 *
 * @param index for which entry in the connection table are we looking for peers?
 */
static void scanForHosts(unsigned int index) {
  BufferEntry * be;
  IndexMatch indexMatch;
#if DEBUG_CONNECTION
  EncName hn;
#endif
  cron_t now;

#if DEBUG_CONNECTION
  LOG(LOG_CRON, 
      "Scanning for hosts (%d).\n",
      index);
#endif
  cronTime(&now);
  indexMatch.index = index;
  indexMatch.matchCount = 0;
  indexMatch.costSelector = 0;
  forEachHost((HostIterator)&scanHelperCount, 
	      now,
	      &indexMatch);
  if (indexMatch.matchCount == 0) 
    return;  
  LOG(LOG_CRON, 
      "Scanning for hosts (%d) found %d matching node identities.\n",
      index,
      indexMatch.matchCount);    
  if (indexMatch.costSelector > 0)
    indexMatch.costSelector
      = randomi(indexMatch.costSelector/4)*4;
  memcpy(&indexMatch.match,
	 &myIdentity,
	 sizeof(HostIdentity));  
  forEachHost((HostIterator)&scanHelperSelect,
	      now,
	      &indexMatch);
  if (hostIdentityEquals(&myIdentity, 
			 &indexMatch.match)) {
    BREAK();
    return;
  }
  if (computeIndex(&indexMatch.match) != index) {
    BREAK();
    return;
  }
#if DEBUG_CONNECTION
  IFLOG(LOG_DEBUG,
	hash2enc(&indexMatch.match.hashPubKey,
		 &hn));
  LOG(LOG_DEBUG, 
      "Attempting to connect to peer '%s' using slot %d.\n",
      &hn, 
      index);
#endif
  be = addHost(&indexMatch.match, 
	       NO); /* NO or YES should not matter here since we know the slot is empty */
  if (be != NULL) {
    if (be->status == STAT_DOWN) {
      blacklistHost(&be->session.sender,
		    CONNECTION_currentActiveHosts,
		    NO); 
      /* we're trying now, don't try again too soon */
      exchangeKey(be);
    }
  }
}

/**
 * Copy the pre-build message part of lenth "len" in closure to the
 * buffer buf. Frees the closure.
 *
 * @param buf the target location where the message is assembled
 * @param closure the pre-build message
 * @param len the length of the pre-build message
 * @return OK (always successful)
 */
static int copyCallback(void * buf,
			void * closure,
			unsigned short len) {
  memcpy(buf, closure, len);
  FREE(closure);
  return OK; 
}

/**
 * Check if the buffer is up (we got a PONG), if not, repeat the PING 
 */
static void checkAndPing(BufferEntry * be) {
  HostIdentity * data;
  PINGPONG_Message pmsg;

  ENTRY();
  data = MALLOC(sizeof(HostIdentity));
  memcpy(data,
	 &be->session.sender,
	 sizeof(HostIdentity));
  if (OK == pingAction(&be->session.sender,
		       (CronJob) &notifyPONG,
		       data,
		       &pmsg)) {
    SendEntry * se;
    
    se = MALLOC(sizeof(SendEntry));
    se->flags = SE_FLAG_NONE;
    se->len = sizeof(PINGPONG_Message);
    se->pri = getConnectPriority();
    se->transmissionTime = cronTime(NULL); /* now */
    se->callback = &copyCallback;
    se->closure = MALLOC(sizeof(PINGPONG_Message));
    memcpy(se->closure,
	   &pmsg,
	   sizeof(PINGPONG_Message));
    appendToBuffer(be, se);
  } else {
    FREE(data);
    LOG(LOG_INFO,
	_("Could not send checking ping, ping buffer full.\n"));
  }
}

/**
 * Shutdown the connection.  Send a HANGUP message to the other side
 * and mark the sessionkey as dead.
 *
 * @param be the connection to shutdown
 */
static void shutdownConnection(BufferEntry * be) {
  HANGUP_Message hangup;
  unsigned int i;

  ENTRY();
  if (be->status == STAT_DOWN)
    return; /* nothing to do */
  if (be->status == STAT_UP) {
    SendEntry * se;

    hangup.header.requestType = htons(p2p_PROTO_HANGUP);
    hangup.header.size = htons(sizeof(HANGUP_Message));
    getHostIdentity(getPublicHostkey(),
		    &hangup.sender);    
    se = MALLOC(sizeof(SendEntry));
    se->len = sizeof(HANGUP_Message);
    se->flags = SE_FLAG_PLACE_TAIL;
    se->pri = EXTREME_PRIORITY;
    se->transmissionTime = cronTime(NULL); /* now */
    se->callback = &copyCallback;
    se->closure = MALLOC(sizeof(HANGUP_Message));
    memcpy(se->closure,
	   &hangup,
	   sizeof(HANGUP_Message));
    appendToBuffer(be, se);
  }
  be->created = 0;
  be->status = STAT_DOWN;
  be->transmitted_limit = START_TRANSMIT_LIMIT; 
  be->max_transmitted_limit = START_TRANSMIT_LIMIT * 10; /* FIXME: remove "*10" post 0.6.2c! */ 
  if (be->session.tsession != NULL) {
    transportDisconnect(be->session.tsession);
    be->session.tsession = NULL;
  }    
#if VERBOSE_STATS
  statChange(stat_connections_shutdown, 1);
#endif
  for (i=0;i<be->sendBufferSize;i++) {
    FREENONNULL(be->sendBuffer[i]->closure);
    FREE(be->sendBuffer[i]);
  }
  statChange(stat_total_messages_queued, 
	     -be->sendBufferSize);
  GROW(be->sendBuffer,
       be->sendBufferSize,
       0);
}

/**
 * Transmit an update to the bandwidth limit to the other peer.
 *
 * @param be the connection to transmit the limit over
 */
static void transmitConnectionLimit(BufferEntry * be) {
  SendEntry * entry;
  CAPABILITY_Message * cap;
  int delta;

  ENTRY();
  delta = be->idealized_limit - be->transmitted_limit;
  if (delta < 0)
    delta = -delta;
  if (be->transmitted_limit == 0)
    be->transmitted_limit = 1;
#if DEBUG_CONNECTION
  LOG(LOG_INFO,
      "ideal: %u bpm, prev. transmitted: %u bpm, will transmit: %s - peers own limit: %u bpm\n",
      be->idealized_limit,
      be->transmitted_limit,
      ( ( (delta * 100) / be->transmitted_limit) < 10) ? "NO" : "YES",
      be->max_bpm);
#endif
  if ( ( (delta * 100) / be->transmitted_limit) < 10)
    return; /* limit changed by less than 10%, ignore. */

  /* limits changed by more than 10%,
     send updated capability message! */  

  entry = MALLOC(sizeof(SendEntry));
  entry->len = sizeof(CAPABILITY_Message);
  entry->flags = SE_FLAG_NONE;
  entry->pri = ADMIN_PRIORITY;
  entry->transmissionTime = cronTime(NULL);
  entry->callback = &copyCallback;
  entry->closure = MALLOC(sizeof(CAPABILITY_Message));
  cap = (CAPABILITY_Message*) entry->closure;
  cap->header.size = htons(sizeof(CAPABILITY_Message));
  cap->header.requestType = htons(p2p_PROTO_CAPABILITY);
  cap->cap.capabilityType = htonl(CAP_BANDWIDTH_RECV);
  cap->cap.value = htonl(be->idealized_limit);
  appendToBuffer(be, 
		 entry);   
#if DEBUG_CONNECTION
  LOG(LOG_INFO,
      "transmitted: limit %u\n",
      be->idealized_limit);
#endif
  be->transmitted_limit = be->idealized_limit;
  if(be->transmitted_limit > be->max_transmitted_limit)
    be->max_transmitted_limit = be->transmitted_limit;
  else
    be->max_transmitted_limit 
      = ( be->max_transmitted_limit * 3 +
	  be->transmitted_limit ) / 4; /* slowly reduce */
}


/* ************* inbound bandwidth scheduling ************* */

typedef struct {
  BufferEntry ** e;
  unsigned int pos;
} UTL_Closure;

static void gatherEntries(BufferEntry * be,
			  UTL_Closure * utl) {
  utl->e[utl->pos++] = be;
}

static void resetRecentlyReceived(BufferEntry * be,
				  void * unused) {
  be->recently_received = 0;
}

/**
 * What is the function used to weigh the value of
 * the connection for bandwidth allocation?
 * Ok, with this API we can not implement "max takes all",
 * but it is possible to use:
 *
 * - proportional share: (x) [ bandwidth proportional to contribution ]
 * - square-root (sqrt(x))  [ contributing a lot more gives a little gain ]
 * - square share: (x*x) [ Bush's tax system: if you're rich, you get even more ]
 * 
 * Pretty much every monotonically increasing, always
 * positive function can be used.  The main loop normalizes later.
 */
#define SHARE_DISTRIBUTION_FUNCTION(be) (be->current_connection_value)

/**
 * What is the minimum number of peers to connect to that is 
 * still acceptable? (By dividing CONNECTION_MAX_HOSTS_ by
 * two, we specify to maintain at least 50% of the maximum
 * number of connections).
 */
static unsigned int minConnect() {
  return CONNECTION_MAX_HOSTS_/2;
}

/**
 * Schedule the available inbound bandwidth among the peers.  Note
 * that this function is called A LOT (dozens of times per minute), so
 * it should execute reasonably fast.
 */
static void scheduleInboundTraffic() {
  unsigned int activePeerCount;
  static cron_t lastRoundStart = 0;
  UTL_Closure utl;
  static cron_t timeDifference;
  cron_t now;
  BufferEntry ** entries;
  double * shares;
  double shareSum;
  unsigned int u;
  unsigned int minCon;
  long long schedulableBandwidth; /* MUST be unsigned! */
  long long decrementSB; 
  long long * adjustedRR;
  int didAssign;

  MUTEX_LOCK(&lock);
  cronTime(&now);    

  /* if this is the first round, don't bother... */
  if (lastRoundStart == 0) {
    /* no allocation the first time this function is called! */
    lastRoundStart = now;
    forAllConnectedHosts(&resetRecentlyReceived,
			 NULL);
    MUTEX_UNLOCK(&lock);
    return;
  }

  /* if time difference is too small, we don't have enough
     sample data and should NOT update the limits */
  timeDifference = now - lastRoundStart;
  if (timeDifference < MIN_SAMPLE_TIME) {
    MUTEX_UNLOCK(&lock);
    return; /* don't update too frequently, we need at least some
	       semi-representative sampling! */
  }

  /* build an array containing all BEs */
  activePeerCount = forAllConnectedHosts(NULL, NULL);
  if (activePeerCount == 0) {
    MUTEX_UNLOCK(&lock);
    return; /* nothing to be done here. */
  }
  entries = MALLOC(sizeof(BufferEntry*)*activePeerCount);
  utl.pos = 0;
  utl.e = entries;
  forAllConnectedHosts((BufferEntryCallback)&gatherEntries,
		       &utl);

  
  /* compute shares */
  shares = MALLOC(sizeof(double)*activePeerCount);
  shareSum = 0.0;
  for (u=0;u<activePeerCount;u++) {
    shares[u] = SHARE_DISTRIBUTION_FUNCTION(entries[u]);
    if (shares[u] < 0.0)
      shares[u] = 0.0;
    shareSum += shares[u];
  }

  /* normalize distribution */
  if (shareSum >= 0.00001) { /* avoid numeric glitches... */
    for (u=0;u<activePeerCount;u++)
      shares[u] = shares[u] / shareSum;
  } else {
    for (u=0;u<activePeerCount;u++)
      shares[u] = 1 / activePeerCount;
  }
  
  /* compute how much bandwidth we can bargain with */
  minCon = minConnect();
  if (minCon > activePeerCount)
    minCon = activePeerCount;
  schedulableBandwidth = max_bpm - minCon * MIN_BPM_PER_PEER;

  adjustedRR = MALLOC(sizeof(long long) * activePeerCount);

  /* reset idealized limits; if we want a smoothed-limits
     algorithm, we'd need to compute the new limits separately
     and then merge the values; but for now, let's just go
     hardcore and adjust all values rapidly */
  for (u=0;u<activePeerCount;u++) {
    entries[u]->idealized_limit = 0;
    adjustedRR[u] = entries[u]->recently_received * cronMINUTES / timeDifference;

#if DEBUG_CONNECTION
    if (adjustedRR[u] > entries[u]->transmitted_limit) {
      EncName enc;
      IFLOG(LOG_INFO,
	    hash2enc(&entries[u]->session.sender.hashPubKey,
		     &enc));
      LOG(LOG_INFO,
	  "peer %s transmitted above limit: %llu bpm > %u bpm\n",
	  &enc,
	  adjustedRR[u],
	  entries[u]->transmitted_limit);
    }
#endif
    /* Check for peers grossly exceeding send limits. Be a bit
     * reasonable and make the check against the max value we have
     * sent to this peer (assume announcements may have got lost). 
     */
    if (adjustedRR[u] > 2 * MAX_BUF_FACT * 
	entries[u]->max_transmitted_limit) {
#if DEBUG_CONNECTION || 1
      EncName enc;
      IFLOG(LOG_INFO,
	    hash2enc(&entries[u]->session.sender.hashPubKey,
		     &enc));
      LOG(LOG_INFO,
	  "blacklisting %s, it sent >%dx+MTU above mLimit: %llu bpm > %u bpm (cLimit %u bpm)\n",
	  &enc,
	  2 * MAX_BUF_FACT,
	  adjustedRR[u],
	  entries[u]->max_transmitted_limit,
	  entries[u]->transmitted_limit);
#endif
      shutdownConnection(entries[u]);
      blacklistHost(&entries[u]->session.sender,
                    CONNECTION_currentActiveHosts--,
		    YES);
      statChange(stat_number_of_connections,
		 -1);
      activePeerCount--;
      entries[u]=entries[activePeerCount];
      shares[u]=shares[activePeerCount];
      adjustedRR[u]=adjustedRR[activePeerCount];
      u--;
    }
    
    if (adjustedRR[u] < MIN_BPM_PER_PEER/2)
      adjustedRR[u] = MIN_BPM_PER_PEER/2; /* even if we received NO traffic, allow
					     at least MIN_BPM_PER_PEER */
  }

#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "freely schedulable bandwidth is %d bpm\n",
      schedulableBandwidth);
#endif
  /* now distribute the schedulableBandwidth according
     to the shares.  Note that since we cap peers at twice
     of what they transmitted last, we may not be done with
     just one pass. 

     We don't wait until schedulableBandwidth hits 0 since that may
     take forever (due to rounding you can even take that literally).
     The "100" equates to 100 bytes per peer (per minute!) being
     potentially under-allocated.  Since there's always some
     (unencrypted) traffic that we're not quite accounting for anyway,
     that's probably not so bad. */
  while (schedulableBandwidth > CONNECTION_MAX_HOSTS_ * 100) {
    didAssign = NO;
    decrementSB = 0;
    for (u=0;u<activePeerCount;u++) {
      /* always allow allocating MIN_BPM_PER_PEER */
      if (entries[u]->idealized_limit < adjustedRR[u] * 2) {
	unsigned int share;

	share = entries[u]->idealized_limit + (unsigned int) (shares[u] * schedulableBandwidth);
	if (share > adjustedRR[u] * 2)
	  share = adjustedRR[u] * 2;
	if (share > entries[u]->idealized_limit) {
	  decrementSB += share - entries[u]->idealized_limit;
	  didAssign = YES;	
	}
	entries[u]->idealized_limit = share;
      }
    }
    schedulableBandwidth -= decrementSB;
    if (didAssign == NO) {
      int * perm = permute(activePeerCount);
      /* assign also to random "worthless" (zero-share) peers */
      for (u=0;u<activePeerCount;u++) {
	unsigned int v = perm[u]; /* use perm to avoid preference to low-numbered slots */
	if (entries[v]->idealized_limit / 2 < adjustedRR[u]) {
	  unsigned int share;

	  share = entries[v]->idealized_limit + (unsigned int) (schedulableBandwidth);
	  if (share > adjustedRR[u] * 2)
	    share = adjustedRR[u] * 2;
	  schedulableBandwidth -= share - entries[v]->idealized_limit;
	  entries[v]->idealized_limit = share;
	}
      }      
      FREE(perm);

      if ( (schedulableBandwidth > 0) &&
	   (activePeerCount > 0) ) {
	/* assign rest disregarding traffic limits */
	perm = permute(activePeerCount);
	for (u=0;u<activePeerCount;u++) 
	  entries[perm[u]]->idealized_limit += (unsigned int) (schedulableBandwidth/activePeerCount);	
	schedulableBandwidth = 0;
	FREE(perm);
      }    
      break;
    } /* didAssign == NO? */
  } /* while bandwidth to distribute */
 

  /* randomly add the MIN_BPM_PER_PEER to minCon peers; yes, this will
     yield some fluctuation, but some amount of fluctuation should be
     good since it creates opportunities. */
  for (u=0;u<minCon;u++) 
    entries[randomi(activePeerCount)]->idealized_limit += MIN_BPM_PER_PEER;  

  /* prepare for next round */
  lastRoundStart = now;
  for (u=0;u<activePeerCount;u++) {
#if DEBUG_CONNECTION
    EncName enc;

    IFLOG(LOG_DEBUG,
	  hash2enc(&entries[u]->session.sender.hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"inbound limit for peer %u: %s set to %d bpm\n",
	u,
	&enc,
	entries[u]->idealized_limit);
#endif
    transmitConnectionLimit(entries[u]);
    entries[u]->current_connection_value /= 2.0;
    entries[u]->recently_received = 0;
  }

  /* free memory */
  FREE(adjustedRR);
  FREE(shares);
  FREE(entries);
  MUTEX_UNLOCK(&lock);
}

/* ******** end of inbound bandwidth scheduling ************* */		    
#define BACKOFF_START_VALUE 16

/**
 * Call this method periodically to decrease liveness of hosts.
 *
 * @param unused not used, just to make signature type nicely
 */
static void cronDecreaseLiveness(void * unused) {  
  static unsigned int lastLivenessHost = 0;
  static unsigned int activePeerCount = 0;
  static int BACKOFF = BACKOFF_START_VALUE;
  BufferEntry * root;
  BufferEntry * prev;
  BufferEntry * tmp;
  cron_t now;

  scheduleInboundTraffic();
  cronTime(&now);    
  if (lastLivenessHost == 0) {
    /* every 12 seconds / for each pass through all slots */
    if ( ( (activePeerCount <= CONNECTION_MAX_HOSTS_/8) ||
           (activePeerCount < 2) ) &&
           (activePeerCount < 16) ) {
      /* (almost) no active peers? well,
	 then we clearly want to discover some :-).
	 < 2 is a definitive sign of trouble, 
	 < 1/8-th of goal is bad, but if goal is huge
	 < 16 is required to avoid mega-peers pounding on the hostlist-server. */
      static int delay = 1;
      /* at most try every BACKOFF time units,
	 use exponential BACKOFF, maybe the peer
	 is misconfigured, then we don't want to kill
	 the hostlist server... */
      if ( (delay % BACKOFF) == 0) {
	LOG(LOG_DEBUG,
	    "attempting to download hostlist from server.\n");
	downloadHostlist();	
	if (BACKOFF < 65536)
	  BACKOFF = BACKOFF * 2; 
      } else {
	char * url = getConfigurationString("GNUNETD",
					    "HOSTLISTURL");
	if (url != NULL) {
	  LOG(LOG_DEBUG,
	      "I only have %d peers connected (want %u), waiting for "
	      "%u to reach %u before trying HTTP download of hostlist%s.\n",
	      activePeerCount,
	      CONNECTION_MAX_HOSTS_,
	      delay % BACKOFF,
	      BACKOFF,
	      (delay > BACKOFF_START_VALUE) ? " (again)":"");
	  FREE(url);
	}
      }
      delay++;
    }
    activePeerCount = 0;
  }
  /* Find the correct host */
  MUTEX_LOCK(&lock);
  if (lastLivenessHost >= CONNECTION_MAX_HOSTS_) {
    /* this happens if the connection buffer size
       shrinks due to reconfiguration and SIGHUP */
    activePeerCount = 0;
    lastLivenessHost = 0;
  }
  root = CONNECTION_buffer_[lastLivenessHost];
  prev = NULL;
  while (NULL != root) {
    /* is this the host? */
    switch (root->status) {
    case STAT_DOWN:
      if (prev == NULL)
	CONNECTION_buffer_[lastLivenessHost] = root->overflowChain;
      else
	prev->overflowChain = root->overflowChain;
      tmp = root;
      root = root->overflowChain;
      FREE(tmp);
      continue;
    case STAT_UP:
      if ( (now > root->isAlive) && /* concurrency might make this false... */
	   (now - root->isAlive > SECONDS_INACTIVE_DROP * cronSECONDS) ) {
	EncName enc;

	/* switch state form UP to DOWN: too much inactivity */
	IFLOG(LOG_DEBUG,
	      hash2enc(&root->session.sender.hashPubKey,
		       &enc));
	LOG(LOG_DEBUG,
	    "closing connection with %s: too much inactivity (%llu ms)\n",
	    &enc,
	    now - root->isAlive);
	shutdownConnection(root);
	whitelistHost(&root->session.sender); /* the host may still be worth trying again soon */
	CONNECTION_currentActiveHosts--;
	statChange(stat_number_of_connections,
		   -1);
	break;
      } 
      activePeerCount++;
      if ( (CONNECTION_currentActiveHosts*4 < CONNECTION_MAX_HOSTS_*3) &&
	   (now - root->isAlive > SECONDS_PINGATTEMPT * cronSECONDS) ){
	/* if we have less than 75% of the number of connections
	   that we would like to have, try ping-ing the other side
	   to keep the connection open instead of hanging up */
	PINGPONG_Message pmsg;
	HostIdentity * hi = MALLOC(sizeof(HostIdentity));
#if DEBUG_CONNECTION
	EncName enc;
		
	IFLOG(LOG_DEBUG,
	      hash2enc(&root->session.sender.hashPubKey, 
		       &enc));
	LOG(LOG_DEBUG,
	    "sending keepalive-ping to peer %s\n",
	    &enc);
#endif
	memcpy(hi, 
	       &root->session.sender, 
	       sizeof(HostIdentity));
	if (OK == pingAction(&root->session.sender,
			     (CronJob)&notifyPING,
			     hi,
			     &pmsg)) {
	  SendEntry * entry;

	  entry = MALLOC(sizeof(SendEntry));
	  entry->len = sizeof(PINGPONG_Message);
	  entry->flags = SE_FLAG_NONE;
	  entry->pri = getConnectPriority(); 
	  entry->transmissionTime = now + 50 * cronMILLIS;
	  entry->callback = &copyCallback;
	  entry->closure = MALLOC(sizeof(PINGPONG_Message));
	  memcpy(entry->closure,
		 &pmsg,
		 sizeof(PINGPONG_Message));	  
	  appendToBuffer(root, 
			 entry);
	} else
	  FREE(hi);
      }
      break;
    case STAT_WAITING_FOR_PING:
      if ( (now > root->isAlive) &&
	   (now - root->isAlive > SECONDS_NOPINGPONG_DROP * cronSECONDS) ) {
#if DEBUG_CONNECTION
        EncName enc;
	IFLOG(LOG_DEBUG, 
	      hash2enc(&root->session.sender.hashPubKey, &enc));
	LOG(LOG_DEBUG,
	    "closing connection to %s: SKEY not answered by PING\n",
	    &enc);
#endif
	shutdownConnection(root);      
      }
      break;
    case STAT_WAITING_FOR_PONG:
      if ( (now > root->isAlive) &&
	   (now - root->isAlive > SECONDS_NOPINGPONG_DROP * cronSECONDS) ) {
#if DEBUG_CONNECTION
	EncName enc;
	IFLOG(LOG_DEBUG,
	      hash2enc(&root->session.sender.hashPubKey, &enc));
	LOG(LOG_DEBUG,
	    "closing connection to %s: PING not answered by PONG\n",
	    &enc);
#endif
	shutdownConnection(root);      
      } else
	checkAndPing(root);
      break;
    default:
      BREAK(); /* root->status unknown! */
      break; /* do nothing */
    } /* end of switch */ 
    sendBuffer(root);

    prev = root;
    root = root->overflowChain;
  } /* end of while */
  if (CONNECTION_buffer_[lastLivenessHost] == NULL) {
    /*LOG(LOG_EVERYTHING,
	" scanning for peer using slot %u\n",
	lastLivenessHost);*/
    if (! testConfigurationString("GNUNETD",
				  "DISABLE-AUTOCONNECT",
				  "YES"))
      scanForHosts(lastLivenessHost);
  }

  lastLivenessHost++;
  if (lastLivenessHost >= CONNECTION_MAX_HOSTS_)
    lastLivenessHost = 0;
  MUTEX_UNLOCK(&lock);
}

/**
 * Check the sequence number.  Updates the sequence number as a
 * side-effect.
 *
 * @param sender from which peer did we receive the SEQ message
 * @param msg the sequence message
 * @returns OK if ok, SYSERR if not.
 */
static int checkSequenceNumber(const HostIdentity * sender,
			       const p2p_HEADER * msg) {
  SEQUENCE_Message * smsg;
  BufferEntry * be;
  int res;
  unsigned int sequenceNumber;
  
  ENTRY();
  if (ntohs(msg->size) != sizeof(SEQUENCE_Message)) {
    LOG(LOG_WARNING,
	_("Sequence message received has wrong size: %d\n"),
	ntohs(msg->size));
    return SYSERR;
  }
  smsg = (SEQUENCE_Message*) msg;
  sequenceNumber = ntohl(smsg->sequenceNumber);
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be == NULL) {
    BREAK();
    MUTEX_UNLOCK(&lock);
    return SYSERR; /* host not found */
  }
  res = OK;
  if (be->lastSequenceNumberReceived >= sequenceNumber) {
    unsigned int rotbit = 1;
    if ( (be->lastSequenceNumberReceived - sequenceNumber <= 32) && 
	 (be->lastSequenceNumberReceived != sequenceNumber) ) {
      rotbit = rotbit << (be->lastSequenceNumberReceived - sequenceNumber - 1);
      if ( (be->lastPacketsBitmap & rotbit) == 0) {
	res = OK;
	be->lastPacketsBitmap |= rotbit;
      } else
	res = SYSERR;
    } else
      res = SYSERR;
    if (res == SYSERR) {
      LOG(LOG_WARNING,
	  _("Invalid sequence number"
	    " %u <= %u, dropping rest of packet.\n"),
	  sequenceNumber, 
	  be->lastSequenceNumberReceived);
    }    
  } else {    
    be->lastPacketsBitmap = 
      be->lastPacketsBitmap << (sequenceNumber - be->lastSequenceNumberReceived);
    be->lastSequenceNumberReceived = sequenceNumber;
  }
  MUTEX_UNLOCK(&lock);
  if (res == SYSERR)
    LOG(LOG_INFO,
	_("Message received has old sequence number. Dropped.\n"));
  return res;
}

/**
 * We received a request from a client to provide the number
 * of directly connected peers.  Sends the response.
 * 
 * @param client the socket connecting to the client
 * @param msg the request from the client
 * @returns OK if ok, SYSERR if not.
 */
static int processGetConnectionCountRequest(ClientHandle client,
					    const CS_HEADER * msg) {
  if (ntohs(msg->size) != sizeof(CS_HEADER)) {
    BREAK();
    return SYSERR;
  }
  return sendTCPResultToClient
    (client,
     CONNECTION_currentActiveHosts);
}


/**
 * Handler for processing P2P HANGUP message.  Terminates
 * a connection (if HANGUP message is valid).
 *
 * @param sender the peer sending the HANGUP message
 * @param msg the HANGUP message
 * @return OK on success, SYSERR on error
 */
static int handleHANGUP(const HostIdentity * sender,
			const p2p_HEADER * msg) {
  BufferEntry * be;
  EncName enc;

  ENTRY();
  if (ntohs(msg->size) != sizeof(HANGUP_Message))
    return SYSERR;
  if (!hostIdentityEquals(sender,
			  &((HANGUP_Message*)msg)->sender))
    return SYSERR;
  IFLOG(LOG_INFO,
	hash2enc(&sender->hashPubKey, 
		 &enc));
#if DEBUG_CONNECTION
  LOG(LOG_INFO,
      "received HANGUP from %s\n",
      &enc);
#endif
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be == NULL) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "closing connection, received HANGUP\n");
#endif
  shutdownConnection(be);
  MUTEX_UNLOCK(&lock);
  return OK;
}

/**
 * Handler for processing CAPABILITY.  Resets the bandwidth
 * limit of a connection (or other capabilities that we may
 * define in the future).
 *
 * @param sender peer that send the CAP message
 * @param msg the CAP message
 * @return OK on success, SYSERR on error
 */
static int handleCAPABILITY(const HostIdentity * sender,
			    const p2p_HEADER * msg) {
  BufferEntry * be;
  EncName enc;
  CAPABILITY_Message * cap;

  ENTRY();
  if (ntohs(msg->size) != sizeof(CAPABILITY_Message))
    return SYSERR;
  cap =  (CAPABILITY_Message*)msg;
  IFLOG(LOG_INFO,
	hash2enc(&sender->hashPubKey, 
		 &enc));
#if DEBUG_CONNECTION
  LOG(LOG_INFO,
      "received CAPABILITY from %s\n",
      &enc);
#endif
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be == NULL) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  switch (ntohl(cap->cap.capabilityType)) {
  case CAP_BANDWIDTH_RECV:
    be->max_bpm = ntohl(cap->cap.value);
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"received cap of %u bpm\n",
	be->max_bpm);
#endif
    if (be->available_send_window >= be->max_bpm) {
      be->available_send_window = be->max_bpm;
      cronTime(&be->last_bps_update);
    }
    break;
  default:
    IFLOG(LOG_INFO,
	  BREAK()); /* unknown capability type (cap.capaibilityType) */
    break;
  }
  MUTEX_UNLOCK(&lock);  
  return OK;
}


/**
 * Check if the received session key is properly signed.
 *
 * @param hostId the sender of the key
 * @param sks the session key message
 * @return SYSERR if invalid, OK if valid
 */
static int verifySKS(const HostIdentity * hostId,
		     SKEY_Message * sks) {
  HashCode160 keyHash;
  EncName hostName;
  HELO_Message * helo;
  char * limited;
  
  ENTRY();
  if ( (sks == NULL) ||
       (hostId == NULL) ) {
    BREAK();
    return SYSERR;
  }
  /* check if we are allowed to accept connections
     from that peer */
  limited = getConfigurationString("GNUNETD",
				   "LIMIT-ALLOW");
  if (limited != NULL) {
    EncName enc;
    hash2enc(&hostId->hashPubKey,
	     &enc);
    if (NULL == strstr(limited,
		       (char*) &enc)) {
      LOG(LOG_DEBUG,
	  "Connection from peer '%s' was rejected.\n",
	  &enc);
      FREE(limited);
      return SYSERR;
    }
    FREE(limited);
  }
  limited = getConfigurationString("GNUNETD",
				   "LIMIT-DENY");
  if (limited != NULL) {
    EncName enc;
    hash2enc(&hostId->hashPubKey,
	     &enc);
    if (NULL != strstr(limited,
		       (char*) &enc)) {
      LOG(LOG_DEBUG,
	  "Connection from peer '%s' was rejected.\n",
	  &enc);
      FREE(limited);
      return SYSERR;
    }
    FREE(limited);
  }
  
  if (SYSERR == identity2Helo(hostId, 
			      ANY_PROTOCOL_NUMBER,
			      YES,
			      &helo)) {
    IFLOG(LOG_INFO,
	  hash2enc(&hostId->hashPubKey, 
		   &hostName));
    LOG(LOG_INFO, 
	"verifySKS: host %s for sessionkey exchange not known\n",
	&hostName);
    return SYSERR;
  }
  /* verify signature */
  hash(&sks->body, 
       sizeof(RSAEncryptedData) + sizeof(TIME_T),
       &keyHash);
  if (!verifySig(&keyHash,
		 sizeof(HashCode160),
		 &sks->body.signature, 
		 &helo->publicKey)) {
    EncName enc;
    IFLOG(LOG_WARNING,
	  hash2enc(&hostId->hashPubKey,
		   &enc));
    LOG(LOG_WARNING, 
	_("Session key from peer '%s' has invalid signature!\n"),
	&enc);
    FREE(helo);
    return SYSERR; /*reject!*/
  }
  FREE(helo);
#if VERBOSE_STATS
  statChange(stat_sessionkeys_verified, 1);
#endif
  return OK; /* ok */
}

/**
 * Call once in a while to synchronize trust values with the disk.
 */
static void cronFlushTrustBuffer(void * unused) {
#if DEBUG_CONNECTION
  LOG(LOG_CRON,
      "enter cronFlushTrustBuffer\n");
#endif
  MUTEX_LOCK(&lock);
  forAllConnectedHosts(&flushHostCredit, unused);
  MUTEX_UNLOCK(&lock);
#if DEBUG_CONNECTION
  LOG(LOG_CRON, 
      "exit cronFlushTrustBuffer\n");
#endif
}

/**
 * Connect to another peer.
 *
 * @param hostId the peer to connect with
 * @return the connection handle
 */
static BufferEntry * connectTo(const HostIdentity * hostId) {
  BufferEntry * be;
  EncName enc;

  ENTRY();
  if (hostIdentityEquals(&myIdentity, 
			 hostId)) {
    BREAK();
    return NULL;
  }
  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
  be = lookForHost(hostId);
  if ( (be == NULL) || 
       (be->status == STAT_DOWN) ) {
    be = addHost(hostId, YES);   /* we *really* want to talk to this guy */
    if (be->status == STAT_DOWN)
      exchangeKey(be); /* note that exchangeKey
			  can fail and leave the buffer
			  in "down" state, e.g. if we don't
			  know any key for the other peer */
  }
  return be;
}

/**
 * How important is it at the moment to establish more connections?
 *
 * @return a measure of the importance to establish connections
 */
int getConnectPriority() {
  if (CONNECTION_MAX_HOSTS_ > 4*CONNECTION_currentActiveHosts)
    return EXTREME_PRIORITY;
  if (CONNECTION_MAX_HOSTS_ > 2*CONNECTION_currentActiveHosts)
    return (CONNECTION_MAX_HOSTS_ - CONNECTION_currentActiveHosts)*256;  
  if (CONNECTION_MAX_HOSTS_ > CONNECTION_currentActiveHosts)
    return (CONNECTION_MAX_HOSTS_ - CONNECTION_currentActiveHosts)*64;  
  return 0;
}

/**
 * Consider switching the transport mechanism used for contacting
 * the given node. This function is called when the handler handles
 * an encrypted connection. For example, if we are sending SMTP
 * messages to a node behind a NAT box, but that node has established
 * a TCP connection to us, it might just be better to send replies
 * on that TCP connection instead of keeping SMTP going.<p>
 *
 * We can only successfully takeover if the transport is bidirectional
 * (can be associated). It also only makes sense if the cost is lower.
 * This method checks both.
 *
 * @param tsession the transport session that is for grabs
 * @param sender the identity of the other node
 */
void considerTakeover(TSession * tsession,
		      const HostIdentity * sender) {
  BufferEntry * be;

  ENTRY();
  if (tsession == NULL)
    return;
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be != NULL) {
    if (be->status != STAT_DOWN) {
      unsigned int cost = -1;
      if (be->session.tsession != NULL)
	cost = transportGetCost(be->session.tsession->ttype);
      /* Question: doesn't this always do takeover in tcp/udp
	 case, which have the same costs? Should it? -IW 

	 Answer: this will always switch to TCP in the long run (if
	 that is possible) since udpAssociate always
	 returns SYSERR. This is intended since for long-running
	 sessions, TCP is the better choice. UDP is only better for
	 sending very few messages (e.g. attempting an initial exchange
	 to get to know each other). See also transport paper and the
	 data on throughput. - CG
      */
      if (transportGetCost(tsession->ttype) >= cost) {
	if (transportAssociate(tsession) == OK) {
	  transportDisconnect(be->session.tsession);
	  be->session.tsession = tsession;
	}
      } /* end if cheaper AND possible */
    } /* end if connected */
  }
  MUTEX_UNLOCK(&lock);
}


/**
 * Accept a session-key that has been sent by another host.
 * The other host must be known (public key)
 *
 * @param sender the identity of the sender host
 * @param tsession the transport session handle
 * @param msg message with the session key
 * @return SYSERR or OK
 */
int acceptSessionKey(const HostIdentity * sender,
		     TSession * tsession,
		     const p2p_HEADER * msg) {
  BufferEntry * be;
  EncName hostName;
  SESSIONKEY key;
  SKEY_Message * sessionkeySigned;
  unsigned short ttype;
  
  ENTRY();
#if VERBOSE_STATS
  statChange(stat_sessionkeys_received, 1);
#endif
  if (ntohs(msg->size) != sizeof(SKEY_Message))
    return SYSERR;
  sessionkeySigned = (SKEY_Message *) msg;
  IFLOG(LOG_DEBUG,
	hash2enc(&sender->hashPubKey,
		 &hostName));
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG, 
      "Received sessionkey from host %s.\n",
      &hostName);
#endif
  if (SYSERR == verifySKS(sender, 
			  sessionkeySigned)) {
    IFLOG(LOG_INFO,
	  hash2enc(&sender->hashPubKey,
		   &hostName));
    LOG(LOG_INFO, 
	_("Session key from '%s' failed verification, ignored!\n"), 
	&hostName);
    return SYSERR;  /* rejected */
  }
  if (tsession != NULL)
    ttype = tsession->ttype;
  else
    ttype = -1;

  /* prepare file */
  if (sizeof(SESSIONKEY) != 
      decryptData(&sessionkeySigned->body.key,
		  &key,
		  sizeof(SESSIONKEY))) {
    IFLOG(LOG_WARNING,
	  hash2enc(&sender->hashPubKey,
		   &hostName));
    LOG(LOG_WARNING, 
	_("Invalid '%s' message received from peer '%s'.\n"),
	"SKEY",
	&hostName);
    return SYSERR;
  }

  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be == NULL) 
    be = addHost(sender, NO);
  if (be == NULL) {
    IFLOG(LOG_INFO,
	  hash2enc(&sender->hashPubKey,
		   &hostName));
    LOG(LOG_INFO, 
	"Session key exchange with '%s' denied, slot busy.\n",
	&hostName);
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }

  if (be->created > (TIME_T)ntohl(sessionkeySigned->body.creationTime)) {
#if DEBUG_CONNECTION
    LOG(LOG_INFO, 
	"key dropped, we've sent or received a more recent key!\n");
#endif
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }

  /* if we have another connection established with the node,
     shut it down! */
  if (be->session.tsession != NULL) {
#if DEBUG_CONNECTION
    IFLOG(LOG_DEBUG,
	  hash2enc(&sender->hashPubKey,
		   &hostName));
    LOG(LOG_DEBUG,
	"Closing old connection with '%s', received new session key.\n",
	&hostName);
#endif
    shutdownConnection(be);
  }

  /* try to associate with an existing connection (if the other side
     contacted us with a bi-directional protocol, if that fails, establish
     our own connection */
  if (SYSERR == transportAssociate(tsession)) {
    HELO_Message * helo;

    tsession = NULL;
    if (SYSERR == identity2Helo(sender,
				ANY_PROTOCOL_NUMBER,
				NO,
				&helo)) {
      IFLOG(LOG_INFO,
 	    hash2enc(&sender->hashPubKey,
		     &hostName));
      LOG(LOG_INFO, 
	  _("Sessionkey received from peer '%s',"
	    " but I could not find a transport that would allow me to reply (%d).\n"),
	  &hostName,
	  ttype);
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
    if (SYSERR == transportConnect(helo,	
				   &tsession)) {
      IFLOG(LOG_WARNING,
 	    hash2enc(&sender->hashPubKey,
		     &hostName));
      LOG(LOG_WARNING, 
	  _("Sessionkey received from peer '%s', but transport failed to connect.\n"),
	  &hostName);
      FREE(helo);
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
  }
  /* ok, everything set, let's change the state to waiting for ping
     and initialize the buffer entry */
  memcpy(&be->skey,
	 &key,
	 SESSIONKEY_LEN);
  be->session.tsession 
    = tsession;
  be->session.isEncrypted 
    = YES;
  be->session.mtu 
    = transportGetMTU(be->session.tsession->ttype);
  be->created 
    = ntohl(sessionkeySigned->body.creationTime);
  be->status 
    = STAT_WAITING_FOR_PONG;
  be->lastSequenceNumberReceived 
    = 0;
  be->lastPacketsBitmap 
    = (unsigned int) -1; /* all bits set */
  if (be->sendBuffer != NULL)
    BREAK();
  be->lastSequenceNumberSend
    = 1;

#if DEBUG_CONNECTION
  LOG(LOG_DEBUG, 
      "SKEY exchange - sending encrypted ping\n");
#endif
  checkAndPing(be);
  MUTEX_UNLOCK(&lock);
  return OK;
}

#define TRUSTDIR "data/credit/"

static void connectionConfigChangeCallback() {
  long new_max_bpm;
  unsigned int i;

  MUTEX_LOCK(&lock);
  /* max_bpm may change... */
  new_max_bpm
    = 60 * getConfigurationInt("LOAD",
			       "MAXNETDOWNBPSTOTAL");
  if (new_max_bpm == 0)
    new_max_bpm = 50000 * 60; /* assume 50 kbps */
  if (max_bpm != new_max_bpm) {
    int newMAXHOSTS = 0;

    max_bpm = new_max_bpm;
    /* max-hosts is supposed to allow TARGET_MSG_SID MTU-sized messages
       per SECONDS_INACTIVE_DROP; maxbps=max_bpm/60 =>
       byte per SID = maxbpm*SID/60; divide by MTU to
       get number of messages that can be send per SID */
    newMAXHOSTS
      = max_bpm / MIN_BPM_PER_PEER;
    /* => for 50000 bps, we get 78 (rounded DOWN to 64) connections! */
  
    if (newMAXHOSTS < 2)
      newMAXHOSTS = 2; /* strict minimum is 2 */
    i = 1;
    while (i <= newMAXHOSTS)
      i*=2;
    newMAXHOSTS = i/2; /* make sure it's a power of 2 */
    
    if (newMAXHOSTS != CONNECTION_MAX_HOSTS_) {
      /* change size of connection buffer!!! */
      unsigned int olen;
      BufferEntry ** newBuffer;

      olen = CONNECTION_MAX_HOSTS_;
      CONNECTION_MAX_HOSTS_ = newMAXHOSTS;
      setConfigurationInt("gnunetd",
			  "connection-max-hosts",
			  CONNECTION_MAX_HOSTS_);
      newBuffer = (BufferEntry**) MALLOC(sizeof(BufferEntry*)*newMAXHOSTS);
      for (i=0;i<CONNECTION_MAX_HOSTS_;i++) 
	newBuffer[i] = NULL;

      /* rehash! */
      for (i=0;i<olen;i++) {
	BufferEntry * be;

	be = CONNECTION_buffer_[i];
	while (be != NULL) {
	  BufferEntry * next;
	  unsigned int j;

	  next = be->overflowChain;
	  j = computeIndex(&be->session.sender);
	  be->overflowChain = newBuffer[j];
	  newBuffer[j] = be;
	  be = next;
	}
      }
      FREENONNULL(CONNECTION_buffer_);
      CONNECTION_buffer_ = newBuffer;

      LOG(LOG_DEBUG,
	  "connection goal is %s%d peers (%llu BPS bandwidth downstream)\n",
	  (olen == 0) ? "" : "now ",
	  CONNECTION_MAX_HOSTS_,
	  max_bpm);
      
    }  
  }
  disable_random_padding = testConfigurationString("GNUNETD-EXPERIMENTAL",
						   "PADDING",
						   "NO");
  MUTEX_UNLOCK(&lock);
}

/**
 * Initialize this module.
 */
void initConnection() {
  char * gnHome;

  ENTRY();
  stat_MsgsExpired
    = statHandle(_("# messages expired (bandwidth stressed too long)"));
#if VERBOSE_STATS
  stat_sessionkeys_received 
    = statHandle(_("# sessionkeys received"));
  stat_sessionkeys_verified 
    = statHandle(_("# valid sessionkeys received"));
  stat_sessionkeys_transmitted
    = statHandle(_("# sessionkeys sent"));
  stat_connections_shutdown
    = statHandle(_("# connections shutdown"));
#endif
  stat_total_messages_queued
    = statHandle(_("# messages in all queues"));
  stat_number_of_connections 
    = statHandle(_("# currently connected nodes"));
  stat_number_of_bytes_noise_send
    = statHandle(_("# bytes noise sent"));
  stat_number_of_bytes_send
    = statHandle(_("# encrypted bytes sent"));
  stat_number_of_bytes_received
    = statHandle(_("# bytes decrypted"));
  scl_nextHead 
    = NULL;
  scl_nextTail 
    = NULL;
  MUTEX_CREATE_RECURSIVE(&lock);
  registerConfigurationUpdateCallback(&connectionConfigChangeCallback);
  CONNECTION_MAX_HOSTS_ = 0;
  connectionConfigChangeCallback();
  CONNECTION_currentActiveHosts 
    = 0;

  registerp2pHandler(p2p_PROTO_SEQUENCE,
		     &checkSequenceNumber);
  registerp2pHandler(p2p_PROTO_HANGUP,
		     &handleHANGUP);
  registerp2pHandler(p2p_PROTO_CAPABILITY,
		     &handleCAPABILITY);
  registerCSHandler(CS_PROTO_CLIENT_COUNT,
		    &processGetConnectionCountRequest);
  addCronJob(&cronCountConnections,
	     1 * cronMINUTES,
	     30 * cronSECONDS,
	     NULL);
  addCronJob(&cronDecreaseLiveness,
	     1 * cronSECONDS, 
	     cronMINUTES / CONNECTION_MAX_HOSTS_ / 5,
	     NULL); 
  gnHome = getFileName("",
		       "GNUNETD_HOME",
		       _("Configuration file must specify a "
			 "directory for GNUnet to store "
			 "per-peer data under %s%s\n"));
  trustDirectory = MALLOC(strlen(gnHome) + 
			  strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  FREE(gnHome);
  strcat(trustDirectory, "/");
  strcat(trustDirectory, TRUSTDIR);
  mkdirp(trustDirectory);
  addCronJob(&cronFlushTrustBuffer,
	     5 * cronMINUTES,
	     5 * cronMINUTES,
	     NULL);

#if DEBUG_COLLECT_PRIO == YES
  prioFile = FOPEN("/tmp/knapsack_prio.txt", "w");
#endif
}


/**
 * Shutdown the connection module.
 */
void doneConnection() {
  unsigned int i;
  BufferEntry * be;
  SendCallbackList * scl;
  
  ENTRY();
  unregisterConfigurationUpdateCallback(&connectionConfigChangeCallback);
  delCronJob(&cronFlushTrustBuffer,
	     5 * cronMINUTES,
	     NULL);
  unregisterCSHandler(CS_PROTO_CLIENT_COUNT,
		      &processGetConnectionCountRequest);
  unregisterp2pHandler(p2p_PROTO_SEQUENCE,
		     &checkSequenceNumber);
  delCronJob(&cronCountConnections,
	     30 * cronSECONDS, 
	     NULL);
  delCronJob(&cronDecreaseLiveness,
	     cronMINUTES / CONNECTION_MAX_HOSTS_, 
	     NULL); 
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    BufferEntry * prev;

    prev = NULL;
    be = CONNECTION_buffer_[i];
    while (be != NULL) {
      LOG(LOG_DEBUG,
	  "Closing connection: shutdown\n");
      shutdownConnection(be);
      flushHostCredit(be, NULL);    
      prev = be;
      be = be->overflowChain;
      FREE(prev);
    }
  } 
  MUTEX_DESTROY(&lock);
  FREENONNULL(CONNECTION_buffer_);
  CONNECTION_buffer_ = NULL;
  CONNECTION_MAX_HOSTS_ = 0;
  FREE(trustDirectory);
  trustDirectory = NULL;
  while (scl_nextHead != NULL) {
    scl = scl_nextHead;
    scl_nextHead = scl_nextHead->next;
    FREE(scl);
  }
  scl_nextTail = NULL;
#if DEBUG_COLLECT_PRIO == YES
  fclose(prioFile);
#endif
}

/**
 * Increase the host credit by a value. 
 *
 * @param hostId is the identity of the host
 * @param value is the int value by which the host credit is to be increased or
 *        decreased
 * @returns the actual change in trust (positive or negative)
 */
unsigned int changeHostCredit(const HostIdentity * hostId, 
			      int value){
  BufferEntry * be;

  if (value == 0)
    return 0;

  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
  if (be == NULL) {
    MUTEX_UNLOCK(&lock);
    return 0; /* not connected! */
  }
  if ( (be->trust & TRUST_ACTUAL_MASK) + value < 0) {
    value = - (be->trust & TRUST_ACTUAL_MASK);
    be->trust = 0 | TRUST_REFRESH_MASK; /* 0 remaining */ 
  } else {
    be->trust = ( (be->trust & TRUST_ACTUAL_MASK) + value) | TRUST_REFRESH_MASK;
  }
  MUTEX_UNLOCK(&lock);
  return value;
}

/**
 * Obtain the trust record of a peer.
 * 
 * @param hostId the identity of the peer
 * @return the amount of trust we currently have in that peer
 */
unsigned int getHostCredit(const HostIdentity * hostId) {
  BufferEntry * be;
  unsigned int trust;

  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
  if (be == NULL) {
    MUTEX_UNLOCK(&lock);
    return 0;
  }
  trust = be->trust;
  MUTEX_UNLOCK(&lock);
  return trust & TRUST_ACTUAL_MASK;
}

/**
 * Wrapper around forAllConnectedHosts.  Calls a given
 * method for each connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
int forEachConnectedNode(PerNodeCallback method,
			 void * arg) {
  fENHWrap wrap;
  int ret;

  wrap.method = method;
  wrap.arg = arg;
  MUTEX_LOCK(&lock);
  ret = forAllConnectedHosts(&fENHCallback,
			     &wrap);
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Print the contents of the connection buffer (for debugging).
 */
void printConnectionBuffer() {
  unsigned int i;
  BufferEntry * tmp;
  EncName hostName;
  EncName skey;
  unsigned short ttype;

  MUTEX_LOCK(&lock);
  ENTRY();
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    tmp = CONNECTION_buffer_[i];
    while (tmp != NULL) {
      if (tmp->status != STAT_DOWN) {
        IFLOG(LOG_MESSAGE,
  	      hash2enc(&tmp->session.sender.hashPubKey, 
  	  	       &hostName));
	IFLOG(LOG_MESSAGE,
	      hash2enc((HashCode160*) &tmp->skey,
		       &skey));
	ttype = 0;
	if (tmp->session.tsession != NULL)
	  ttype = tmp->session.tsession->ttype;
	LOG(LOG_MESSAGE,
  	    "CONNECTION-TABLE: %3d-%1d-%2d-%6u-%4ds"
	    " (of %ds) BPM %4ur %4ut %4ui-%3u: %20s-%16s\n",
	    i,
	    tmp->status,
	    ttype,
	    tmp->trust & TRUST_ACTUAL_MASK, 
	    (int) ((cronTime(NULL) - tmp->isAlive)/cronSECONDS), 
	    SECONDS_INACTIVE_DROP,
	    tmp->recently_received,
	    tmp->transmitted_limit,
	    tmp->idealized_limit,
	    tmp->sendBufferSize,
	    &hostName,
	    &skey);
      }
      tmp = tmp->overflowChain;
    }
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Register a callback method that should be invoked whenever a
 * message is about to be send that has more than minimumPadding bytes
 * left before maxing out the MTU. The callback method can then be
 * used to add additional content to the message (instead of the
 * random noise that is added by otherwise). Note that if the MTU is 0
 * (for streams), the callback method will always be called with
 * padding set to the maximum number of bytes left in the buffer
 * allocated for the send.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return OK if the handler was registered, SYSERR on error
 */
int registerSendCallback(const unsigned int minimumPadding,
			 BufferFillCallback callback) {
  SendCallbackList * scl;

  ENTRY();
  scl = MALLOC(sizeof(SendCallbackList));
  scl->minimumPadding = minimumPadding;
  scl->callback = callback;
  scl->next = NULL;
  MUTEX_LOCK(&lock);
  if (scl_nextTail == NULL) {
    scl_nextHead = scl;
    scl_nextTail = scl;
  } else {
    scl_nextTail->next = scl;
    scl_nextTail = scl;
  }
  MUTEX_UNLOCK(&lock);
  return OK;  
}
 
/**
 * Unregister a handler that was registered with registerSendCallback.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return OK if the handler was removed, SYSERR on error
 */
int unregisterSendCallback(const unsigned int minimumPadding,
			   BufferFillCallback callback) {
  SendCallbackList * pos;
  SendCallbackList * prev;
  
  prev = NULL;
  MUTEX_LOCK(&lock);
  pos = scl_nextHead;
  while (pos != NULL) {
    if ( (pos->callback == callback) &&
	 (pos->minimumPadding == minimumPadding) ) {
      if (prev == NULL) 
	scl_nextHead = pos->next;
      else
	prev->next = pos->next;
      if (scl_nextTail == pos)
	scl_nextTail = prev;
      FREE(pos);
      MUTEX_UNLOCK(&lock);
      return OK;     
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(&lock);
  return SYSERR;
}

/**
 * We received a sign of life from this host. 
 * 
 * @param hostId the peer that gave a sign of live
 */
void notifyPONG(const HostIdentity * hostId) {
  BufferEntry * be;
  EncName enc;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
  if (be != NULL) {
    switch (be->status) {
    case STAT_DOWN:
      break;
    case STAT_WAITING_FOR_PING:
      /* wrong message, ignore */
      break;
    case STAT_WAITING_FOR_PONG:
      be->status = STAT_UP;
      be->transmitted_limit = START_TRANSMIT_LIMIT; 
      be->idealized_limit = MIN_BPM_PER_PEER;
      transmitConnectionLimit(be);
      CONNECTION_currentActiveHosts++;
      cronTime(&be->isAlive);
      statChange(stat_number_of_connections,
		 1);
      IFLOG(LOG_DEBUG,
	    hash2enc(&hostId->hashPubKey, 
		     &enc));
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG, 
	  "Marking host %s active.\n",
	  &enc);
#endif
      break;
    case STAT_UP:
      cronTime(&be->isAlive);
      break;
    default:
      BREAK(); /* be->status undefined! */
      break;
    }
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * We received a sign of life from this host. 
 *
 * @param hostId the peer that send a PING.
 */
void notifyPING(const HostIdentity * hostId) {
  BufferEntry * be;
#if DEBUG_CONNECTION 
  EncName enc;
#endif

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
#if DEBUG_CONNECTION
  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
  LOG(LOG_DEBUG,
      "notify ping called for peer %s lookup result: %s\n",
      &enc,
      (be == NULL) ? "not found" : "found");
#endif
  if (be != NULL) {
    switch (be->status) {
    case STAT_DOWN:
      break;
    case STAT_WAITING_FOR_PONG:
      /* wrong message */
      break;
    case STAT_WAITING_FOR_PING:
      be->status = STAT_UP; 
      be->transmitted_limit = START_TRANSMIT_LIMIT; 
      be->idealized_limit = MIN_BPM_PER_PEER;
      transmitConnectionLimit(be);
      CONNECTION_currentActiveHosts++;
      statChange(stat_number_of_connections,
		 1);
      cronTime(&be->isAlive);
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG, 
	  "Marking host %s active.\n",
	  &enc);
#endif
      break;
    case STAT_UP:
      cronTime(&be->isAlive);
      break;
    default:
      LOG(LOG_WARNING, 
	  "unknown status!\n");
      break;
    }
  }
  MUTEX_UNLOCK(&lock);  
}

/**
 * Send a message to all directly connected nodes.
 *
 * @param message the message to send
 * @param priority how important is the message? The higher, the more important
 * @param maxdelay how long can we wait (max), in CRON-time (ms)
 */
void broadcast(const p2p_HEADER * message,
	       unsigned int priority,
	       unsigned int maxdelay) {
  unsigned int i;
  BufferEntry * tmp;

  ENTRY();
  MUTEX_LOCK(&lock);
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    tmp = CONNECTION_buffer_[i];
    while (tmp != NULL) {
      /* we need no sync here as we only read,
         and concurrent rw access does not hurt */
      if (tmp->status == STAT_UP) 
	sendToNode(&tmp->session.sender,
		   message,
		   priority,
		   maxdelay);
      tmp = tmp->overflowChain;
    }
  }
  MUTEX_UNLOCK(&lock);    
}

/**
 * Send a message to a specific host (reply, enqueue)
 *
 * @param message the message to send (unencrypted!), first 2 bytes give size
 * @param hostId the identity of the receiver
 * @param priority how important is the message?
 * @param maxdelay how long can we wait (max), in CRON-time (ms)
 */
void sendToNode(const HostIdentity * hostId,
		const p2p_HEADER * message,
		unsigned int priority,
		unsigned int maxdelay) {
  BufferEntry * be;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
  LOG(LOG_DEBUG, 
      "sendToNode: sending message to host %s message of type %d\n",
      &enc,
      ntohs(message->requestType));
#endif
  ENTRY();
  if (ntohs(message->size) < sizeof(p2p_HEADER)) {
    BREAK();
    return;
  }

  if (hostIdentityEquals(hostId,
			 &myIdentity)) {
    MessagePack * mp;

    mp = MALLOC(sizeof(MessagePack));
    mp->msg = MALLOC(ntohs(message->size));
    mp->tsession = NULL;
    mp->sender = myIdentity;
    mp->size = ntohs(message->size);
    mp->isEncrypted = LOOPBACK;
    mp->crc = crc32N(message, mp->size);
    memcpy(mp->msg,
	   message,
	   ntohs(message->size));
    core_receive(mp);
    return;
  }

  MUTEX_LOCK(&lock);
  be = connectTo(hostId); 
  if ( (be != NULL) &&
       (be->status != STAT_DOWN) ) {  
    SendEntry * entry;
    unsigned short len = ntohs(message->size);

    entry = MALLOC(sizeof(SendEntry));
    entry->len = ntohs(message->size);
    entry->flags = SE_FLAG_NONE;
    entry->pri = priority;
    entry->transmissionTime = cronTime(NULL) + maxdelay;
    entry->callback = &copyCallback;
    entry->closure = MALLOC(len);
    memcpy(entry->closure,
	   message,
	   len);
    appendToBuffer(be,
		   entry);
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Send an encrypted, on-demand build message to another node.
 *
 * @param hostId the target node
 * @param callback the callback to build the message
 * @param closure the second argument to callback
 * @param len how long is the message going to be?
 * @param importance how important is the message?
 * @param maxdelay how long can the message wait?
 */
void unicast(const HostIdentity * hostId,
	     BuildMessageCallback callback,
	     void * closure,
	     unsigned short len,
	     unsigned int importance,
	     unsigned int maxdelay) {
  BufferEntry * be;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
  LOG(LOG_DEBUG, 
      "unicast: sending message to host %s message of size %d\n",
      &enc,
      len);
#endif
  ENTRY();
  MUTEX_LOCK(&lock);
  be = connectTo(hostId); 
  if ( (be != NULL) &&
       (be->status != STAT_DOWN) ) {  
    SendEntry * entry;

    entry = MALLOC(sizeof(SendEntry));
    entry->len = len;
    entry->flags = SE_FLAG_NONE;
    entry->pri = importance;
    entry->transmissionTime = cronTime(NULL) + maxdelay;
    entry->callback = callback;
    entry->closure = closure;
    appendToBuffer(be,
		   entry);
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Shutdown all connections (send HANGUPs, too).
 */
void shutdownConnections() {
  MUTEX_LOCK(&lock);
  LOG(LOG_DEBUG,
      "shutdown of all connections\n");
  forAllConnectedHosts((BufferEntryCallback)&shutdownConnection, 
		       NULL);
  MUTEX_UNLOCK(&lock);
}

/**
 * Are we connected to this peer?
 *
 * @param hi the peer in question
 * @return NO if we are not connected, YES if we are
 */
int isConnected(const HostIdentity * hi) {
  BufferEntry * be;

  MUTEX_LOCK(&lock);
  be = lookForHost(hi);
  MUTEX_UNLOCK(&lock);
  if (be == NULL) {
    return NO;
  } else {
    return (be->status == STAT_UP);
  }
}
	       
/**
 * Decipher data coming in from a foreign host.
 *
 * @param data the data to decrypt
 * @param size the size of the encrypted data
 * @param hostId the sender host that encrypted the data 
 * @param result where to store the decrypted data, must
 *        be at least of size data->len long
 * @return the size of the decrypted data, SYSERR on error
 */
int decryptFromHost(const void * data,
		    const unsigned short size,
		    const HostIdentity * hostId,
		    void * result) {  
  BufferEntry * be;
  int res;
  EncName enc;

  ENTRY();
  statChange(stat_number_of_bytes_received, size);
  if ( (data == NULL) || 
       (hostId == NULL) ) {    
    BREAK();
    return SYSERR;
  }
  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, 
		 &enc));
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG, 
      "decrypting message from host %s\n",
      &enc);
#endif
  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
  if (be == NULL) {
    IFLOG(LOG_INFO,
	  hash2enc(&hostId->hashPubKey, 
		   &enc));
    LOG(LOG_INFO, 
	"decrypting message from host %s failed, no sessionkey!\n",
	&enc);
    /* try to establish a connection, that way, we don't keep
       getting bogus messages until the other one times out. */
    connectTo(hostId); 
    MUTEX_UNLOCK(&lock);
    return SYSERR; /* could not decrypt */
  }
  res = decryptBlock(&be->skey, 
		     data,
		     size,
		     INITVALUE,
		     result);
  MUTEX_UNLOCK(&lock);
  return res;
}

/**
 * Compute the hashtable index of a host id.
 * 
 * @param hostId the ID of a peer
 * @return the index for this peer in the connection table
 */
unsigned int computeIndex(const HostIdentity * hostId) {
  unsigned int res = (((unsigned int)hostId->hashPubKey.a) & 
		      ((unsigned int)(CONNECTION_MAX_HOSTS_ - 1)));
  GNUNET_ASSERT(res <  CONNECTION_MAX_HOSTS_);
  return res;
}

/**
 * Obtain the lock for the connection module
 *
 * @return the lock
 */
Mutex * getConnectionModuleLock() {
  return &lock;
}

/**
 * Notification for per-connection bandwidth tracking:
 * we received size bytes from hostId.  Note that only
 * encrypted messages are counted as "real" traffic.
 *
 * @param hostId the peer that send the message
 * @param size the size of the message
 */
void trafficReceivedFrom(const HostIdentity * hostId,
			 const unsigned int size) {
  BufferEntry * be;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey, &enc));
  LOG(LOG_DEBUG,
      "received %u bytes from %s\n",
      size, 
      &enc);
#endif
  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(hostId);
  if (be != NULL ) {
    be->recently_received += size;
    cronTime(&be->isAlive);
  }
  MUTEX_UNLOCK(&lock);
}

unsigned int getBandwidthAssignedTo(const HostIdentity * node) {
  BufferEntry * be;
  unsigned int ret;
  
  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if (be != NULL) 
    ret = be->idealized_limit;
  else
    ret = 0;
  MUTEX_UNLOCK(&lock);
  return ret;  
}

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void updateTrafficPreference(const HostIdentity * node,
			     double preference) {
  BufferEntry * be;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if (be != NULL)
    be->current_connection_value += preference;
  MUTEX_UNLOCK(&lock);
}

/**
 * Disconnect a particular peer.  Sends a HANGUP message to the other
 * side and mark the sessionkey as dead.
 *
 * @param peer the peer to disconnect
 */
void disconnectFromPeer(const HostIdentity *node) {
  BufferEntry * be;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if (be != NULL)
    shutdownConnection(be);
  MUTEX_UNLOCK(&lock);
}

/* end of connection.c */
