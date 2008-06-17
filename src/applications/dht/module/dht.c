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
 * @file module/dht.c
 * @brief definition of the entry points to the module; implements
 *   the client-server application using the DHT service; the DHT
 *   service is based on RPC and the DHT itself is roughly based
 *   on kademlia.
 * @author Marko Räihä, Christian Grothoff
 *
 * 
 * Warning: what follows is 3.000+ lines of incomplete, crazy,
 * recursive, asynchronous, multithreaded routing code with plenty of
 * function pointers, too little documentation and no testing.  Pray
 * to the C gods before venturing any further.
 *
 *
 * Todo:
 * - various OPTIMIZE-MEs (make protocol cheaper by adding
 *   extra fields to messages, handle content migration, etc.)
 * - master-table-datastore needs content timeout functionality!
 * - fix plenty of bugs (unavoidable...)
 * - document (lots!)
 *   
 * Problems to investigate:
 * - get/put/remove routing: the first step by the initiator
 *   MAY go in any direction if the peer does not participate
 *   in the table, but after that we MUST guarantee that we
 *   always only route to peers closer to key (to avoid looping)
 * - put: to ensure we hit the replication level with reasonable
 *   precision, we must only store data locally if we're in the
 *   k-best peers for the datum by our best estimate
 * - put: check consistency between table-replication level
 *   and the user-specified replication level!
 * - security: how to pick priorities?  Access rights?
 * - errors: how to communicate errors (RPC vs. DHT errors)
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_rpc_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_dht_datastore_memory.h"

/* ********************* CONSTANTS ******************* */

/**
 * Enable/disable DHT debugging output.
 */
#define DEBUG_DHT YES

#if DEBUG_DHT
#define ENTER() LOG(LOG_EVERYTHING, "Entering method %s at %s:%d.\n", __FUNCTION__, __FILE__, __LINE__)
#else
#define ENTER() do {} while (0)
#endif

/**
 * Number of replications for the master table.  At maximum since
 * that table is quite important.
 */
#define ALPHA  (DHT_FLAGS_TABLE_REPLICATION_MASK)

/**
 * Frequency of the DHT maintain job (trade-off between
 * more smooth traffic from the maintain job and useless
 * CPU consumption for the job going over the table doing
 * nothing).
 */
#define DHT_MAINTAIN_FREQUENCY (15 * cronSECONDS)

/**
 * How often should we notify the master-table about our
 * bucket status?
 */ 
#define DHT_MAINTAIN_BUCKET_FREQUENCY (5 * cronMINUTES)

/**
 * After what time do peers always expire for good?
 */
#define DHT_INACTIVITY_DEATH (56 * DHT_MAINTAIN_FREQUENCY)

/**
 * For how long after the last message do we consider a peer
 * "hyperactive" and refuse to remove it from the table?
 */
#define DHT_HYPERACTIVE_TIME (60 * cronSECONDS)

/**
 * What is the trade-off factor between the number of tables that a
 * peer participates in and the additional time we give it before
 * removing it? (We may also want to take table-diversity into account
 * here, but for now just the number of tables will do).  Effectively,
 * a peer with k tables more stays DHT_TABLE_FACTOR seconds longer in
 * our connection list.
 */
#define DHT_TABLE_FACTOR (10 * cronSECONDS)

/**
 * What is the CURRENT target size for buckets?
 */
#define BUCKET_TARGET_SIZE (4 + DHT_FLAGS_TABLE_REPLICATION_MASK * tablesCount)


/* ********************* STRUCTS ************************** */
/* ******************and Function-Types******************** */

/**
 * Per-peer information.
 */
typedef struct {
  /**
   * What was the last time we received a message from this peer?
   */
  cron_t lastActivity;
  /**
   * What was the last time we received a table status message
   * from this peer?
   */
  cron_t lastTableRefresh;
  /**
   * What was the last time we send a PING to this peer?
   */ 
  cron_t lastTimePingSend;
  /**
   * In which tables do we know that peer to participate in?
   */
  DHT_TableId * tables;
  /**
   * How large is the tables array?
   */
  unsigned int tableCount;
  /**
   * What is the identity of the peer?
   */
  HostIdentity id;
} PeerInfo;

/**
 * Peers are grouped into buckets.
 */
typedef struct {
  /**
   * Peers in this bucket fall into the distance-range 
   * (2^bstart to 2^bend].
   */
  unsigned int bstart;

  /**
   * Peers in this bucket fall into the distance-range 
   * (2^bstart to 2^bend].
   */
  unsigned int bend;

  /**
   * Peers in this bucket.  NULL is used if no peer is known.
   */
  Vector * peers; /* contains PeerInfo instances */
} PeerBucket;

/**
 * Local information about a DHT table that this peer is participating
 * in.
 */
typedef struct {
  DHT_TableId id;
  DHT_Datastore * store;
  int flags;
  /**
   * What was the last time we advertised this nodes participation in
   * this table to the master table?
   */ 
  cron_t lastMasterAdvertisement;
} LocalTableData;


/**
 * Context for callbacks used by FindNodes.
 */
typedef struct {
  /**
   * Towards which key are we routing?
   */ 
  HashCode160 key;
  
  /**
   * In what table are we searching?
   */
  DHT_TableId table;

  /**
   * Signal used to return from findNodes when timeout has
   * expired.
   */
  Semaphore * signal;

  /**
   * Number of entries in matches.
   */
  unsigned int k;

  /**
   * Best k matches found so far.  Of size ALPHA.
   */
  HashCode160 * matches;
  
  /**
   * Number of RPCs transmitted so far (if it reaches
   * rpcRepliesExpected we can possibly abort before
   * the timeout!).
   */
  unsigned int rpcRepliesReceived;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * Handle for the async dht_get operation (NULL if
   * such an operation was not performed).
   */
  struct DHT_GET_RECORD * async_handle;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * When do we need to be done (absolute time).
   */
  cron_t timeout;  

  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} FindNodesContext;

/**
 * Callback for findNodes that is invoked whenever a node is found.
 *
 * @param identity the identity of the node that was found
 * @return OK to continue searching, SYSERR to abort early
 */
typedef int (*NodeFoundCallback)(HostIdentity * identity,
				 void * closure);

/**
 * Context for callbacks used by FindNodes.
 */
typedef struct {
  /**
   * Towards which key are we routing?
   */ 
  HashCode160 key;
  
  /**
   * In what table are we searching?
   */
  DHT_TableId table;

  /**
   * Number of entries to wait for
   */
  unsigned int k;

  /**
   * Number of entries found so far.
   */
  unsigned int found;
  
  /**
   * Number of RPCs transmitted so far (if it reaches
   * rpcRepliesExpected we can possibly abort before
   * the timeout!).
   */
  unsigned int rpcRepliesReceived;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * Handle for the async dht_get operation (NULL if
   * such an operation was not performed).
   */
  struct DHT_GET_RECORD * async_handle;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * When do we need to be done (absolute time).
   */
  cron_t timeout;  

  /**
   * Lock for accessing this struct.
   */
  Mutex lock;

  /**
   * Callback to call on the k nodes.
   */
  NodeFoundCallback callback;

  /**
   * Extra argument to the callback.
   */
  void * closure;
} FindKNodesContext;

/**
 * Context for async DHT_GET operation.
 */
typedef struct DHT_GET_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  /**
   * What is the key?
   */
  HashCode160 key;

  unsigned int resultsFound;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  /**
   * How many more results are we looking for?
   */
  unsigned int maxResults;

  DHT_GET_Complete callback;

  void * closure;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_GET_RECORD;

/**
 * Context for async DHT_PUT operation.
 */
typedef struct DHT_PUT_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  /**
   * What is the key?
   */
  HashCode160 key;

  DHT_DataContainer value;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  /**
   * How many copies should we try to make?
   */
  unsigned int replicationLevel;

  /**
   * The set of peers that have responded (and claim to have
   * made a replica).
   */
  HostIdentity * replicas;

  /**
   * Size of the replicas array.
   */
  unsigned int confirmedReplicas; /* size of replicas array! */

  /**
   * Callback to call upon completion.
   */
  DHT_PUT_Complete callback;

  /**
   * Extra argument to callback.
   */
  void * closure;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_PUT_RECORD;


/**
 * Context for async DHT_REMOVE operation.
 */
typedef struct DHT_REMOVE_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  /**
   * What is the key?
   */
  HashCode160 key;

  /**
   * Which value should be removed?
   */
  DHT_DataContainer value;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  /**
   * How many copies should we try to remove? (Or: how many
   * replicas do we expect to exist?)
   */
  unsigned int replicationLevel;

  /**
   * Number of remove confirmations received.
   */
  unsigned int confirmedReplicas;

  /**
   * Callback to call upon completion.
   */ 
  DHT_REMOVE_Complete callback;

  /**
   * Extra argument to callback.
   */
  void * closure;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_REMOVE_RECORD;



/**
 */
typedef struct {
  Semaphore * semaphore;
  unsigned int maxResults;
  unsigned int count;
  DHT_DataContainer * results;
} DHT_GET_SYNC_CONTEXT;

/**
 */
typedef struct {
  Semaphore * semaphore;
  unsigned int targetReplicas;
  unsigned int confirmedReplicas;
} DHT_PUT_SYNC_CONTEXT;

/**
 */
typedef struct {
  Semaphore * semaphore;
  unsigned int targetReplicas;
  unsigned int confirmedReplicas;
} DHT_REMOVE_SYNC_CONTEXT;

typedef struct {
  DHT_TableId table;
  cron_t timeout;  
} MigrationClosure;


typedef struct {
  /**
   * Maximum number of results for this get operation.
   */
  unsigned int maxResults;
  /**
   * Number of results currently received (size of the
   * results-array).
   */
  unsigned int count;
  /**
   * The results received so far.
   */
  DHT_DataContainer * results;
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_GET_RECORD * get_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_FindValue_Context;

typedef struct {
  /**
   * Maximum number of replicas for this put operation.
   */
  unsigned int replicationLevel;
  /**
   * Number of results currently received (size of the
   * results-array).
   */
  unsigned int count;
  /**
   * The peers that confirmed storing the record so far.
   */
  HostIdentity * peers;
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_PUT_RECORD * put_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_store_Context;

typedef struct {
  /**
   * Maximum number of replicas for this put operation.
   */
  unsigned int replicationLevel;
  /**
   * Number of results currently received (size of the
   * results-array).
   */
  unsigned int count;
  /**
   * The peers that confirmed storing the record so far.
   */
  HostIdentity * peers;
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_REMOVE_RECORD * remove_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_remove_Context;

/**
 * Cron-job that must be run before DHT can shutdown.
 */
typedef struct {
  CronJob job;
  void * arg;
} AbortEntry;


/* ***************** prototypes ******************** */

/**
 * Send an RPC 'ping' request to that node requesting DHT table
 * information.  Note that this is done asynchronously.
 * This is just the prototype, the function is below.
 */
static void request_DHT_ping(const HostIdentity * identity,
			     FindNodesContext * fnc);

static FindKNodesContext * findKNodes_start(const DHT_TableId * table,
					    const HashCode160 * key,
					    cron_t timeout,
					    unsigned int k,
					    NodeFoundCallback callback,
					    void * closure);

static int findKNodes_stop(FindKNodesContext * fnc);


/* ******************* GLOBALS ********************* */

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI = NULL;

/**
 * RPC API
 */
static RPC_ServiceAPI * rpcAPI = NULL;

/**
 * The buckets (Kademlia style routing table).
 */
static PeerBucket * buckets;

/**
 * Total number of active buckets.
 */
static unsigned int bucketCount;   

/**
 * The ID of the master table.
 */
static HashCode160 masterTableId;

/**
 * List of the tables that this peer participates in.
 */
static LocalTableData * tables;

/**
 * Number of entries in the tables array.
 */
static unsigned int tablesCount;

/**
 * Mutex to synchronize access to tables.
 */
static Mutex lock;

/**
 * Handle for the masterTable datastore that is used by this node
 * to store information about which peers participate in which
 * tables (the masterTable is another DHT, this store is just the
 * part of the masterTable that is stored at this peer).
 */
static DHT_Datastore * masterTableDatastore;

/**
 * Table of cron-jobs (and arguments) that MUST be run
 * before the DHT module can shutdown.  All of these
 * jobs are guaranteed to be triggered during the shutdown.
 */
static AbortEntry * abortTable;

static unsigned int abortTableSize;

/* *********************** CODE! ********************* */

/**
 * we need to prevent unloading of the
 * DHT module while this cron-job is pending (or
 * rather keep track of it globally to do a proper
 * shutdown on-the-spot if needed!
 */
static void addAbortJob(CronJob job,
			void * arg) {
  ENTER();
  MUTEX_LOCK(&lock);
  GROW(abortTable,
       abortTableSize,
       abortTableSize+1);
  abortTable[abortTableSize-1].job = job;
  abortTable[abortTableSize-1].arg = arg;
  MUTEX_UNLOCK(&lock);
}

/**
 * Remove a job from the abort table.
 */
static void delAbortJob(CronJob job,
			void * arg) {
  int i;

  ENTER();
  MUTEX_LOCK(&lock);
  for (i=0;i<abortTableSize;i++) {
    if ( (abortTable[i].job == job) &&
	 (abortTable[i].arg == arg) ) {
      abortTable[i] = abortTable[abortTableSize-1];
      GROW(abortTable,
	   abortTableSize,
	   abortTableSize-1);
      break;
    }
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Get the LocalTableData for the given table ID.
 * @return NULL if this peer does not participate in that table.
 */
static LocalTableData * getLocalTableData(const DHT_TableId * id) {
  int i;
  for (i=tablesCount-1;i>=0;i--)
    if (equalsHashCode160(id,
			  &tables[i].id))
      return &tables[i];
  return NULL;
}

/**
 * Find the bucket into which the given peer belongs.
 */
static PeerBucket * findBucket(const HostIdentity * peer) {
  unsigned int index;
  int i;
  int diff;

  index = sizeof(HashCode160)*8;
  for (i = sizeof(HashCode160)*8 - 1; i >= 0; --i) {
    diff = getHashCodeBit(&peer->hashPubKey, i) - getHashCodeBit(&coreAPI->myIdentity->hashPubKey, i);
    if (diff != 0) {
      index = i;
      continue;
    }
  } 
  i = bucketCount-1;
  while ( (buckets[i].bstart >= index) &&
	  (i > 0) )
    i--;
  if ( (buckets[i].bstart <  index) &&  
       (buckets[i].bend   >= index) ) {
    return &buckets[i];
  } else {    
    return NULL; /* should only happen for localhost! */
  }
}

/**
 * Update the set kbest which is supposed to accumulate the k closest
 * peers to the given key.  The size of the kbset set is given by
 * limit.
 *
 * @param newValue the new candidate for inclusion in the set
 * @param *k the current number of entries in the set
 */
static void k_best_insert(unsigned int limit,
			  int * k,
			  const HashCode160 * key,
			  HashCode160 * kbest,
			  const HashCode160 * newValue) {
  int replace;
  int m;

  if ((*k) < limit) {
    memcpy(&kbest[*k],
	   newValue,
	   sizeof(HashCode160));
    (*k)++;
  } else {
    replace = -1;
    for (m=limit-1;m>=0;m--) 
      if ( (1 == hashCodeCompareDistance(&kbest[m],
					 newValue,
					 key)) &&
	   ( (replace == -1) ||
	     (1 == hashCodeCompareDistance(&kbest[m],
					   &kbest[replace],
					   key)) ) )
	replace = m;
    if (replace != -1) {
      memcpy(&kbest[replace],
	     newValue,
	     sizeof(HashCode160));
    }
  }  
}

/**
 * Find the PeerInfo for the given peer.
 *
 * @return NULL if the peer is not in the RT.
 */
static PeerInfo * findPeerInfo(const HostIdentity * peer) {
  PeerBucket * bucket;
  PeerInfo * pos;

  bucket = findBucket(peer);
  if (bucket == NULL)
    return NULL;
  pos = vectorGetFirst(bucket->peers);
  while (pos != NULL) {
    if (equalsHashCode160(&peer->hashPubKey,
			  &pos->id.hashPubKey)) 
      return pos;    
    pos = vectorGetNext(bucket->peers);
  }
  return NULL;
}

/**
 * The given peer has responded to our find RPC callback.  Update the
 * last response time in the peer list and add the peers from results
 * to the FNC.  Trigger further create_find_nodes_rpc requests.
 *
 * @param responder the ID of the responding peer
 * @param results return values from the peer, must contain
 *   a field 'peers' which contains serialized HostIdentities
 * @param fnc the context (used to continue iterative search)
 */
static void create_find_nodes_rpc_complete_callback(const HostIdentity * responder,
						    RPC_Param * results,
						    FindNodesContext * fnc) {
  PeerInfo * info;
  char * value;
  unsigned int dataLength;
  unsigned int pos;
  EncName enc;

  ENTER();
  /* update peer list */
  MUTEX_LOCK(&lock);
  info = findPeerInfo(responder);
  if (info != NULL) 
    info->lastActivity = cronTime(NULL);   
  MUTEX_UNLOCK(&lock);

  if (OK != RPC_paramValueByName(results,
				 "peers",
				 &dataLength,
				 (void**) &value)) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Received malformed response to '%s' from peer '%s'.\n"),
	"DHT_findNode",
	&enc);
    return;
  }
  
  /* parse value, try to DHT-ping  the new peers 
     (to add it to the table; if that succeeds
     the peer will automatically trigger the ping_reply_handler
     which will in turn trigger create_find_nodes_rpc) */
  if ( (dataLength % sizeof(HostIdentity)) != 0) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Received malformed response to '%s' from peer '%s'.\n"),
	"DHT_findNode",
	&enc);
    return;
  }
  for (pos=0;pos<dataLength;pos+=sizeof(HostIdentity)) {
    HostIdentity * msg;

    msg = (HostIdentity*) &value[pos];
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"processing PeerID received from peer '%s' in response to '%s' RPC.\n",
	&enc,
	"DHT_findNode");
    IFLOG(LOG_DEBUG,
	  hash2enc(&msg->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"sending RPC '%s' to learn more about peer '%s'.\n",
	"DHT_ping",
	&enc);
#endif
    if (hostIdentityEquals(msg,
			   coreAPI->myIdentity))
      continue; /* ignore self-references! */
    request_DHT_ping(msg,
		     fnc);
  }
}

/**
 * Send a find_nodes RPC to the given peer.  Replies are
 * to be inserted into the FNC k-best table.
 */
static void create_find_nodes_rpc(const HostIdentity * peer,
				  FindNodesContext * fnc) {
  RPC_Param * param;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC '%s' to peer '%s'.\n",
      "DHT_find_nodes",
      &enc);
#endif
  ENTER();
  param = RPC_paramNew();
  MUTEX_LOCK(&fnc->lock);
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &fnc->table);
	       
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode160),
	       &fnc->key);
  GROW(fnc->rpc,
       fnc->rpcRepliesExpected,
       fnc->rpcRepliesExpected+1);
  fnc->rpc[fnc->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(peer,
			"DHT_findNode", 
			param, 
			0, 
			fnc->timeout - cronTime(NULL), 
			(RPC_Complete) &create_find_nodes_rpc_complete_callback, 
			fnc);  
  MUTEX_UNLOCK(&fnc->lock);
  RPC_paramFree(param);
}

/**
 * We received a reply from a peer that we ping'ed.  Update
 * the FNC's kbest list and the buckets accordingly.
 */
static void ping_reply_handler(const HostIdentity * responder,
			       RPC_Param * results,
			       FindNodesContext * fnc) {
  PeerBucket * bucket;
  PeerInfo * pos;
  unsigned int tableCount;
  int i;
  cron_t now;
  DHT_TableId * tables;
  unsigned int dataLength;
  char * data;
  EncName enc;

  ENTER();
  GNUNET_ASSERT(! hostIdentityEquals(responder,
				     coreAPI->myIdentity));
  /* verify and extract reply data */ 
  data = NULL;
  if (OK != RPC_paramValueByName(results,
				 "tables",
				 &dataLength,
				 (void**)&data)) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Received invalid PING-reply from peer '%s'.\n"),
	&enc);
    return;
  }
  tableCount = dataLength / sizeof(DHT_TableId);
  if (tableCount * sizeof(DHT_TableId) != dataLength) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Malformed PING-reply received from peer '%s'.\n"),
	&enc);
    return;
  }
  tables = (DHT_TableId*) data;
  
  cronTime(&now);

#if DEBUG_DHT
  IFLOG(LOG_DEBUG,
	hash2enc(&responder->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "updating routing table after learning about peer '%s' who provides %d tables.\n",	
      &enc,
      tableCount);
#endif

  /* update buckets */
  MUTEX_LOCK(&lock);
  pos = findPeerInfo(responder);
  bucket = findBucket(responder); 
  GNUNET_ASSERT(bucket != NULL);
  if (pos == NULL) {
    PeerInfo * oldest = NULL;

    pos = vectorGetFirst(bucket->peers);
    while (pos != NULL) {
      if (pos->lastActivity + DHT_INACTIVITY_DEATH < now) {
	if (oldest == NULL)
	  oldest = pos;
	else
	  if (pos->lastActivity < oldest->lastActivity)
	    oldest = pos;
      }
      if (pos->lastTableRefresh + 
	  (pos->tableCount - tableCount) * DHT_TABLE_FACTOR + DHT_HYPERACTIVE_TIME < now) {
	if (oldest == NULL)
	  oldest = pos;
	else if (pos->lastTableRefresh + 
		 (pos->tableCount - tableCount) * DHT_TABLE_FACTOR <
		 oldest->lastTableRefresh + 
		 (oldest->tableCount - tableCount) * DHT_TABLE_FACTOR)
	  oldest = pos; 
      }
      pos = vectorGetNext(bucket->peers);
    }
    pos = oldest;
  }
  if ( (vectorSize(bucket->peers) < BUCKET_TARGET_SIZE) &&
       (pos == NULL) ) {
    /* create new entry */
    pos = MALLOC(sizeof(PeerInfo));
    pos->tables = NULL;
    pos->tableCount = 0;
    pos->lastTimePingSend = cronTime(NULL);
    vectorInsertLast(bucket->peers, pos);
  }
  if (pos == NULL) {
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"routing table full, not adding peer '%s'.\n",	
	&enc);
#endif
  } else {
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"adding peer '%s' to routing table.\n",	
	&enc);
#endif
    
    pos->lastActivity = now;
    pos->lastTableRefresh = now;
    pos->id = *responder;
    GROW(pos->tables,
	 pos->tableCount,
	 tableCount);
    memcpy(pos->tables,
	   tables,
	   sizeof(DHT_TableId) * tableCount);
  }
  MUTEX_UNLOCK(&lock);  

  if (fnc == NULL)
    return;

  /* does the peer support the table in question? */
  if (! equalsHashCode160(&fnc->table,
			  &masterTableId)) {
    for (i=tableCount-1;i>=0;i--)
      if (equalsHashCode160(&fnc->table,
			    &tables[i]))
	break;
    if (i == -1)
      return; /* peer does not support table in question */
  }
  
  /* update k-best list */
  MUTEX_LOCK(&fnc->lock);
#if DEBUG_DHT
  IFLOG(LOG_DEBUG,
	hash2enc(&responder->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "peer '%s' supports table in question, considering the peer for list of %d-best matches.\n",	
      &enc,
      ALPHA);
#endif
  k_best_insert(ALPHA,
		&fnc->k,
		&fnc->key,
		fnc->matches,
		&responder->hashPubKey);

  /* trigger transitive request searching for more nodes! */
  create_find_nodes_rpc(responder,
			fnc);
  MUTEX_UNLOCK(&fnc->lock);
}

/**
 * Send an RPC 'ping' request to that node requesting DHT table
 * information.  Note that this is done asynchronously.
 */
static void request_DHT_ping(const HostIdentity * identity,
			     FindNodesContext * fnc) {  
  Vector * request_param;
  PeerInfo * pos;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&identity->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC '%s' to peer '%s'.\n",
      "DHT_ping",
      &enc);
#endif
  ENTER();
  if (hostIdentityEquals(identity,
			 coreAPI->myIdentity)) {
    BREAK();
    return; /* refuse to self-ping!... */
  }
  MUTEX_LOCK(&lock);
  /* test if this peer is already in buckets */
  pos = findPeerInfo(identity);
  if (pos != NULL)
    pos->lastTimePingSend = cronTime(NULL);
  MUTEX_UNLOCK(&lock);

  /* peer not in RPC buckets; try PINGing via RPC */
  MUTEX_LOCK(&fnc->lock);
  GROW(fnc->rpc,
       fnc->rpcRepliesExpected,
       fnc->rpcRepliesExpected+1);
  request_param = vectorNew(4);
  fnc->rpc[fnc->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(identity,
			"DHT_ping",
			request_param,
			0,
			fnc->timeout,							  
			(RPC_Complete) &ping_reply_handler, 
			fnc);
  vectorFree(request_param);
  MUTEX_UNLOCK(&fnc->lock);
}

/**
 * Find k nodes in the local buckets that are closest to the
 * given key for the given table.  Return instantly, do NOT
 * attempt to query remote peers.
 * 
 * @param hosts array with space for k hosts.
 * @return number of hosts found 
 */
static unsigned int findLocalNodes(const DHT_TableId * table,
				   const HashCode160 * key,
				   HostIdentity * hosts,
				   unsigned int k) {
  int i;
  int j;
  PeerBucket * bucket;
  PeerInfo * pos;
  unsigned int ret;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc));
  LOG(LOG_DEBUG,
      "searching local table for peers supporting table '%s'.\n",
      &enc);
#endif
  ENTER();
  ret = 0;
  /* find peers in local peer-list that participate in
     the given table */
  for (i=bucketCount-1;i>=0;i--) {
    bucket = &buckets[i];
    pos = vectorGetFirst(bucket->peers);
    while (pos != NULL) {
      for (j=pos->tableCount-1;j>=0;j--) {
	if (equalsHashCode160(&pos->tables[j],
			      table)) {
#if DEBUG_DHT
	  EncName enc;
	  
	  IFLOG(LOG_DEBUG,
		hash2enc(&pos->id.hashPubKey,
			 &enc));
	  LOG(LOG_DEBUG,
	      "local table search showed peer '%s' is supporting the table.\n",
	      &enc);
#endif
	  k_best_insert(k,
			&ret,
			key,
			(HashCode160*) hosts,
			&pos->id.hashPubKey);
	}
      }
      pos = vectorGetNext(bucket->peers);
    }
  } /* end for all buckets */
  return ret;
}
					      
/**
 * We got a reply from the DHT-get operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::data created in rpc_DHT_findValue_abort
 */
static void dht_findvalue_rpc_reply_callback(const HostIdentity * responder,
					     RPC_Param * results,
					     DHT_GET_RECORD * record) {
  DHT_DataContainer value;
  unsigned int i;
  unsigned int max;
  PeerInfo * pos;
  EncName enc;      

  ENTER();
  MUTEX_LOCK(&lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);
  MUTEX_UNLOCK(&lock);

  max = RPC_paramCount(results);
#if DEBUG_DHT
  IFLOG(LOG_DEBUG,
	hash2enc(&responder->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "peer '%s' responded to RPC '%s' with %u results.\n",
      &enc,
      "DHT_findvalue",
      max);
#endif
  for (i=0;i<max;i++) {
    value.data = NULL; 
    value.dataLength = 0;
    if (OK != RPC_paramValueByPosition(results,
				       i,
				       &value.dataLength,
				       (void**)&value.data)) {
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to '%s' from peer '%s'.\n"),
	  "DHT_findValue",
	  &enc);
      return;
    }
    MUTEX_LOCK(&record->lock);
    if (record->maxResults > 0) {
      record->maxResults--;
      record->resultsFound++; 
      if (record->callback != NULL) {
	record->callback(&value,
			 record->closure);
      }
    } 
    MUTEX_UNLOCK(&record->lock);
  }
}

/**
 * Send an (async) DHT get to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_get_rpc(const HostIdentity * peer,
			     DHT_GET_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  unsigned int maxResults;
  cron_t delta;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC '%s' to peer '%s'.\n",      
      "DHT_findvalue",
      &enc);
#endif
  delta = (record->timeout - cronTime(NULL)) / 2;
  timeout = htonll(delta);
  maxResults = htonl(record->maxResults);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode160),
	       &record->key);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  RPC_paramAdd(param,
	       "maxResults",
	       sizeof(unsigned int),
	       &maxResults);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  record->rpc[record->rpcRepliesExpected-1] 
    = rpcAPI->RPC_start(peer,
		        "DHT_findValue",
			param,
			0,
			delta,
			(RPC_Complete) &dht_findvalue_rpc_reply_callback,
			record); 
  RPC_paramFree(param);
}

/**
 * Perform an asynchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key.  The peer does not have to be part
 * of the table (if so, we will attempt to locate a peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param maxResults maximum number of results to obtain;
 *        also used to determine the level of parallelism; is that wise?
 * @param callback function to call on each result
 * @param closure extra argument to callback
 * @return handle to stop the async get
 */
static struct DHT_GET_RECORD * dht_get_async_start(const DHT_TableId * table,
						   const HashCode160 * key,
						   cron_t timeout,
						   unsigned int maxResults,
						   DHT_GET_Complete callback,
						   void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_GET_RECORD * ret;
  unsigned int count;
#if DEBUG_DHT
  EncName enc;
  EncName enc2;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(key,
		 &enc));
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc2));
  LOG(LOG_DEBUG,
      "performing '%s' operation on key '%s' and table '%s'.\n",
      "DHT_GET",
      &enc,
      &enc2);
#endif
  if (maxResults == 0)
    maxResults = 1; /* huh? */
  ret = MALLOC(sizeof(DHT_GET_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->key = *key;
  ret->table = *table;
  ret->maxResults = maxResults;
  ret->callback = callback;
  ret->closure = closure;
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->resultsFound = 0;
  ret->kfnc = NULL;
  MUTEX_LOCK(&lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    HostIdentity * hosts;
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I participate in the table '%s' for the '%s' operation.\n",      
	&enc,
	"DHT_GET");
#endif
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(HostIdentity) * maxResults);
    count = findLocalNodes(table,
			   key,
			   hosts,
			   maxResults);
    /* try adding this peer to hosts */
    k_best_insert(maxResults,
		  &count,
		  key,
		  (HashCode160*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(&lock);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++) 
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	int res;
	int j;
	DHT_DataContainer * results;

	results = MALLOC(sizeof(DHT_DataContainer) * maxResults);
	for (j=0;j<maxResults;j++) {
	  results[j].data = NULL;
	  results[j].dataLength = 0;
	}	  
	res = ltd->store->lookup(ltd->store->closure,
				 key,
				 maxResults,
				 results,
				 ltd->flags);
#if DEBUG_DHT
	IFLOG(LOG_DEBUG,
	      hash2enc(key,
		       &enc));
	LOG(LOG_DEBUG,
	    "local datastore lookup for key '%s' resulted in %d results.\n",
	    &enc,
	    res);
#endif
	if (res > 0) {
	  for (j=0;j<res;j++) {
	    if ( (equalsHashCode160(table,
				    &masterTableId)) &&
		 (results[j].dataLength % sizeof(HostIdentity) != 0) )
		BREAK(); /* assertion failed: entry in master table malformed! */
	    if (callback != NULL)
	      callback(&results[j],
		       closure);
	    FREE(results[j].data);
	  } 	  
	  ret->resultsFound += res;
	}
	FREE(results);
	break;
      }  
    
    if (maxResults > ret->resultsFound) {
      /* if less than maxResults replies were found, send 
	 dht_get_RPC to the other peers */
      for (i=0;i<count;i++) {
	if (! hostIdentityEquals(coreAPI->myIdentity,
				 &hosts[i])) {
#if DEBUG_DHT
	  IFLOG(LOG_DEBUG,
		hash2enc(&hosts[i].hashPubKey,
			 &enc));
	  LOG(LOG_DEBUG,
	      "sending RPC '%s' to peer '%s' that also participates in the table.\n",      
	      "DHT_GET",
	      &enc);
#endif
	  send_dht_get_rpc(&hosts[i],
			   ret);
	}
      }
    }
  } else {
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I do not participate in the table '%s', finding %d other nodes that do.\n",
	&enc,
	maxResults);
#endif
    /* We do not particpate in the table; hence we need to use 
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_get_rpc.
    */   
    ret->kfnc 
      = findKNodes_start(table,
			 key,
			 timeout,
			 maxResults,
			 (NodeFoundCallback) &send_dht_get_rpc,
			 ret);
  }  
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Stop async DHT-get.  Frees associated resources.
 */
static int dht_get_async_stop(struct DHT_GET_RECORD * record) {
  int i;
  int resultsFound;

  ENTER();
  if (record == NULL)
    return SYSERR;
  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++) 
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  resultsFound = record->resultsFound;
  FREE(record); 
#if DEBUG_DHT
  LOG(LOG_DEBUG,
      "'%s' operation completed with %d results.\n",
      "DHT_GET",
      resultsFound);
#endif

  if (resultsFound > 0)
    return resultsFound;
  else
    return SYSERR; /* timeout */
}

/**
 * We found a peer in the MasterTable that supports the table that
 * we're trying to find peers for.  Update FNC accordingly and
 * start transitive search for peers from that new peer.
 *
 * @param value should contain a set of HeloMessages corresponding
 *  to the identities of peers that support the table that we're 
 *  looking for; pass those Helos to the core *and* try to ping them.
 */
static void findnodes_dht_master_get_callback(const DHT_DataContainer * cont,
					      FindNodesContext * fnc) {
  unsigned int dataLength;
  HostIdentity * id;
  int i;

  ENTER();
  dataLength = cont->dataLength;

  if (dataLength % sizeof(HostIdentity) != 0) {
    LOG(LOG_DEBUG,
	"Response size was %d, expected multile of %d\n",
	dataLength, 
	sizeof(HostIdentity));
    LOG(LOG_WARNING,
	_("Invalid response to '%s'.\n"),
	"DHT_findValue");
    return;
  }
  id = (HostIdentity*) cont->data;
  for (i=dataLength/sizeof(HostIdentity)-1;i>=0;i--) {
    if (!hostIdentityEquals(&id[i],
			    coreAPI->myIdentity)) 
      request_DHT_ping(&id[i],
		       fnc);  
  }
}

/**
 * In the induced sub-structure for the given 'table', find the ALPHA
 * nodes closest to the given key.  The code first tries to find ALPHA
 * nodes in the routing table that participate in the given table.  If
 * nodes are found, the k<=ALPHA nodes closest to the key are queried
 * (using the find node RPC) to find nodes closer to the key.
 *
 * If no (zero!) participating nodes are found, the a set of introduction
 * nodes for this table is obtained from the master table (using RPC
 * get).  For the master table we try to discover peers participating
 * in the DHT using broadcasts to all connected peers (relying on
 * GNUnet core peer discovery).
 *
 * If we learn about new nodes in this step, add them to the RT table;
 * if we run out of space in the RT, send pings to oldest entry; if 
 * oldest entry did not respond to PING, replace it!
 *
 * This function is used periodially for each table that we have joined
 * to ensure that we're connected to our neighbours.
 *
 * @param table the table which the peers must participate in
 * @param key the target key to use for routing
 * @param timeout how long to tell the RPCs that we will wait
 *  (note that the caller is supposed to call findNodes_stop
 *   to finally collect the collected nodes)
 * @return context for findNodes_stop
 */
static FindNodesContext * findNodes_start(const DHT_TableId * table,
					  const HashCode160 * key,
					  cron_t timeout) {
  FindNodesContext * fnc;
  int i;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc));
  LOG(LOG_DEBUG,
      "function '%s' called to look for nodes participating in table '%s'.\n",
      __FUNCTION__,      
      &enc);
#endif
  fnc = MALLOC(sizeof(FindNodesContext));
  fnc->key = *key;
  fnc->table = *table;
  fnc->k = 0;
  fnc->matches = MALLOC(sizeof(HashCode160) * ALPHA);
  fnc->signal = SEMAPHORE_NEW(0);
  fnc->timeout = cronTime(NULL) + timeout;
  fnc->rpcRepliesExpected = 0;
  fnc->rpcRepliesReceived = 0;
  MUTEX_CREATE_RECURSIVE(&fnc->lock);

  /* find peers in local peer-list that participate in
     the given table */
  fnc->k = findLocalNodes(table,
			  key,
			  (HostIdentity*) fnc->matches,
			  ALPHA);
#if DEBUG_DHT
  LOG(LOG_DEBUG,
      "found %d participating nodes in local routing table.\n",
      fnc->k);
#endif
  for (i=0;i<fnc->k;i++) {
    /* we found k nodes participating in the table; ask these
       k nodes to search further (in this table, with this key,
       with this timeout).  Improve k-best node until timeout
       expires */
    create_find_nodes_rpc((HostIdentity*) &fnc->matches[i],
			  fnc);     		      
  }

  /* also search for more peers for this table? */
  fnc->async_handle = NULL;
  if (fnc->k < ALPHA) {
    if (equalsHashCode160(table,
			  &masterTableId)) {
#if DEBUG_DHT
      LOG(LOG_DEBUG,
	  "broadcasting RPC ping to find other peers for master table.\n");
#endif
     /* No or too few other DHT peers known, search 
	 for more by sending a PING to all connected peers 
	 that are not in the table already */
      coreAPI->forAllConnectedNodes((PerNodeCallback)&request_DHT_ping,
				    fnc);
    } else {
#if DEBUG_DHT
      IFLOG(LOG_DEBUG,
	    hash2enc(table,
		     &enc));
      LOG(LOG_DEBUG,
	  "performing RPC '%s' to find other peers participating in table '%s'.\n",
	  "DHT_findValue",
	  &enc);
#endif
      /* try finding peers responsible for this table using
	 the master table */
      fnc->async_handle
	= dht_get_async_start(&masterTableId,
			      table,
			      timeout,
			      ALPHA - fnc->k, /* level of parallelism proportional to 
						 number of peers we're looking for */
			      (DHT_GET_Complete)&findnodes_dht_master_get_callback,
			      fnc);
    }
  }
  return fnc;
}

/**
 * This stops the asynchronous findNodes process.  The search is aborted
 * and the k-best results are passed to the callback.
 * 
 * @param fnc context returned from findNodes_start
 * @param callback function to call for each peer found
 * @param closure extra argument to the callback
 * @return number of peers found, SYSERR on error
 */
static int findNodes_stop(FindNodesContext * fnc,
			  NodeFoundCallback callback,
			  void * closure) {
  int i;

  ENTER();
  /* stop async DHT get */
  if (fnc->async_handle != NULL) {
    dht_get_async_stop(fnc->async_handle);
    fnc->async_handle = NULL;
  }

  /* stop all async RPCs */
  for (i=fnc->rpcRepliesExpected-1;i>=0;i--) 
    rpcAPI->RPC_stop(fnc->rpc[i]);     
  SEMAPHORE_FREE(fnc->signal);
  MUTEX_DESTROY(&fnc->lock);

  /* Finally perform callbacks on collected k-best nodes. */
  if (callback != NULL)
    for (i=fnc->k-1;i>=0;i--)
      callback((HostIdentity*)&fnc->matches[i], closure);
  FREE(fnc->matches);
  i = fnc->k;
  FREE(fnc);
  return i;
}

/**
 * We found a peer in the MasterTable that supports the table that
 * we're trying to find peers for.  Notify the caller about this peer.
 *
 * @param value should contain a set of HeloMessages corresponding
 *  to the identities of peers that support the table that we're 
 *  looking for; pass those Helos to the core *and* to the callback
 *  as peers supporting the table.
 */
static void find_k_nodes_dht_master_get_callback(const DHT_DataContainer * cont,
						 FindKNodesContext * fnc) {
  unsigned int pos;
  unsigned int dataLength;
  char * value;
#if DEBUG_DHT
  EncName enc;
#endif

  ENTER();
  dataLength = cont->dataLength;
  value = cont->data;

  /* parse value, try to DHT-ping the new peers
     (to add it to the table; if that succeeds
     the peer will automatically trigger the ping_reply_handler
     which will in turn trigger create_find_nodes_rpc) */
  if ( (dataLength % sizeof(HostIdentity)) != 0) {
    LOG(LOG_WARNING,
	_("Malformed response to '%s' on master table.\n"),
	"DHT_findValue");
    return;
  }
  for (pos = 0;pos<dataLength;pos+=sizeof(HostIdentity)) {
    HostIdentity * msg;

    msg = (HostIdentity*) &value[pos];
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&msg->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"master table returned peer '%s' in '%s' operation.\n",
	&enc,
	"DHT_findValue");
#endif
    MUTEX_LOCK(&fnc->lock);
    if (fnc->k > 0) {
      if (fnc->callback != NULL)
	fnc->callback(msg,
		      fnc->closure);
      fnc->k--;
      fnc->found++;
    }
    MUTEX_UNLOCK(&fnc->lock);
  }
}


/**
 * In the induced sub-structure for the given 'table', find k nodes
 * close to the given key that participate in that table.  Any node in
 * the table will do, but preference is given to nodes that are close.
 * Still, the first k nodes that were found are returned (just the
 * search goes towards the key).  This function is used for lookups 
 * in tables in which this peer does not participate in.  
 *
 * If no (zero!) participating nodes are found locally, the a set of
 * introduction nodes for this table is obtained from the master table
 * (using RPC get).  For the master table we try to discover peers
 * participating in the DHT using broadcasts to all connected peers
 * (relying on GNUnet core peer discovery).
 *
 * If we learn about new nodes in this step, add them to the RT table;
 * if we run out of space in the RT, send pings to oldest entry; if 
 * oldest entry did not respond to PING, replace it!
 *
 * @param table the table which the peers must participate in,
 *        for this function, this should NEVER be the master-table.
 * @param key the target key to use for routing
 * @param timeout how long to tell the RPCs that we will wait
 *  (note that the caller is supposed to call findNodes_stop
 *   to finally collect the collected nodes)
 * @param k number of nodes to find
 * @param callback function to call for each peer found
 * @param closure extra argument to the callback
 * @return context for findKNodes_stop
 */
static FindKNodesContext * findKNodes_start(const DHT_TableId * table,
					    const HashCode160 * key,
					    cron_t timeout,
					    unsigned int k,
					    NodeFoundCallback callback,
					    void * closure) {
  FindKNodesContext * fnc;
  int i;
  int found;
  HostIdentity * matches;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  hash2enc(table,
	   &enc);
  LOG(LOG_DEBUG,
      "'%s' called to find %d nodes that participate in table '%s'.\n",
      __FUNCTION__,
      k,
      &enc);
#endif
  fnc = MALLOC(sizeof(FindKNodesContext));
  fnc->key = *key;
  fnc->table = *table;
  fnc->k = k;
  fnc->callback = callback;
  fnc->closure = closure;
  fnc->timeout = cronTime(NULL) + timeout;
  fnc->rpcRepliesExpected = 0;
  fnc->rpcRepliesReceived = 0;
  fnc->found = 0;
  MUTEX_CREATE_RECURSIVE(&fnc->lock);
  matches = MALLOC(sizeof(HostIdentity) * fnc->k);

  /* find peers in local peer-list that participate in
     the given table */
  found = findLocalNodes(table,
			 key,
			 matches,
			 k);
  if (callback != NULL)
    for (i=0;i<found;i++)     
      callback(&matches[i],
	       closure); 
  if (found == k) {
#if DEBUG_DHT
    LOG(LOG_DEBUG,
	"'%s' found %d nodes in local table, no remote requests needed.\n",
	__FUNCTION__,
	k);
#endif
    FREE(matches);
    return fnc; /* no need for anything else, we've found
		   all we care about! */
  }
  fnc->k -= found;  
  fnc->found = found;
  FREE(matches);

  /* also do 'get' to find for more peers for this table */
  fnc->async_handle = NULL;
  if (equalsHashCode160(table,
			  &masterTableId)) {
    BREAK();
    /* findKNodes_start called for masterTable.  That should not happen! */
  } else {
 #if DEBUG_DHT
    LOG(LOG_DEBUG,
	"'%s' sends request to find %d in master table.\n",
	__FUNCTION__,
	k);
#endif
    /* try finding peers responsible for this table using
       the master table */
    fnc->async_handle
      = dht_get_async_start(&masterTableId,
			    table,
			    timeout,
			    fnc->k, /* level of parallelism proportional to 
				       number of peers we're looking for */
			    (DHT_GET_Complete)&find_k_nodes_dht_master_get_callback,
			    fnc);
  }  
  return fnc;
}

/**
 * This stops the asynchronous find-k-Nodes process. 
 * The search is aborted.
 * 
 * @param fnc context returned from findNodes_start
 * @return number of peers found, SYSERR on error
 */
static int findKNodes_stop(FindKNodesContext * fnc) {
  int i;
  /* stop async DHT get */
  ENTER();
  if (fnc->async_handle != NULL) {
    dht_get_async_stop(fnc->async_handle);
    fnc->async_handle = NULL;
  }

  /* stop all async RPCs */
  for (i=fnc->rpcRepliesExpected-1;i>=0;i--) 
    rpcAPI->RPC_stop(fnc->rpc[i]);     
  MUTEX_DESTROY(&fnc->lock);

  i = fnc->found;
  FREE(fnc);
  return i;
}


/**
 * The get operation found some reply value.  Add it to the
 * context.  If we have collected the maximum number of replies,
 * signal dht_get to continue (before the timeout).
 */
static void dht_get_sync_callback(const DHT_DataContainer * value,
				  DHT_GET_SYNC_CONTEXT * context) {
  ENTER();
  MUTEX_LOCK(&lock);
  if (context->count >= context->maxResults) {
    MUTEX_UNLOCK(&lock);
    return;
  }
  if (context->results[context->count].dataLength > 0) {
    if (context->results[context->count].dataLength > 
	value->dataLength)
      context->results[context->count].dataLength = value->dataLength;
    memcpy(context->results[context->count].data,
	   value->data,
	   context->results[context->count].dataLength);
  } else {
    context->results[context->count].dataLength = value->dataLength;
    context->results[context->count].data = MALLOC(value->dataLength);
    memcpy(context->results[context->count].data,
	   value->data,
	   value->dataLength);
  }
  context->count++;
  if (context->count == context->maxResults)
    SEMAPHORE_UP(context->semaphore); /* done early! */
  MUTEX_UNLOCK(&lock);
}


/**
 * Perform a synchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key; store the result in 'result'.  If
 * result->dataLength == 0 the result size is unlimited and
 * result->data needs to be allocated; otherwise result->data refers
 * to dataLength bytes and the result is to be stored at that
 * location; dataLength is to be set to the actual size of the
 * result.
 *
 * The peer does not have to be part of the table!  This method
 * must not be called from within a cron-job!
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param maxResults maximum number of results to obtain, size of the results array
 * @param results where to store the results (on success)
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
static int dht_get(const DHT_TableId * table,
		   const HashCode160 * key,
		   cron_t timeout,
		   unsigned int maxResults,
		   DHT_DataContainer * results) {
  DHT_GET_RECORD * rec;
  DHT_GET_SYNC_CONTEXT context;
  int ret;

  ENTER();
  context.results = results;
  context.maxResults = maxResults;
  context.count = 0;
  context.semaphore = SEMAPHORE_NEW(0);
  rec = dht_get_async_start(table,
			    key,
			    timeout,
			    maxResults,
			    (DHT_GET_Complete) &dht_get_sync_callback,
			    &context);
  addCronJob((CronJob) &semaphore_up_,
	     timeout,
	     0,
	     &context.semaphore);
  SEMAPHORE_DOWN(context.semaphore);
  ret = dht_get_async_stop(rec);
  suspendCron();
  delCronJob((CronJob) &semaphore_up_,
	     0,
	     &context.semaphore);
  resumeCron();
  SEMAPHORE_FREE(context.semaphore);
  return ret;
}
					      
/**
 * We got a reply from the DHT_store operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::peer created in rpc_DHT_store_abort
 */
static void dht_put_rpc_reply_callback(const HostIdentity * responder,
				       RPC_Param * results,
				       DHT_PUT_RECORD * record) {
  HostIdentity * peer;
  unsigned int dataLength;
  PeerInfo * pos;
  unsigned int i;
  unsigned int max;
  unsigned int j;

  ENTER();
  MUTEX_LOCK(&record->lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);
  
  max = RPC_paramCount(results);
  for (i=0;i<max;i++) {
    if ( (OK != RPC_paramValueByPosition(results,
					 i,
					 &dataLength,
					 (void**)&peer)) ||
	 (dataLength != sizeof(HostIdentity)) ) {
      EncName enc;
      
      MUTEX_UNLOCK(&record->lock);
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to '%s' from '%s'\n"),
	  "DHT_put",
	  &enc);
      return;
    }
    /* ensure we don't count duplicates! */
    for (j=0;j<record->confirmedReplicas;j++)
      if (hostIdentityEquals(peer,
			     &record->replicas[j])) {
	peer = NULL;
	break;
      }
    if (peer != NULL) {
      GROW(record->replicas,
	   record->confirmedReplicas,
	   record->confirmedReplicas+1);
      record->replicas[record->confirmedReplicas-1] = *peer;
      if (record->callback != NULL)
	record->callback(peer,
			 record->closure);
    }
  }
  MUTEX_UNLOCK(&record->lock);
}

/**
 * Send an (async) DHT put to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_put_rpc(const HostIdentity * peer,
			     DHT_PUT_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  cron_t delta;

  ENTER();
  delta = (record->timeout - cronTime(NULL)) / 2;
  timeout = htonll(delta);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode160),
	       &record->key);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  RPC_paramAdd(param,
	       "value",
	       record->value.dataLength,
	       record->value.data);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  record->rpc[record->rpcRepliesExpected-1] 
    = rpcAPI->RPC_start(peer,
		        "DHT_store",
			param,
			0,
			delta,
			(RPC_Complete) &dht_put_rpc_reply_callback,
			record); 
  RPC_paramFree(param);
}


/**
 * Perform an asynchronous PUT operation on the DHT identified by
 * 'table' storing a binding of 'key' to 'value'.  The peer does not
 * have to be part of the table (if so, we will attempt to locate a
 * peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param replicationLevel how many copies should we make?
 * @param callback function to call on successful completion
 * @param closure extra argument to callback
 * @return handle to stop the async put
 */
static struct DHT_PUT_RECORD * dht_put_async_start(const DHT_TableId * table,
						   const HashCode160 * key,
						   cron_t timeout,
						   const DHT_DataContainer * value,
						   unsigned int replicationLevel,
						   DHT_PUT_Complete callback,
						   void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_PUT_RECORD * ret;
  unsigned int count;
#if DEBUG_DHT
  EncName enc;
  EncName enc2;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(key,
		 &enc));
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc2));
  LOG(LOG_DEBUG,
      "performing '%s' operation on key '%s' and table '%s'.\n",      
      "DHT_PUT",
      &enc,
      &enc2);
#endif
  if (replicationLevel == 0)
    replicationLevel = 1;
  ret = MALLOC(sizeof(DHT_PUT_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->key = *key;
  ret->table = *table;
  ret->callback = callback;
  ret->closure = closure;
  ret->replicationLevel = replicationLevel;
  ret->value = *value;
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->confirmedReplicas = 0;
  ret->replicas = NULL;
  ret->kfnc = NULL;
  MUTEX_LOCK(&lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    HostIdentity * hosts;
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I participate in the table '%s' for the '%s' operation.\n",      
	&enc,
	"DHT_PUT");
#endif
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(HostIdentity) * replicationLevel);
    count = findLocalNodes(table,
			   key,
			   hosts,
			   replicationLevel);
    /* try adding this peer to hosts */
    k_best_insert(replicationLevel,
		  &count,
		  key,
		  (HashCode160*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(&lock);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++) {
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	if (OK == ltd->store->store(ltd->store->closure,
				    key,
				    value,
				    ltd->flags)) {
	  if (callback != NULL)
	    callback(coreAPI->myIdentity,
		     closure); 
	  ret->confirmedReplicas++;
	  if (replicationLevel == 1) {
	    /* that's it then */
	    MUTEX_UNLOCK(&lock);
	    return ret;
	  }
	} else {
	  /* warning?  How to communicate errors? */
	}
	break;
      }  
    }

    if (ret->replicationLevel > 0) {
      /* send dht_put_RPC to the other peers */
      for (i=0;i<count;i++) 
	if (! hostIdentityEquals(coreAPI->myIdentity,
				 &hosts[i]))
	  send_dht_put_rpc(&hosts[i],
			   ret);
    }
  } else {
    /* We do not particpate in the table; hence we need to use 
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_put_rpc.
    */   
    ret->kfnc 
      = findKNodes_start(table,
			 key,
			 timeout,
			 replicationLevel,
			 (NodeFoundCallback) &send_dht_put_rpc,
			 ret);
  }  
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Stop async DHT-put.  Frees associated resources.
 */
static int dht_put_async_stop(struct DHT_PUT_RECORD * record) {
  int i;

  ENTER();
  if (record == NULL)
    return SYSERR;

  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++) 
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  i = record->confirmedReplicas;
  GROW(record->replicas,
       record->confirmedReplicas,
       0);
  FREE(record); 
  if (i > 0)
    return OK;
  else
    return SYSERR;
}

/**
 * The put operation found a peer willing to store. 
 * If we have collected the maximum number of replicas,
 * signal dht_get to continue (before the timeout).
 */
static void dht_put_sync_callback(const DHT_DataContainer * value,
				  DHT_PUT_SYNC_CONTEXT * context) {
  ENTER();
  MUTEX_LOCK(&lock);
  if (context->confirmedReplicas >= context->targetReplicas) {
    MUTEX_UNLOCK(&lock);
    return;
  }
  context->confirmedReplicas++;
  if (context->confirmedReplicas == context->targetReplicas)
    SEMAPHORE_UP(context->semaphore); /* done early! */
  MUTEX_UNLOCK(&lock);
}

/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to store
 * @param flags bitmask
 * @return OK on success, SYSERR on error (or timeout)
 */
static int dht_put(const DHT_TableId * table,
		   const HashCode160 * key,
		   cron_t timeout,
		   const DHT_DataContainer * value,
		   int flags) {
  DHT_PUT_SYNC_CONTEXT context;
  DHT_PUT_RECORD * rec;
  int ret;

  ENTER();
  context.confirmedReplicas = 0;
  context.targetReplicas = flags & DHT_FLAGS_TABLE_REPLICATION_MASK;
  context.semaphore = SEMAPHORE_NEW(0);
  rec = dht_put_async_start(table,
			    key,
			    timeout,
			    value,
			    context.targetReplicas,
			    (DHT_PUT_Complete) &dht_put_sync_callback,
			    &context);
  addCronJob((CronJob) &semaphore_up_,
	     timeout,
	     0,
	     &context.semaphore);
  SEMAPHORE_DOWN(context.semaphore);
  ret = dht_put_async_stop(rec);
  suspendCron();
  delCronJob((CronJob) &semaphore_up_,
	     0,
	     &context.semaphore);
  resumeCron();
  SEMAPHORE_FREE(context.semaphore);
  return ret;
}
				      
/**
 * We got a reply from the DHT_remove operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::peer created in rpc_DHT_store_abort
 */
static void dht_remove_rpc_reply_callback(const HostIdentity * responder,
					  RPC_Param * results,
					  DHT_REMOVE_RECORD * record) {
  HostIdentity * peer;
  unsigned int dataLength;
  PeerInfo * pos;
  unsigned int i;
  unsigned int max;
  unsigned int j;

  ENTER();
  MUTEX_LOCK(&record->lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);

  max = RPC_paramCount(results);
  for (i=0;i<max;i++) {
    if ( (OK != RPC_paramValueByPosition(results,
					 i,
					 &dataLength,
					 (void**)&peer)) ||
	 (dataLength != sizeof(HostIdentity)) ) {
      EncName enc;
      
      MUTEX_UNLOCK(&record->lock);
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to '%s' from '%s'\n"),
	  "DHT_remove",
	  &enc);
      return;
    }
    record->confirmedReplicas++;
    if (record->callback != NULL)
      record->callback(peer,
		       record->closure);       
  }
  MUTEX_UNLOCK(&record->lock);
}

/**
 * Send an (async) DHT remove to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_remove_rpc(const HostIdentity * peer,
				DHT_REMOVE_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  cron_t delta;

  ENTER();
  delta = (record->timeout - cronTime(NULL)) / 2;
  timeout = htonll(delta);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode160),
	       &record->key);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  if (record->value.dataLength > 0)
    RPC_paramAdd(param,
		 "value",
		 record->value.dataLength,
		 record->value.data);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  record->rpc[record->rpcRepliesExpected-1] 
    = rpcAPI->RPC_start(peer,
		        "DHT_remove",
			param,
			0,
			delta,
			(RPC_Complete) &dht_remove_rpc_reply_callback,
			record); 
  RPC_paramFree(param);
}

/**
 * Perform an asynchronous REMOVE operation on the DHT identified by
 * 'table' removing the binding of 'key' to 'value'.  The peer does not
 * have to be part of the table (if so, we will attempt to locate a
 * peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param replicationLevel how many copies should we make?
 * @param callback function to call on successful completion
 * @param closure extra argument to callback
 * @return handle to stop the async remove
 */
static struct DHT_REMOVE_RECORD * dht_remove_async_start(const DHT_TableId * table,
							 const HashCode160 * key,
							 cron_t timeout,
							 const DHT_DataContainer * value,
							 unsigned int replicationLevel,
							 DHT_REMOVE_Complete callback,
							 void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_REMOVE_RECORD * ret;
  unsigned int count;

  ENTER();
  ret = MALLOC(sizeof(DHT_REMOVE_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->key = *key;
  ret->table = *table;
  ret->callback = callback;
  ret->closure = closure;
  ret->replicationLevel = replicationLevel;
  if (value == NULL) {
    ret->value.dataLength = 0;
    ret->value.data = NULL;
  } else
    ret->value = *value;
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->confirmedReplicas = 0;
  ret->kfnc = NULL;
  MUTEX_LOCK(&lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    HostIdentity * hosts;
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(HostIdentity) * replicationLevel);
    count = findLocalNodes(table,
			   key,
			   hosts,
			   replicationLevel);
    /* try adding this peer to hosts */
    k_best_insert(replicationLevel,
		  &count,
		  key,
		  (HashCode160*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(&lock);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++) {
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	if (OK == ltd->store->remove(ltd->store->closure,
				     key,
				     value,
				     ltd->flags)) {
	  if (callback != NULL)
	    callback(coreAPI->myIdentity,
		     closure); 
	  ret->confirmedReplicas++;
	  if (replicationLevel == 1) {
	    /* that's it then */
	    MUTEX_UNLOCK(&lock);
	    return ret;
	  }
	} else {
	  /* warning?  How to communicate errors? */
	}
	break;
      }  
    }

    if (ret->replicationLevel > 0) {
      /* send dht_remove_RPC to the other peers */
      for (i=0;i<count;i++) 
	if (! hostIdentityEquals(coreAPI->myIdentity,
				 &hosts[i]))
	  send_dht_remove_rpc(&hosts[i],
			   ret);
    }
  } else {
    /* We do not particpate in the table; hence we need to use 
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_remove_rpc.
    */   
    ret->kfnc 
      = findKNodes_start(table,
			 key,
			 timeout,
			 replicationLevel,
			 (NodeFoundCallback) &send_dht_remove_rpc,
			 ret);
  }  
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Stop async DHT-remove.  Frees associated resources.
 */
static int dht_remove_async_stop(struct DHT_REMOVE_RECORD * record) {
  int i;

  ENTER();
  if (record == NULL)
    return SYSERR;

  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++) 
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  i = record->confirmedReplicas;
  FREE(record); 
  if (i > 0)
    return OK;
  else
    return SYSERR;
}

/**
 * The remove operation found a peer containing the value.
 * If we have removed the maximum number of replicas,
 * signal dht_remove to continue (before the timeout).
 */
static void dht_remove_sync_callback(const DHT_DataContainer * value,
				     DHT_REMOVE_SYNC_CONTEXT * context) {
  ENTER();
  MUTEX_LOCK(&lock);
  if (context->confirmedReplicas >= context->targetReplicas) {
    MUTEX_UNLOCK(&lock);
    return;
  }
  context->confirmedReplicas++;
  if (context->confirmedReplicas == context->targetReplicas)
    SEMAPHORE_UP(context->semaphore); /* done early! */
  MUTEX_UNLOCK(&lock);
}

/**
 * Perform a synchronous remove operation.  The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to remove; NULL for all values matching the key
 * @param flags bitmask
 * @return OK on success, SYSERR on error (or timeout)
 */
static int dht_remove(const DHT_TableId * table,
		      const HashCode160 * key,
		      cron_t timeout,
		      const DHT_DataContainer * value,
		      int flags) {
  DHT_REMOVE_SYNC_CONTEXT context;
  DHT_REMOVE_RECORD * rec;
  int ret;

  ENTER();
  context.confirmedReplicas = 0;
  context.targetReplicas = flags & DHT_FLAGS_TABLE_REPLICATION_MASK;
  context.semaphore = SEMAPHORE_NEW(0);
  rec = dht_remove_async_start(table,
			       key,
			       timeout,
			       value,
			       context.targetReplicas,
			       (DHT_REMOVE_Complete) &dht_remove_sync_callback,
			       &context);
  addCronJob((CronJob) &semaphore_up_,
	     timeout,
	     0,
	     &context.semaphore);
  SEMAPHORE_DOWN(context.semaphore);
  ret = dht_remove_async_stop(rec);
  suspendCron();
  delCronJob((CronJob) &semaphore_up_,
	     0,
	     &context.semaphore);
  resumeCron();
  SEMAPHORE_FREE(context.semaphore);
  return ret;
}


/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout NOT USED.  Remove?
 * @param flags options for the table (i.e. replication)
 * @return SYSERR on error, OK on success
 */
static int dht_join(DHT_Datastore * datastore,
		    const DHT_TableId * table,
		    cron_t timeout,
		    int flags) {
  int i;

  ENTER();
  MUTEX_LOCK(&lock);
  for (i=0;i<tablesCount;i++) {
    if (equalsDHT_TableId(&tables[i].id, table)) {
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
  }
  GROW(tables,
       tablesCount,
       tablesCount+1);
  tables[tablesCount-1].id = *table;
  tables[tablesCount-1].store = datastore;
  tables[tablesCount-1].flags = flags;
  MUTEX_UNLOCK(&lock);
  return OK;
}


/**
 * Callback function to migrate content to other peers.
 */
static int dht_migrate(const HashCode160 * key,
		       const DHT_DataContainer * value,
		       int flags,
		       MigrationClosure * cls) {
  cron_t now;

  ENTER();
  cronTime(&now);
  if (now >= cls->timeout) {
    LOG(LOG_DEBUG,
	"Aborting DHT migration due to timeout.\n");
    return SYSERR; /* abort: timeout */
  } 
  /* OPTIMIZE-ME: we may want to do the migration using
     async RPCs; but we need to be careful not to
     flood the network too badly at that point.  Tricky! */
  if (OK != dht_put(&cls->table,
		    key,
		    cls->timeout - now,
		    value,
		    flags))
    LOG(LOG_DEBUG,
	"Failed to migrate DHT content.\n");
  return OK;  
}

  
/**
 * Leave a table (stop storing data for the table).  Leave
 * fails if the node is not joint with the table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to 
 *   the leave request (has no impact on success or failure);
 *   but only timeout time is available for migrating data, so
 *   pick this value with caution.
 * @param flags 
 * @return SYSERR on error, OK on success
 */
static int dht_leave(const DHT_TableId * table,
		     cron_t timeout,
		     int flags) {
  int i;
  int idx;
  LocalTableData old;
  MigrationClosure cls;

  ENTER();
  MUTEX_LOCK(&lock);
  idx = -1;
  for (i=0;i<tablesCount;i++) {
    if (equalsDHT_TableId(&tables[i].id, table)) {
      idx = i;
      break;
    }
  }
  if (idx == -1) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  old = tables[i];
  tables[i] = tables[tablesCount-1];
  GROW(tables,
       tablesCount,
       tablesCount-1);
  MUTEX_UNLOCK(&lock);

  /* migrate content if applicable! */
  if ((flags & DHT_FLAGS_TABLE_MIGRATION_FLAG) > 0) {
    cls.table = *table;
    cls.timeout = cronTime(NULL) + timeout;
    old.store->iterate(old.store->closure,
		       0,
		       (DHT_DataProcessor) &dht_migrate,
		       &cls);
  }
  if (! equalsHashCode160(&masterTableId,
			  table)) {
    /* OPTIMIZE-ME: also issue dht_remove to remove this peer
       from the master node! (timeout used here!);
       use async operation to do it concurrently with
       dht_migrate! */
  }
  return OK;
}

/**
 * We received a PING from another DHT.  The appropriate response
 * is to send a list of the tables that this peer participates in.
 *
 * @param arguments do we need any?
 * @param results::tables the tables we participate in (DHT_TableIds)
 * @param helos::HELOs for this peer (optional, not implemented)
 */
static void rpc_DHT_ping(const HostIdentity * sender,
			 RPC_Param * arguments,
			 RPC_Param * results) {
  DHT_TableId * tabs;
  int i;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&sender->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "Received RPC '%s' from peer '%s'.\n",
      "DHT_ping",
      &enc);
#endif
  ENTER();
  MUTEX_LOCK(&lock);
  tabs = MALLOC(sizeof(DHT_TableId) * tablesCount);
  for (i=0;i<tablesCount;i++)
    tabs[i] = tables[i].id;
  MUTEX_UNLOCK(&lock);
  RPC_paramAdd(results,
	       "tables",
	       sizeof(DHT_TableId) * tablesCount,
	       tabs);
  FREE(tabs);
  /* OPTIMIZE-ME: optionally add helos here */
}

/**
 * Find nodes that we know of that participate in the given
 * table and that are close to the given key.
 *
 * @param arguments::key the key to route towards
 * @param arguments::table the id of the table
 * @param results::peers list of peers found to participate in the given table with ID close to key;
 *    peers consists of HostIdentities one after the other. See 
 *    create_find_nodes_rpc_complete_callback for the parser of the reply.
 * @param results::list of tables that this peer participates in (optional,
 *    not implemented)
 */
static void rpc_DHT_findNode(const HostIdentity * sender,
			     RPC_Param * arguments,
			     RPC_Param * results) {
  HashCode160 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  unsigned int count;
  unsigned int k;
  HostIdentity * peers;

  ENTER();
  key = NULL;
  table = NULL;
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode160)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ) {    
    LOG(LOG_WARNING,
	_("Received invalid RPC '%s'.\n"),
	"DHT_findNode");
    return;
  }
  k = ALPHA; /* optionally obtain k from arguments??? */
  peers = MALLOC(sizeof(HostIdentity) * k);
  count = findLocalNodes(table,
			 key,
			 peers,
			 k);
  RPC_paramAdd(results,
	       "peers",
	       count * sizeof(HostIdentity),
	       peers);
  FREE(peers);  
  /* OPTIMIZE-ME: optionally add table list here */
}

/**
 * Cron-job to abort an rpc_DHT_findValue operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_findvalue_rpc_reply_callback.
 */
static void rpc_DHT_findValue_abort(RPC_DHT_FindValue_Context * fw) {
  RPC_Param * results;
  int errorCode;
  int i;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_findValue_abort, 
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_get_async_stop(fw->get_record); 
  fw->get_record = NULL;

  /* build RPC reply, call RPC callback */ 
  results = RPC_paramNew();
  if (fw->count > 0) {
    errorCode = RPC_ERROR_OK;
    for (i=fw->count-1;i>=0;i--) 
      RPC_paramAdd(results,
		   "data",
		   fw->results[i].dataLength,
		   fw->results[i].data);
  } else {
    errorCode = RPC_ERROR_TIMEOUT;
  }
  if (fw->callback != NULL)
    fw->callback(results,
		 errorCode,
		 fw->rpc_context);
  RPC_paramFree(results);
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of replies for this
 * find-value operation.  If the maximum number of results has
 * been accumulated this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static void rpc_dht_findValue_callback(const DHT_DataContainer * value,
				       RPC_DHT_FindValue_Context * fw) {
  int stop;

  ENTER();
  MUTEX_LOCK(&fw->lock);
  GROW(fw->results,
       fw->count,
       fw->count+1);
  fw->results[fw->count-1].dataLength = value->dataLength;
  fw->results[fw->count-1].data = MALLOC(value->dataLength);
  memcpy(fw->results[fw->count-1].data,
	 value->data,
	 value->dataLength);
  stop = fw->count == fw->maxResults;
  MUTEX_UNLOCK(&fw->lock);
  if (stop) {
    /* don't wait for timeout, run now! */
    advanceCronJob((CronJob) &rpc_DHT_findValue_abort,
		   0,
		   fw);
  }
}

/**
 * Asynchronous RPC function called for 'findValue' RPC.
 *
 * @param arguments::key the key to search for
 * @param arguments::table the table to search in
 * @param arguments::timeout how long to wait at most
 * @param arguments::maxResults how many replies to send at most
 * @param callback function to call with results when done
 * @param context additional argument to callback
 * @param results::data the result of the get operation
 * @param results::tables optional argument describing the tables
 *   that this peer participates in (not implemented)
 */
static void rpc_DHT_findValue(const HostIdentity * sender,
			      RPC_Param * arguments,
			      Async_RPC_Complete_Callback callback,
			      struct CallInstance * rpc_context) {
  HashCode160 * key;
  DHT_TableId * table;
  unsigned long long * timeout;
  unsigned int * maxResults;
  unsigned int dataLength;
  RPC_DHT_FindValue_Context * fw_context;
  
  ENTER();
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode160)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ||
       (OK != RPC_paramValueByName(arguments,
				   "maxResults",
				   &dataLength,
				   (void**) &maxResults)) ||
       (dataLength != sizeof(unsigned int)) ) {    
    LOG(LOG_WARNING,
	_("Received invalid RPC '%s'.\n"),
	"DHT_findValue");
    return;
  }   

  fw_context 
    = MALLOC(sizeof(RPC_DHT_FindValue_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  fw_context->maxResults
    = ntohl(*maxResults);
  fw_context->count
    = 0;
  fw_context->done
    = NO;
  fw_context->results 
    = NULL;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->get_record 
    = dht_get_async_start(table,
			  key,
			  ntohll(*timeout),
			  ntohl(*maxResults),
			  (DHT_GET_Complete) &rpc_dht_findValue_callback,
			  fw_context);
  addAbortJob((CronJob)&rpc_DHT_findValue_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_findValue_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
}

/**
 * Cron-job to abort an rpc_DHT_store operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_put_rpc_reply_callback.
 */
static void rpc_DHT_store_abort(RPC_DHT_store_Context * fw) {
  RPC_Param * results;
  int errorCode;
  int i;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_store_abort,
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_put_async_stop(fw->put_record);
  fw->put_record = NULL;

  /* build RPC reply, call RPC callback */ 
  results = RPC_paramNew();
  if (fw->count > 0) {
    errorCode = RPC_ERROR_OK;
    for (i=fw->count-1;i>=0;i--) 
      RPC_paramAdd(results,
		   "peer",
		   sizeof(HostIdentity),
		   &fw->peers[i]);
  } else {
    errorCode = RPC_ERROR_TIMEOUT;
  }
  if (fw->callback != NULL)
    fw->callback(results,
		 errorCode,
		 fw->rpc_context);
  RPC_paramFree(results);
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of replies for this
 * store operation.  If the maximum number of peers has stored
 * the value, this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static void rpc_dht_store_callback(const HostIdentity * store,
				   RPC_DHT_store_Context * fw) {
  int stop;

  MUTEX_LOCK(&fw->lock);
  GROW(fw->peers,
       fw->count,
       fw->count+1);
  fw->peers[fw->count-1] = *store;
  stop = fw->count == fw->replicationLevel;
  MUTEX_UNLOCK(&fw->lock);
  if (stop) {
    /* don't wait for timeout, run now! */
    advanceCronJob((CronJob) &rpc_DHT_store_abort,
		   0,
		   fw);
  }
}

static void rpc_DHT_store(const HostIdentity * sender,
			  RPC_Param * arguments,
			  Async_RPC_Complete_Callback callback,
			  struct CallInstance * rpc_context) {
  HashCode160 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  DHT_DataContainer value;
  unsigned long long * timeout;
  RPC_DHT_store_Context * fw_context;
  LocalTableData * ltd;
  
  ENTER();
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode160)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ||
       (OK != RPC_paramValueByName(arguments,
				   "value",
				   &value.dataLength,
				   (void**) &value.data)) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC '%s'.\n"),
	"DHT_store");
    return;
  }   

  fw_context 
    = MALLOC(sizeof(RPC_DHT_store_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  MUTEX_LOCK(&lock);
  ltd = getLocalTableData(table);
  if (ltd == NULL) {    
    LOG(LOG_WARNING,
	"RPC for DHT_store received for table that we do not participate in!\n");
    fw_context->replicationLevel = 1; /* or 0?  Well, for now we'll just try to 
					 find another peer anyway */
  } else {
    fw_context->replicationLevel = ltd->flags & DHT_FLAGS_TABLE_REPLICATION_MASK;
  }
  MUTEX_UNLOCK(&lock);
  fw_context->count
    = 0;
  fw_context->done
    = NO;
  fw_context->peers
    = NULL;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->put_record 
    = dht_put_async_start(table,
			  key,
			  ntohll(*timeout),
			  &value,
			  fw_context->replicationLevel,
			  (DHT_PUT_Complete) &rpc_dht_store_callback,
			  fw_context);
  addAbortJob((CronJob)&rpc_DHT_store_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_store_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
}

/**
 * Cron-job to abort an rpc_DHT_remove operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_remove_rpc_reply_callback.
 */
static void rpc_DHT_remove_abort(RPC_DHT_remove_Context * fw) {
  RPC_Param * results;
  int errorCode;
  int i;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_remove_abort,
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_remove_async_stop(fw->remove_record);
  fw->remove_record = NULL;

  /* build RPC reply, call RPC callback */ 
  results = RPC_paramNew();
  if (fw->count > 0) {
    errorCode = RPC_ERROR_OK;
    for (i=fw->count-1;i>=0;i--) 
      RPC_paramAdd(results,
		   "peer",
		   sizeof(HostIdentity),
		   &fw->peers[i]);
  } else {
    errorCode = RPC_ERROR_TIMEOUT;
  }
  if (fw->callback != NULL)
    fw->callback(results,
		 errorCode,
		 fw->rpc_context);
  RPC_paramFree(results);
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of peers that have removed
 * this find-value operation.  If the number of peers reaches the
 * number of replicas this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static void rpc_dht_remove_callback(const HostIdentity * store,
				    RPC_DHT_remove_Context * fw) {
  int stop;
  
  ENTER();
  MUTEX_LOCK(&fw->lock);
  GROW(fw->peers,
       fw->count,
       fw->count+1);
  fw->peers[fw->count-1] = *store;
  stop = fw->count == fw->replicationLevel;
  MUTEX_UNLOCK(&fw->lock);
  if (stop) {
    /* don't wait for timeout, run now! */
    advanceCronJob((CronJob) &rpc_DHT_remove_abort,
		   0,
		   fw);
  }
}

/**
 * ASYNC RPC call for removing entries from the DHT.
 *
 * @param arguments::key the key to remove
 * @param arguments::table the table to remove data from
 * @param arguments::timeout how long to wait at most
 * @param arguments::value optional argument specifying which
 *    value to remove from the given table under the given key
 * @param callback RPC service function to call once we are done
 * @param rpc_context extra argument to callback
 */
static void rpc_DHT_remove(const HostIdentity * sender,
			   RPC_Param * arguments,
			   Async_RPC_Complete_Callback callback,
			   struct CallInstance * rpc_context) {
  HashCode160 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  DHT_DataContainer value;
  unsigned long long * timeout;
  RPC_DHT_remove_Context * fw_context;
  LocalTableData * ltd;
  
  ENTER();
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode160)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC '%s'.\n"),
	"DHT_store");
    return;
  }   
    
  if (OK != RPC_paramValueByName(arguments,
				 "value",
				 &value.dataLength,
				 (void**) &value.data))
    value.dataLength = 0;

  fw_context 
    = MALLOC(sizeof(RPC_DHT_remove_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  MUTEX_LOCK(&lock);
  ltd = getLocalTableData(table);
  if (ltd == NULL) {    
    LOG(LOG_DEBUG,
	"RPC for DHT_removed received for table that we do not participate in!\n");
    fw_context->replicationLevel = 1; /* or 0?  Well, for now we'll just try to 
					 find another peer anyway */
  } else {
    fw_context->replicationLevel = ltd->flags & DHT_FLAGS_TABLE_REPLICATION_MASK;
  }
  MUTEX_UNLOCK(&lock);
  fw_context->count
    = 0;
  fw_context->done
    = NO;
  fw_context->peers
    = NULL;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->remove_record 
    = dht_remove_async_start(table,
			     key,
			     ntohll(*timeout),
			     (value.dataLength==0) ? NULL : &value,
			     fw_context->replicationLevel,
			     (DHT_REMOVE_Complete) &rpc_dht_remove_callback,
			     fw_context);
  addAbortJob((CronJob)&rpc_DHT_remove_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_remove_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
}

/**
 * Cron-job to maintain DHT invariants.  The responsibility of
 * this job is to maintain the routing table (by finding peers
 * if necessary).
 *
 * During shutdown the cron-job is called at a particular point
 * to free the associated resources.  The point is chosen such
 * that the cron-job will not allocate new resources (since all
 * tables and all buckets are empty at that point).
 */ 
static void dhtMaintainJob(void * unused) {
  static struct RPC_Record ** pingRecords = NULL;
  static unsigned int pingRecordsSize = 0;
  static struct DHT_PUT_RECORD ** putRecords = 0;
  static unsigned int putRecordsSize = 0;
  static FindNodesContext ** findRecords = NULL;
  static unsigned int findRecordsSize = 0;

  int i;
  Vector * request_param;
  PeerBucket * bucket;
  PeerInfo * pos;
  cron_t now;
  DHT_DataContainer value;

  ENTER();
  MUTEX_LOCK(&lock);
  /* first, free resources from ASYNC calls started last time */
#if DEBUG_DHT
  LOG(LOG_CRON,
      "'%s' stops async requests from last cron round.\n",
      __FUNCTION__);
#endif
  for (i=0;i<putRecordsSize;i++)
    dht_put_async_stop(putRecords[i]);
  GROW(putRecords, 
       putRecordsSize,
       0);
  for (i=0;i<findRecordsSize;i++)
    findNodes_stop(findRecords[i],
		   NULL,
		   NULL);
  GROW(findRecords,
       findRecordsSize,
       0);
  for (i=0;i<pingRecordsSize;i++)
    rpcAPI->RPC_stop(pingRecords[i]);
  GROW(pingRecords,
       pingRecordsSize,
       0);

  /* now trigger next round of ASYNC calls */

  cronTime(&now);
  /* for all of our tables, do a PUT on the master table */
  /* OPTIMIZE-ME: limit how often we do this! (every 15s is
     definitively too excessive!)*/
  request_param = vectorNew(4);
  value.dataLength = sizeof(HostIdentity);
  value.data = coreAPI->myIdentity;
#if DEBUG_DHT
  LOG(LOG_CRON,
      "'%s' issues DHT_PUTs to advertise tables this peer participates in.\n",
      __FUNCTION__);
#endif
  for (i=0;i<tablesCount;i++) {
    if (! equalsHashCode160(&tables[i].id, 
			    &masterTableId)) {
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize+1);
      putRecords[putRecordsSize-1] 
	= dht_put_async_start(&masterTableId,
			      &tables[i].id,
			      DHT_MAINTAIN_FREQUENCY,
			      &value,
			      ALPHA,
			      NULL,
			      NULL);
    }
  }
  vectorFree(request_param);

  /*
    for each table that we have joined gather OUR neighbours
  */
#if DEBUG_DHT
  LOG(LOG_CRON,
      "'%s' issues findNodes for each table that we participate in.\n",
      __FUNCTION__);
#endif
  for (i=0;i<tablesCount;i++) {
    GROW(findRecords,
	 findRecordsSize,
	 findRecordsSize+1);
    findRecords[findRecordsSize-1] 
      = findNodes_start(&tables[i].id,
			&coreAPI->myIdentity->hashPubKey,
			DHT_MAINTAIN_FREQUENCY); /* ?? */
  }

  /* 
     for all peers in RT:
     a) if lastTableRefresh is very old, send ping
     b) if lastActivity is very very old, drop
  */
#if DEBUG_DHT
  LOG(LOG_CRON,
      "'%s' issues put to advertise tables that we participate in.\n",
      __FUNCTION__);
#endif
  request_param = vectorNew(4);
  for (i=bucketCount-1;i>=0;i--) {
    bucket = &buckets[i];
    pos = vectorGetFirst(bucket->peers);
    while (pos != NULL) {
      if (now - pos->lastTableRefresh > DHT_INACTIVITY_DEATH) {
	/* remove from table: dead peer */
	vectorRemoveObject(bucket->peers,
			   pos);
	GROW(pos->tables,
	     pos->tableCount,
	     0);
	FREE(pos);
	pos = vectorGetFirst(bucket->peers);
	continue;
      }
      if ( (now - pos->lastTableRefresh > DHT_INACTIVITY_DEATH / 2) &&
	   (now - pos->lastTimePingSend > DHT_INACTIVITY_DEATH / 6) ) {
	pos->lastTimePingSend = now;
	GROW(pingRecords,
	     pingRecordsSize,
	     pingRecordsSize+1);
	pingRecords[pingRecordsSize-1]
	  = rpcAPI->RPC_start(&pos->id,
			      "DHT_ping",
			      request_param,
			      0,
			      DHT_MAINTAIN_FREQUENCY,
			      (RPC_Complete) &ping_reply_handler, 
			      NULL);
      }   
      pos = vectorGetNext(bucket->peers);
    }
  } /* end for all buckets */
  vectorFree(request_param);

  /* 
     OPTIMIZE-ME:
     for all content in all tables:
     check if this peer should still be responsible for
     it, if not, migrate!
  */
  MUTEX_UNLOCK(&lock);
} 

/**
 * Provide the DHT service.  The DHT service depends on the RPC
 * service.
 *
 * @param capi the core API
 * @return NULL on errors, DHT_API otherwise
 */
DHT_ServiceAPI * provide_dht_protocol(CoreAPIForApplication * capi) {
  static DHT_ServiceAPI api;
  unsigned int i;
  
  ENTER();
  coreAPI = capi;
  rpcAPI = capi->requestService("rpc");
  if (rpcAPI == NULL)
    return NULL;
  i = getConfigurationInt("DHT",
			  "BUCKETCOUNT");
  if ( (i == 0) || (i > 160) )
    i = 160;
  GROW(buckets,
       bucketCount,
       i);
  for (i=0;i<bucketCount;i++) {
    buckets[i].bstart = 160 * i / bucketCount;
    buckets[i].bend = 160 * (i+1) / bucketCount;
    buckets[i].peers = vectorNew(4);
  }
  
  rpcAPI->RPC_register("DHT_ping",
		       &rpc_DHT_ping);
  rpcAPI->RPC_register("DHT_findNode",
		       &rpc_DHT_findNode);
  rpcAPI->RPC_register_async("DHT_findValue",
			     &rpc_DHT_findValue);
  rpcAPI->RPC_register_async("DHT_store",
			     &rpc_DHT_store);
  rpcAPI->RPC_register_async("DHT_remove",
			     &rpc_DHT_remove);
  MUTEX_CREATE_RECURSIVE(&lock);
  api.get = &dht_get;
  api.put = &dht_put;
  api.remove = &dht_remove;
  api.join = &dht_join;
  api.leave = &dht_leave;
  api.get_start = &dht_get_async_start;
  api.get_stop = &dht_get_async_stop;
  api.put_start = &dht_put_async_start;
  api.put_stop = &dht_put_async_stop;
  api.remove_start = &dht_remove_async_start;
  api.remove_stop = &dht_remove_async_stop;

  memset(&masterTableId, 0, sizeof(HashCode160));
  /* join the master table */
  i = getConfigurationInt("DHT",
			  "MASTER-TABLE-SIZE");
  if (i == 0)
    i = 65536; /* 64k memory should suffice */
  masterTableDatastore 
    = create_datastore_memory(i);
  dht_join(masterTableDatastore,
	   &masterTableId,
	   0,
	   ALPHA); /* replication level = ALPHA! */
  addCronJob(&dhtMaintainJob,
	     0,
	     DHT_MAINTAIN_FREQUENCY,
	     NULL);
  return &api;
}

/**
 * Shutdown DHT service.
 */
int release_dht_protocol() {
  unsigned int i;
  PeerInfo * bucket;

  ENTER();
  rpcAPI->RPC_unregister("DHT_ping",
			 &rpc_DHT_ping);
  rpcAPI->RPC_unregister("DHT_findNode",
			 &rpc_DHT_findNode);
  rpcAPI->RPC_unregister_async("DHT_findValue",
			       &rpc_DHT_findValue);
  rpcAPI->RPC_unregister_async("DHT_store",
			       &rpc_DHT_store);
  rpcAPI->RPC_unregister_async("DHT_remove",
			       &rpc_DHT_remove);
  delCronJob(&dhtMaintainJob,
	     DHT_MAINTAIN_FREQUENCY,
	     NULL);
  /* stop existing / pending DHT operations */
  while (abortTableSize > 0) {
    delCronJob(abortTable[0].job,
	       0,
	       abortTable[0].arg);
    abortTable[0].job(abortTable[0].arg);
  }
  /* leave the master table */
  dht_leave(&masterTableId,
	    0,
	    0);  
  for (i=0;i<bucketCount;i++) {
    bucket = (PeerInfo*) vectorGetFirst(buckets[i].peers);
    while (bucket != NULL) {
      GROW(bucket->tables,
	   bucket->tableCount,
	   0); 
      bucket = (PeerInfo*) vectorGetNext(buckets[i].peers);
    }
    vectorFree(buckets[i].peers);
  }
  GROW(buckets,
       bucketCount,
       0);

  dhtMaintainJob(NULL); /* free's cron's internal resources! */
  destroy_datastore_memory(masterTableDatastore);
  coreAPI->releaseService(rpcAPI);
  MUTEX_DESTROY(&lock);
  rpcAPI = NULL;
  coreAPI = NULL;
  return OK;
}


/* end of dht.c */
