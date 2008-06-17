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
 * @file module/dht_rpc.c
 * @brief Implementation of RPC's
 * @author Antti Salonen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_rpc_service.h"

/**
 * Flag that determines if the RPC test will be build as
 * an application module.
 */
#define PROVIDE_RPC_TEST YES

#define DEBUG_RPC YES

/**
 * Access to GNUnet core API.
 */
static CoreAPIForApplication * coreAPI = NULL;

/**
 * A mutex for synchronous access to all module-wide data structures. This
 * lock must be held by the thread that accesses any module-wide accessable
 * data structures.
 */
static Mutex rpcLock;

/* *************** RPC registration ****************** */

/**
 * An RPC registered by the local node.
 */
typedef struct {
  char * name;
  /**
   * Callback for a synchronous RPC.  NULL for async RPCs.
   */
  RPC_Function callback;

  /**
   * Callback for an asynchronous RPC.  NULL for sync RPCs.
   */
  ASYNC_RPC_Function async_callback;
} RegisteredRPC;
  
/**
 * A set of RegisteredRPC structures, one for each RPC registered by the 
 * local node. 
 */
static Vector * list_of_callbacks;


/**
 * Registers an RPC callback under the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to call
 * @return OK on success, SYSERR on error
 *   (typically if a callback of that name is already in use).
 */
static int RPC_register(const char *name,
			RPC_Function callback) {
  RegisteredRPC * rrpc;

  GNUNET_ASSERT(name != NULL);
  GNUNET_ASSERT(callback != NULL);
  MUTEX_LOCK (&rpcLock);
  rrpc = vectorGetFirst(list_of_callbacks);
  while (rrpc != NULL) {
    if (0 == strcmp(rrpc->name, name)) {
      MUTEX_UNLOCK (&rpcLock);
      LOG(LOG_WARNING,
	  _("%s::%s - RPC %s:%p could not be registered:"
	    " another callback is already using this name (%p)\n"),
	  __FILE__, __FUNCTION__, 
	  name, callback, rrpc->callback);
      return SYSERR;
    }
    rrpc = vectorGetNext(list_of_callbacks);
  }
  rrpc = MALLOC(sizeof (RegisteredRPC));
  rrpc->name = STRDUP(name);
  rrpc->callback = callback;
  rrpc->async_callback = NULL;
  vectorInsertLast(list_of_callbacks, rrpc);
  LOG(LOG_DEBUG,
      "%s::%s - Registered RPC %d: %s\n",
      __FILE__, __FUNCTION__, 
      vectorSize(list_of_callbacks), name);
  MUTEX_UNLOCK (&rpcLock);
  return OK;
}

/**
 * Registers an async RPC callback under the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to call
 * @return OK on success, SYSERR on error
 *   (typically if a callback of that name is already in use).
 */
static int RPC_register_async(const char *name,
			      ASYNC_RPC_Function callback) {
  RegisteredRPC * rrpc;

  GNUNET_ASSERT(name != NULL);
  GNUNET_ASSERT(callback != NULL);
  MUTEX_LOCK (&rpcLock);
  rrpc = vectorGetFirst(list_of_callbacks);
  while (rrpc != NULL) {
    if (0 == strcmp(rrpc->name, name)) {
      MUTEX_UNLOCK (&rpcLock);
      LOG(LOG_WARNING,
	  _("%s::%s - RPC %s:%p could not be registered:"
	    " another callback is already using this name (%p)\n"),
	  __FILE__, __FUNCTION__, 
	  name, callback, rrpc->callback);
      return SYSERR;
    }
    rrpc = vectorGetNext(list_of_callbacks);
  }
  rrpc = MALLOC(sizeof (RegisteredRPC));
  rrpc->name = STRDUP(name);
  rrpc->callback = NULL;
  rrpc->async_callback = callback;
  vectorInsertLast(list_of_callbacks, rrpc);
  LOG(LOG_DEBUG,
      "%s::%s - Registered asynchronous RPC %d: %s\n",
      __FILE__, __FUNCTION__, 
      vectorSize(list_of_callbacks), name);
  MUTEX_UNLOCK (&rpcLock);
  return OK;
}


/**
 * Unregisters an RPC callback of the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to unregister, NULL for any function
 * @return OK on success, SYSERR on error
 *   (typically if a callback of that name does not exist or is
 *    bound to a different function).
 */
static int RPC_unregister(const char *name,
			  RPC_Function callback) {
  RegisteredRPC * rrpc;

  GNUNET_ASSERT(name != NULL);
  MUTEX_LOCK(&rpcLock);
  rrpc = vectorGetFirst(list_of_callbacks);
  while (rrpc != NULL) {
    if (0 == strcmp(rrpc->name, name)) {
      if ( (rrpc->callback != callback) &&
	   (callback != NULL) ) {
	LOG(LOG_WARNING,
	    _("%s::%s - RPC %s:%p could not be unregistered:"
	      " another callback registered under that name: %p\n"),
	    __FILE__, __FUNCTION__, 
	    name, callback, rrpc->callback);		
	MUTEX_UNLOCK (&rpcLock);
	return SYSERR;
      } 
      vectorRemoveObject(list_of_callbacks, rrpc);
      FREE(rrpc->name);
      FREE(rrpc);
      MUTEX_UNLOCK(&rpcLock);
      LOG(LOG_DEBUG,
	  "%s::%s - Unregistered RPC %s\n",
	  __FILE__, __FUNCTION__, 
	  name); 
      return OK;
    }
    rrpc = vectorGetNext(list_of_callbacks);
  }
  MUTEX_UNLOCK(&rpcLock);
  LOG(LOG_WARNING,
      _("%s::%s - RPC %s:%p could not be unregistered: not found\n"),
      __FILE__, __FUNCTION__, 
      name, callback);
  return SYSERR; 
}

/**
 * Unregisters an asynchronous RPC callback of the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to unregister, NULL for any function
 * @return OK on success, SYSERR on error
 *   (typically if a callback of that name does not exist or is
 *    bound to a different function).
 */
static int RPC_unregister_async(const char *name,
				ASYNC_RPC_Function callback) {
  RegisteredRPC * rrpc;

  GNUNET_ASSERT(name != NULL);
  MUTEX_LOCK(&rpcLock);
  rrpc = vectorGetFirst(list_of_callbacks);
  while (rrpc != NULL) {
    if (0 == strcmp(rrpc->name, name)) {
      if ( (rrpc->async_callback != callback) &&
	   (callback != NULL) ) {
	LOG(LOG_WARNING,
	    _("%s::%s - RPC %s:%p could not be unregistered:"
	      " another callback registered under that name: %p\n"),
	    __FILE__, __FUNCTION__, 
	    name, callback, rrpc->callback);		
	MUTEX_UNLOCK (&rpcLock);
	return SYSERR;
      } 
      vectorRemoveObject(list_of_callbacks, rrpc);
      FREE(rrpc->name);
      FREE(rrpc);
      MUTEX_UNLOCK(&rpcLock);
      LOG(LOG_DEBUG,
	  "%s::%s - Unregistered asynchronous RPC %s\n",
	  __FILE__, __FUNCTION__, 
	  name); 
      return OK;
    }
    rrpc = vectorGetNext(list_of_callbacks);
  }
  MUTEX_UNLOCK(&rpcLock);
  LOG(LOG_WARNING,
      _("%s::%s - async RPC %s:%p could not be unregistered: not found\n"),
      __FILE__, __FUNCTION__, 
      name, callback);
  return SYSERR; 
}


/* ******** tracking per peer stats to estimate turnaround ***** */

/**
 * What is the time-interval for which we keep activity stats?
 */
#define PEER_TRACKING_TIME_INTERVAL (30 * cronSECONDS)

/**
 * Of how many messages do we keep track per peer (for statistics).
 */
#define MTRACK_COUNT 64

/**
 * A per-peer structure to store TCP-like data.
 */
typedef struct {
  HostIdentity identity;

  /**
   * What is the expected response time for this peer? (0 for unknown)
   */
  cron_t averageResponseTime;

  /**
   * In which of the last 32 time intervals did we send a message?
   * (highest bit corresponds to last time interval; if zero,
   * the record is to be freed).
   */
  unsigned int agedActivitySend;

  /**
   * In which of the last 32 time intervals did we receive a message?
   * (highest bit corresponds to last time interval; if zero,
   * the record is to be freed).
   */
  unsigned int agedActivityRecv;

  /**
   * What were the last times when requests were send to the peer?
   * 0 for no request send *or* last request was repeated.
   */
  cron_t lastRequestTimes[MTRACK_COUNT];

  /**
   * Message ID of the last requests.
   */
  unsigned int lastRequestId[MTRACK_COUNT];

  /**
   * Index to the smallest value in lastRequestTimes.
   */
  unsigned int oldestRTIndex;
  
} PeerInfo;

/**
 * A set of Peer structures, one for each GNUnet peer (as identified by
 * HostIdentity) known to the RPC module. Peers are added as either RPC's
 * are made to them from the local node, or an RPC call is received from them.
 */
static Vector * peerInformation;

/**
 * What is the expected response time for this peer?
 * @return 0 for unknown
 */
static cron_t getExpectedResponseTime(const HostIdentity * peer) {
  cron_t result;
  PeerInfo * pi;

  MUTEX_LOCK(&rpcLock);
  pi = (PeerInfo*) vectorGetFirst(peerInformation);
  while (pi != NULL) {
    if (hostIdentityEquals(peer,
			   &pi->identity)) {
      result = pi->averageResponseTime;
      MUTEX_UNLOCK(&rpcLock);
      return result;
    }
    pi = (PeerInfo*) vectorGetNext(peerInformation);
  }
  MUTEX_UNLOCK(&rpcLock);
  return 0;
}

/**
 * Cron-job used to age the peer statistics.
 */
static void agePeerStats(void * unused) {
  PeerInfo * pi;

  MUTEX_LOCK(&rpcLock);
  pi = vectorGetFirst(peerInformation);
  while (pi != NULL) {
    pi->agedActivitySend = pi->agedActivitySend / 2;
    pi->agedActivityRecv = pi->agedActivityRecv / 2;
    if ( (pi->agedActivitySend == 0) &&
	 (pi->agedActivityRecv == 0) ) {
      vectorRemoveObject(peerInformation, pi);
      FREE(pi);
    }      
    
    pi = vectorGetNext(peerInformation);
  }
  MUTEX_UNLOCK(&rpcLock);
}

/**
 * Ensure replies and requests have different IDs when dealing
 * with the same peer.
 */
#define MINGLE(a,b) (((b) == RPC_p2p_PROTO_RES) ? (a) : (a) ^ 0x12345678)

/**
 * Notification: we sent a message to the peer.
 * @param messageID pseudo-unique ID of the request
 */
static void notifyPeerRequest(HostIdentity * peer,
			      unsigned int messageID) {
  int i;
  PeerInfo * pi;

  MUTEX_LOCK(&rpcLock);
  pi = vectorGetFirst(peerInformation);
  while (pi != NULL) {
    if (hostIdentityEquals(peer,
			   &pi->identity)) {
      for (i=0;i<MTRACK_COUNT;i++) {
	if (pi->lastRequestId[i] == messageID) {
	  pi->lastRequestTimes[i] = 0; /* re-send! */
	  MUTEX_UNLOCK(&rpcLock);
	  return;
	}
      }
      pi->agedActivitySend |= 0x80000000;
      pi->lastRequestTimes[pi->oldestRTIndex] = cronTime(NULL);
      pi->lastRequestId[pi->oldestRTIndex] = messageID;
      pi->oldestRTIndex = (pi->oldestRTIndex+1) % MTRACK_COUNT;
      MUTEX_UNLOCK(&rpcLock);
      return;
    }
    pi = vectorGetNext(peerInformation);
  }
  pi = MALLOC(sizeof(PeerInfo));
  memset(pi, 0, sizeof(PeerInfo));
  pi->identity = *peer;
  pi->agedActivitySend = 0x80000000;
  pi->lastRequestTimes[0] = cronTime(NULL);
  pi->lastRequestId[0] = messageID;
  pi->oldestRTIndex = 1;
  MUTEX_UNLOCK(&rpcLock);
}

/**
 * Notification: we received a (valid) response from the peer.
 * @param messageID the ID of the message that a reply was received
 *        for
 */
static void notifyPeerReply(const HostIdentity * peer,
			    unsigned int messageID) {
  int i;
  PeerInfo * pi;

  MUTEX_LOCK(&rpcLock);
  pi = vectorGetFirst(peerInformation);
  while (pi != NULL) {
    if (hostIdentityEquals(peer,
			   &pi->identity)) {
      for (i=0;i<MTRACK_COUNT;i++) {
	if (pi->lastRequestId[i] == messageID) {
	  if (pi->lastRequestTimes[i] != 0) { /* resend */
	    pi->averageResponseTime
	      = (pi->averageResponseTime * (MTRACK_COUNT-1) +
		 cronTime(NULL) - pi->lastRequestTimes[i]) / MTRACK_COUNT;	    
	    pi->agedActivityRecv |= 0x80000000;
	    pi->lastRequestTimes[i] = 0;
	  }
	  MUTEX_UNLOCK(&rpcLock);
	  return;
	}
      }
      break;
    }
    pi = vectorGetNext(peerInformation);
  }
  MUTEX_UNLOCK(&rpcLock);
}

/* ***************** RPC datastructures ****************** */

/**
 * Minimum delay between retry attempts for RPC messages in
 * the absence of information about the other peer.
 */
#define MIN_RPC_FREQUENCY (250 * cronMILLIS)

/**
 * After what time do we time-out every request (if it is not
 * repeated)?
 */ 
#define MAX_RPC_TIMEOUT (5 * cronMINUTES)


/**
 * Request to execute an function call on the remote peer.  The
 * message is of variable size to pass arguments.  Requests and reply
 * messages use the same struct, the only difference is in the value
 * of the header.requestType field.  For the reply, the
 * functionNameLength indicates the status (0 for OK, otherwise an
 * error code).  argumentCount must be 0 for errors and otherwise
 * indicate the number of return values.
 */
typedef struct {
  p2p_HEADER header; 
  TIME_T timestamp;
  unsigned int sequenceNumber;
  unsigned int importance;
  unsigned short argumentCount;
  unsigned short functionNameLength;
} RPC_Message;


typedef struct {
  RPC_Message rpc_message;
  /**
   * functionNameLength characters describing the function name
   * followed by a serialization of argumentCount arguments.
   */
  char data[1];
} RPC_Message_GENERIC;


/**
 * An ACK message.  An ACK acknowledges the receiving a reply to an
 * RPC call (three-way handshake).  Without an ACK, the receiver of an
 * RPC request is supposed to repeatedly send the RPC reply (until it
 * times out).
 */
typedef struct {
  p2p_HEADER header; 
  /**
   * The number of the original request for which this is the
   * ACK.
   */
  unsigned int sequenceNumber;
} RPC_ACK_Message;

/**
 * Signature of a function called on completion of
 * the RPC.
 * @param context closure
 * @param sequenceNumber ID of the callback
 * @param errorCode 0 on success
 * @param result the return values, NULL on error
 */
typedef void (*RPCFinishedCallback)(void * context,
				    unsigned int sequenceNumber,
				    unsigned short errorCode,
				    RPC_Param * result);

/**
 * A per-RPC structure.
 */
typedef struct CallInstance {
  /**
   * The sequence number of this RPC.
   */
  unsigned int sequenceNumber;

  /**
   * For which peer is this message?
   */
  HostIdentity receiver;

  /**
   * The message we are transmitting (either the request or the
   * reply).
   */
  RPC_Message * msg;

  /**
   * Time where this record times out (timeout value for original
   * request, fixed timeout for reply if no further requests are
   * received; once we send the ACK the record of the sender is
   * discarded; we always send additional ACKs even if we don't have a
   * matching record anymore).
   */
  cron_t expirationTime;

  /**
   * Frequency at which we currently repeat the message.  Initially
   * set to the round-trip estimate, with exponential back-off.
   */
  cron_t repetitionFrequency;

  /**
   * Last time the message was sent.
   */
  cron_t lastAttempt;

  /**
   * If this was a request initiated by this node we'll have to pass
   * the result back to the original caller.  This gives the method
   * and some context args that needs to be invoked.
   */ 
  RPCFinishedCallback finishedCallback;

  /**
   * Arguments to the callback.
   */
  void * rpcCallbackArgs;

   /**
    * How important is this RPC?
    */
  unsigned int importance;
} CallInstance;

/**
 * A set of CallInstance structures for active incoming rpc calls.
 * (requests without a reply).
 */
static Vector * incomingCalls;

/**
 * A set of CallInstance structures for active outgoing rpc calls.
 * (reply messages without an ACK).
 */
static Vector * outgoingCalls;

/**
 * A counter whose value is used for identifying the RPC's originating
 * from the local node. The value of the counter is incremented after each
 * RPC and thus its value also tells the number of RPC's originated from the
 * local node (modulo integer overflow).
 */
static unsigned int rpcIdentifier = 0;

/**
 * Cron-job that processes the RPC queues.  Created for
 * each CallInstance.  Not renewed if the call times out,
 * deleted if the appropriate response is received.
 */
static void retryRPCJob(CallInstance * call) {
#if DEBUG_RPC
  LOG(LOG_DEBUG,
      "Entering %s.\n",
      __FUNCTION__);
#endif

  MUTEX_LOCK(&rpcLock);
  if (cronTime(NULL) > call->expirationTime) {
    if (call->finishedCallback != NULL) {
      call->finishedCallback(call->rpcCallbackArgs,
			     call->sequenceNumber,
			     RPC_ERROR_TIMEOUT,
			     NULL);
      vectorRemoveObject(outgoingCalls, call);
    } else {
      vectorRemoveObject(incomingCalls, call);
    }	  
    FREE(call->msg);
    FREE(call);
  } else {
    if (coreAPI != NULL) {
      unsigned int maxdelay;
      
      if (call->repetitionFrequency == 0)
	call->repetitionFrequency = MIN_RPC_FREQUENCY;
      else
	call->repetitionFrequency = 2 * call->repetitionFrequency;
      maxdelay = (cronTime(NULL) - call->expirationTime)/2;
      if (maxdelay > call->repetitionFrequency / 2)
	maxdelay = call->repetitionFrequency / 2;
      notifyPeerRequest(&call->receiver,
			MINGLE(call->sequenceNumber, 
			       ntohs(call->msg->header.requestType)));
#if DEBUG_RPC
      LOG(LOG_DEBUG,
	  "Sending RPC request.\n");
#endif
      coreAPI->sendToNode(&call->receiver,
			  &call->msg->header,
			  ntohl(call->msg->importance),
			  maxdelay);
    } 
    addCronJob((CronJob) &retryRPCJob,
	       call->repetitionFrequency,
	       0,
	       call);
  }
  MUTEX_UNLOCK(&rpcLock);    
}

/**
 * Send an ACK message.
 */
static void sendAck(const HostIdentity * receiver,
		    unsigned int sequenceNumber,
		    unsigned int importance, 
		    unsigned int maxDelay) {
  RPC_ACK_Message msg;

  msg.header.size = htons(sizeof(RPC_ACK_Message)); 
  msg.header.requestType = htons(RPC_p2p_PROTO_ACK);
  msg.sequenceNumber = htonl(sequenceNumber);  
  coreAPI->sendToNode(receiver, 
		      &msg.header, 
		      importance,
		      maxDelay);
}

static char * getFunctionName(RPC_Message * req) {
  char * ret;
  unsigned short slen;

  slen = ntohs(req->functionNameLength);
  if (ntohs(req->header.size) < sizeof(RPC_Message) + slen)
    return NULL; /* invalid! */
  ret = MALLOC(slen+1);
  memcpy(ret,
	 &((RPC_Message_GENERIC*)req)->data[0],
	 slen);
  ret[slen] = '\0';
  return ret;
}

static RPC_Param * deserializeArguments(RPC_Message * req) {
  unsigned short slen;
  RPC_Param * ret;

  slen = ntohs(req->functionNameLength);
  if (ntohs(req->header.size) < sizeof(RPC_Message) + slen)
    return NULL;  /* invalid! */
  ret = RPC_paramDeserialize(&((RPC_Message_GENERIC*)req)->data[slen],
			     ntohs(req->header.size) - sizeof(RPC_Message) - slen);
  if (RPC_paramCount(ret) != ntohs(req->argumentCount)) {
    RPC_paramFree(ret);
    return NULL; /* invalid! */
  }
  return ret;
}

/**
 * Build an RPC message serializing the name and values
 * properly.
 * @param errorCode the status code for the message, if non-NULL
 *   values will be NULL
 * @param name the name of the target method, NULL for a reply.
 * @param sequenceNumber the unique ID of the message
 * @param values the arguments or return values, maybe NULL
 * @return the RPC message to transmit, caller must free
 */
static RPC_Message * buildMessage(unsigned short errorCode,
				  const char * name,
				  unsigned int sequenceNumber,
				  unsigned int importance,
				  RPC_Param * values) {
  RPC_Message * ret;
  size_t size = sizeof(RPC_Message);
  int slen;

  if (name != NULL) {
    slen = strlen(name);
    size += slen;
  } else
    slen = 0;
  if (values != NULL)
    size += RPC_paramSize(values);
  if (size > 0xFFFF) 
    return NULL; /* message to big! */
  ret = MALLOC(size);
  ret->header.size = htons(size);
  ret->timestamp = htonl(TIME(NULL));
  ret->sequenceNumber = htonl(sequenceNumber);
  ret->importance = htonl(importance);
  if (name == NULL)
    ret->functionNameLength = htons(errorCode);
  else
    ret->functionNameLength = htons(strlen(name));
  ret->argumentCount = htons(RPC_paramCount(values));
  if (name != NULL) {
    memcpy(&((RPC_Message_GENERIC*)ret)->data[0],
	   name,
	   slen);
  }
  RPC_paramSerialize(values,
		     &((RPC_Message_GENERIC*)ret)->data[slen]);
  
  if (name == NULL)
    ret->header.requestType = htons(RPC_p2p_PROTO_RES);
  else
    ret->header.requestType = htons(RPC_p2p_PROTO_REQ);

  return ret;
}


/* ***************** RPC P2P message handlers **************** */


/**
 * Signature of the callback function for the ASYNC_RPC to
 * be called upon completion of the ASYNC function.  Initiates
 * sending back the reply.  Also called in the synchronous RPC
 * case o complete the reply (since it's the same code).
 */
static void async_rpc_complete_callback(RPC_Param * results,
					int errorCode,
					CallInstance * calls) {  
  MUTEX_LOCK (&rpcLock);
  /* build reply message */
  calls->msg = buildMessage(errorCode,
			    NULL,
			    calls->sequenceNumber,
			    calls->importance,
			    results);
  if (calls->msg == NULL)
    calls->msg = buildMessage(RPC_ERROR_RETURN_VALUE_TOO_LARGE,
			      NULL,
			      calls->sequenceNumber,
			      calls->importance,
			      results);
  vectorInsertLast(incomingCalls, calls);

  /* for right now: schedule cron job to send reply! */
  addCronJob((CronJob)&retryRPCJob,
	     0,
	     0,
	     calls);
  MUTEX_UNLOCK (&rpcLock);
}


/**
 * Handle request for remote function call.  Checks if message
 * has been seen before, if not performs the call and sends
 * reply.
 */
static int handleRPCMessageReq(const HostIdentity *sender,
			       const p2p_HEADER * message) {
  RPC_Message * req;
  CallInstance * calls;
  unsigned int sq;
  unsigned short errorCode;
  char * functionName;
  RPC_Param * argumentValues;
  RPC_Param * returnValues;
  RegisteredRPC * rpc;
  
#if DEBUG_RPC
  LOG(LOG_DEBUG,
      "Received RPC request.\n");
#endif
  if ( (ntohs(message->requestType) != RPC_p2p_PROTO_REQ) ||
       (ntohs(message->size) < sizeof(RPC_Message)) ) {
    LOG (LOG_WARNING, 
	 _("Invalid message of type %u received.  Dropping.\n"),
	 ntohs(message->requestType));
    return SYSERR;
  }
  req = (RPC_Message *) message; 
  MUTEX_LOCK (&rpcLock);

  /* check if message is already in incomingCalls,
     if so, update expiration, otherwise deserialize,
     perform call, add reply and create cron job */
  sq = ntohl(req->sequenceNumber);
  
  calls = vectorGetFirst(incomingCalls);
  while (calls != NULL) {
    if ( (calls->sequenceNumber == sq) &&
	 (hostIdentityEquals(&calls->receiver,
			     sender)) ) 
      break;
    calls = vectorGetNext(incomingCalls);
  }
  if (calls != NULL) {
    calls->expirationTime = cronTime(NULL) + MAX_RPC_TIMEOUT;
    MUTEX_UNLOCK(&rpcLock);
    return OK; /* seen before */
  }

  /* deserialize */
  functionName = getFunctionName(req);
  argumentValues = deserializeArguments(req);
  if ( (functionName == NULL) ||
       (argumentValues == NULL) ) {
    FREENONNULL(functionName);
    if (argumentValues != NULL)
      RPC_paramFree(argumentValues);
    MUTEX_UNLOCK(&rpcLock);
    return SYSERR; /* message malformed */
  }
  
  /* find matching RPC function */
  rpc = (RegisteredRPC*) vectorGetFirst(list_of_callbacks);
  while (rpc != NULL) {
    if (0 == strcmp(functionName,
		    rpc->name))
      break;
    rpc = (RegisteredRPC*) vectorGetNext(list_of_callbacks);
  }
  FREE(functionName);

  calls = MALLOC(sizeof(CallInstance));
  calls->sequenceNumber = sq;
  calls->receiver = *sender;
  calls->expirationTime = cronTime(NULL) + MAX_RPC_TIMEOUT;
  calls->lastAttempt = 0;
  calls->finishedCallback = NULL;
  calls->rpcCallbackArgs = NULL;
  calls->importance = ntohl(req->importance);

  /* if possible, perform RPC call */
  if (rpc == NULL) {
    RPC_paramFree(argumentValues);
    returnValues = NULL;
    errorCode = RPC_ERROR_UNKNOWN_FUNCTION;
  } else {
    if (rpc->callback == NULL) {
      /* asynchronous RPC */
      rpc->async_callback(sender,
			  argumentValues,
			  &async_rpc_complete_callback,
			  calls);      
      MUTEX_UNLOCK (&rpcLock);
      return OK;
    } 
    returnValues = RPC_paramNew();
    rpc->callback(sender,
		  argumentValues,
		  returnValues);
    RPC_paramFree(argumentValues);
    errorCode = RPC_ERROR_OK;
  }
  MUTEX_UNLOCK(&rpcLock);
  async_rpc_complete_callback(returnValues,
			      errorCode, 
			      calls);
  return OK;
}

/**
 * Handle reply for request for remote function call.  Checks
 * if we are waiting for a reply, if so triggers the reply.
 * Also always sends an ACK.
 */
static int handleRPCMessageRes(const HostIdentity * sender,
			       const p2p_HEADER * message) {
  RPC_Message * res;
  CallInstance * call;

#if DEBUG_RPC
  LOG(LOG_DEBUG,
      "Received RPC reply.\n");
#endif
  if ( (ntohs(message->requestType) != RPC_p2p_PROTO_RES) ||
       (ntohs(message->size) < sizeof(RPC_Message)) ) {
    LOG(LOG_WARNING,
	_("Invalid message of type %u received.  Dropping.\n"),
	ntohs(message->requestType));
    return SYSERR;
  }

  suspendCron();
  MUTEX_LOCK (&rpcLock);
  res = (RPC_Message *) message;

  /* Locate the CallInstance structure. */
  call = vectorGetFirst(outgoingCalls); 
  while (call != NULL) {
    if ( hostIdentityEquals(&call->receiver, sender) &&
	 (call->sequenceNumber == ntohl(res->sequenceNumber)) )
      break;
    call = vectorGetNext(outgoingCalls);
  }
  if (NULL != call) {
    RPC_Param * reply;
    RPC_Message_GENERIC * gen;
    unsigned short error;

    gen = (RPC_Message_GENERIC*)res;
    reply = NULL;
    error = ntohs(res->functionNameLength);

    if (error == RPC_ERROR_OK) {
      reply = RPC_paramDeserialize(&gen->data[0],
				   ntohs(message->size) - sizeof(RPC_Message));
      if (ntohs(res->argumentCount) != RPC_paramCount(reply)) {
	RPC_paramFree(reply);
	reply = NULL;
	error = RPC_ERROR_REPLY_MALFORMED;
      } 
    }
    if (call->finishedCallback != NULL) {
      call->finishedCallback(call->rpcCallbackArgs,
			     call->sequenceNumber,
			     error,
			     reply);
      call->finishedCallback = NULL;
    }
    vectorRemoveObject(outgoingCalls,
		       call);
    notifyPeerReply(sender,
		    MINGLE(call->sequenceNumber,
			   RPC_p2p_PROTO_REQ));
    delCronJob((CronJob) &retryRPCJob,
	       0,
	       call);
    FREE(call->msg);
    FREE(call);
    if (reply != NULL)
      RPC_paramFree(reply);
  }
  sendAck(sender,
	  ntohl(res->sequenceNumber),
	  0,/* not important, ACK should be tiny enough to go through anyway */
	  0 /* right away */);
  MUTEX_UNLOCK (&rpcLock);
  resumeCron();
  return OK;
}


/**
 * Handle a peer-to-peer message of type RPC_p2p_PROTO_ACK.
 */
static int handleRPCMessageAck(const HostIdentity *sender,
			       const p2p_HEADER * message) {
  RPC_ACK_Message * ack;
  CallInstance *call;
  
#if DEBUG_RPC
  LOG(LOG_DEBUG,
      "Received RPC ACK.\n");
#endif
  if ( (ntohs(message->requestType) != RPC_p2p_PROTO_ACK) ||
       (ntohs(message->size) != sizeof(RPC_ACK_Message)) ) {
    LOG (LOG_WARNING,
	 _("Invalid message of type %u received.  Dropping.\n"),
         ntohs (message->requestType));
    return SYSERR;
  }

  ack = (RPC_ACK_Message*) message;
  suspendCron();
  MUTEX_LOCK (&rpcLock);

  /* Locate the CallInstance structure. */
  call = (CallInstance*) vectorGetFirst(incomingCalls); 
  while (call != NULL) {
    if ( hostIdentityEquals(&call->receiver, sender) &&
	 (call->sequenceNumber == ntohl(ack->sequenceNumber)) )
      break;
    call = (CallInstance*) vectorGetNext(incomingCalls);
  }  

  /* check if we're waiting for an ACK, if so remove job */
  if (NULL != call) {
    notifyPeerReply(sender,
		    MINGLE(ntohl(ack->sequenceNumber),
			   RPC_p2p_PROTO_RES));
    delCronJob((CronJob) &retryRPCJob,
	       0,
	       call);
    vectorRemoveObject(incomingCalls,
		       call);
    FREE(call->msg);
    FREE(call);
  }
  
  MUTEX_UNLOCK (&rpcLock);
  resumeCron();
  return OK;
}

/* ********************* RPC service functions ******************** */

typedef struct {
  Semaphore * sem;
  RPC_Param * result;
  unsigned short ec;
} RPC_EXEC_CLS;

/**
 * Callback function invoked whenever the RPC is complete
 * (timeout, error or success).
 */
static void RPC_execute_callback(RPC_EXEC_CLS * context,
				 unsigned int sq,
				 unsigned short ec,
				 RPC_Param * res) {
  int i;
  unsigned int dl;
  void * data;

  for (i=RPC_paramCount(res)-1;i>=0;i--) {
    data = NULL;
    RPC_paramValueByPosition(res,
			     i,
			     &dl,
			     &data);
    RPC_paramAdd(context->result,
		 RPC_paramName(res,
			       i),
		 dl,
		 data);
  }
  context->ec = ec;
  SEMAPHORE_UP(context->sem);
}

/**
 * Executes a blocking RPC on a node, which may be the local node. The
 * function performs the following steps:
 *
 * - Constructs a request packet from the request parameters 
 * - Waits on a signaling semaphore until the result is ready or timeout
 * - passes the results back to the caller
 *
 * @return the error code of the operation (0 for success).
 */
static int RPC_execute(const HostIdentity *receiver, 
		       const char *name,
		       RPC_Param *requestParam,
		       RPC_Param *returnParam,
		       unsigned int importance,
		       cron_t timeout) {
  RPC_EXEC_CLS cls;
  CallInstance * call;

  MUTEX_LOCK(&rpcLock);
  cls.sem = SEMAPHORE_NEW(0);
  cls.result = returnParam;
  call = MALLOC(sizeof(CallInstance));
  call->lastAttempt = 0;
  call->repetitionFrequency = getExpectedResponseTime(receiver);
  call->expirationTime = cronTime(NULL) + timeout;
  call->receiver = *receiver;
  call->sequenceNumber = rpcIdentifier++;
  call->msg = buildMessage(RPC_ERROR_OK,
			   name,
			   call->sequenceNumber,
			   importance,
			   requestParam);
  call->finishedCallback = (RPCFinishedCallback) &RPC_execute_callback;
  call->rpcCallbackArgs = &cls;
  vectorInsertLast(outgoingCalls, call);
  addCronJob((CronJob) &retryRPCJob, 
	     0,
	     0,
	     call);
  MUTEX_UNLOCK (&rpcLock);
  SEMAPHORE_DOWN(cls.sem);
  SEMAPHORE_FREE(cls.sem);
  return cls.ec;
}

typedef struct RPC_Record {
  HostIdentity peer;
  CallInstance * call;
  RPC_Complete callback;
  void * closure;
  unsigned short errorCode;
} RPC_Record;

static void RPC_async_callback(RPC_Record * rec,
			       unsigned int sequenceNumber,
			       unsigned short errorCode,
			       RPC_Param * result) {
  if ( (errorCode == RPC_ERROR_OK) &&
       (rec->callback != NULL) ) {
    rec->callback(&rec->peer,
		  result,
		  rec->closure);
    rec->callback = NULL; /* never call callback twice */
  }
  rec->errorCode = errorCode; 
}

/**
 * Start an asynchronous RPC.
 *
 * @param timeout when should we stop trying the RPC
 * @param callback function to call with the return value from
 *        the RPC 
 * @param closure extra argument to callback
 * @return value required to stop the RPC (and the RPC must
 *  be explicitly stopped to free resources!)
 */
static RPC_Record * RPC_start(const HostIdentity * receiver,
			      const char * name,
			      RPC_Param * request_param,
			      unsigned int importance,
			      cron_t timeout,
			      RPC_Complete callback,
			      void * closure) {
  RPC_Record * ret;

  ret = MALLOC(sizeof(RPC_Record));
  ret->peer = *receiver;
  ret->callback = callback;
  ret->closure = closure;
  ret->errorCode = RPC_ERROR_TIMEOUT;
  MUTEX_LOCK(&rpcLock);
  ret->call = MALLOC(sizeof(CallInstance));
  ret->call->lastAttempt = 0;
  ret->call->repetitionFrequency = getExpectedResponseTime(receiver);
  ret->call->expirationTime = cronTime(NULL) + timeout;
  ret->call->receiver = *receiver;
  ret->call->sequenceNumber = rpcIdentifier++;
  ret->call->msg = buildMessage(RPC_ERROR_OK,
				name,
				ret->call->sequenceNumber,
				importance,
				request_param);
  ret->call->finishedCallback =
    (RPCFinishedCallback) &RPC_async_callback;
  ret->call->rpcCallbackArgs = ret;
  vectorInsertLast(outgoingCalls, ret->call);
  addCronJob((CronJob) &retryRPCJob, 
	     0,
	     0,
	     ret->call);
  MUTEX_UNLOCK (&rpcLock);
  return ret;
}
 
/**
 * Stop an asynchronous RPC (and free associated resources)
 *
 * @param record the return value from RPC_start
 * @return RPC_ERROR_OK if the RPC was successful,
 *  another RPC_ERROR code if it was aborted
 */
static int RPC_stop(RPC_Record * record) {
  int ret; 
  int cronRunning;

  cronRunning = isCronRunning();
  if (cronRunning)
    suspendIfNotCron();
  delCronJob((CronJob) &retryRPCJob,
	     0,
	     record->call);
  if (cronRunning)
    resumeIfNotCron();
  MUTEX_LOCK(&rpcLock);
  if (NULL != vectorRemoveObject(outgoingCalls, record->call)) {
    FREE(record->call->msg);
    FREE(record->call);    
  }
  MUTEX_UNLOCK(&rpcLock);
  ret = record->errorCode;
  FREE(record);

  return ret;
}

/* ******************* Exported functions ******************* */

/**
 * Shutdown RPC service.
 */
void release_rpc_protocol() {
  CallInstance * call;

  delCronJob(&agePeerStats,
	     PEER_TRACKING_TIME_INTERVAL,
	     NULL);
  coreAPI->unregisterHandler(RPC_p2p_PROTO_REQ, 
			     &handleRPCMessageReq);
  coreAPI->unregisterHandler(RPC_p2p_PROTO_RES, 
			     &handleRPCMessageRes);
  coreAPI->unregisterHandler(RPC_p2p_PROTO_ACK,
			     &handleRPCMessageAck);
  if (NULL != peerInformation) {
    while(vectorSize(peerInformation) > 0)
      FREE(vectorRemoveLast(peerInformation));
    vectorFree(peerInformation);
    peerInformation = NULL;
  }
  if (NULL != incomingCalls) {
    while(vectorSize (incomingCalls) > 0) {
      call = (CallInstance*) vectorRemoveLast(incomingCalls);
      delCronJob((CronJob)&retryRPCJob,
		 0,
		 call);
      FREE(call->msg);
      FREE(call);
    }
    vectorFree(incomingCalls);
    incomingCalls = NULL;
  }
  if (NULL != outgoingCalls) {
    while(vectorSize (outgoingCalls) > 0) {
      call = (CallInstance*) vectorRemoveLast(outgoingCalls);
      delCronJob((CronJob) &retryRPCJob,
		 0,
		 call);
      FREE(call->msg);
      FREE(call);
    }
    vectorFree(outgoingCalls);
    outgoingCalls = NULL;
  }
  if (NULL != list_of_callbacks) {
    while(vectorSize(list_of_callbacks) > 0) {
      RegisteredRPC * rpc;
      rpc = (RegisteredRPC*) vectorRemoveLast(list_of_callbacks);
      LOG(LOG_ERROR,
	  _("RPC not unregistered: %s:%p\n"),
	  rpc->name, rpc->callback);
      FREE(rpc->name);
      FREE(rpc);
    }
    vectorFree(list_of_callbacks);
    list_of_callbacks = NULL;
  }
  coreAPI = NULL;
  MUTEX_DESTROY (&rpcLock);
}

/**
 * Initialize the RPC service.
 */
RPC_ServiceAPI * provide_rpc_protocol(CoreAPIForApplication * capi) {
  static RPC_ServiceAPI rpcAPI;
  int rvalue;
  
  MUTEX_CREATE_RECURSIVE(&rpcLock);
  coreAPI = capi;
  peerInformation = vectorNew(16);
  incomingCalls = vectorNew(16);
  outgoingCalls = vectorNew(16);
  list_of_callbacks = vectorNew(16);
  LOG(LOG_DEBUG, 
      "RPC registering handlers: "
      "%d %d %d\n",
      RPC_p2p_PROTO_REQ,
      RPC_p2p_PROTO_RES,
      RPC_p2p_PROTO_ACK);
  rvalue = OK;
  if (capi->registerHandler(RPC_p2p_PROTO_REQ, 
			    &handleRPCMessageReq) ==
      SYSERR) 
    rvalue = SYSERR;
  if (capi->registerHandler(RPC_p2p_PROTO_RES,
			    &handleRPCMessageRes) ==
      SYSERR) 
    rvalue = SYSERR;
  if (capi->registerHandler (RPC_p2p_PROTO_ACK,
			     &handleRPCMessageAck) ==
      SYSERR) 
    rvalue = SYSERR;
  if (rvalue == SYSERR) {
    release_rpc_protocol();
    LOG(LOG_WARNING,
	_("Failed to initialize '%s' service.\n"),
	"rpc");
    return NULL;
  } else {
    rpcAPI.RPC_execute = &RPC_execute;
    rpcAPI.RPC_register = &RPC_register;
    rpcAPI.RPC_unregister = &RPC_unregister;
    rpcAPI.RPC_register_async = &RPC_register_async;
    rpcAPI.RPC_unregister_async = &RPC_unregister_async;
    rpcAPI.RPC_start = &RPC_start;
    rpcAPI.RPC_stop = &RPC_stop;
    addCronJob(&agePeerStats,
	       PEER_TRACKING_TIME_INTERVAL,
	       PEER_TRACKING_TIME_INTERVAL,
	       NULL);
    return &rpcAPI;
  }
}

#if PROVIDE_RPC_TEST

static void testCallback(const HostIdentity * sender,
			 RPC_Param * arguments,
			 RPC_Param * results) {
  unsigned int dl;
  char * data;

  LOG(LOG_DEBUG, 
      "RPC callback invoked!\n");
  if ( (OK == RPC_paramValueByName(arguments,
				   "command",
				   &dl,
				   (void**)&data)) &&
       (strncmp("Hello", data, dl) == 0) ) {
    LOG(LOG_DEBUG, 
	"RPC callback received Hello command!\n");
    RPC_paramAdd(results,
		 "response",
		 strlen("Hello RPC World")+1,
		 "Hello RPC World");
  }
}

static void async_RPC_Complete_callback(RPC_Param * results,
					Semaphore * sign) {
  unsigned int dl;
  char * reply;

  SEMAPHORE_DOWN(sign);
  if ( (OK != RPC_paramValueByName(results,
				   "response",
				   &dl,
				   (void**)&reply)) ||
       (strncmp("Hello RPC World",
		reply, dl) != 0) ) {
    LOG(LOG_WARNING,
	_("RPC async reply invalid.\n"));
  } else
    LOG(LOG_DEBUG,
	"RPC async reply received.\n");
}

int initialize_rpc_protocol(CoreAPIForApplication * capi) {
  RPC_ServiceAPI * rpcAPI;
  int ret;
  RPC_Param * args;
  RPC_Param * rets;
  unsigned int dl;
  char * reply;
  int code;
  RPC_Record * record;
  Semaphore * sign;

  LOG(LOG_DEBUG, 
      "RPC testcase starting\n");
  rpcAPI = capi->requestService("rpc");
  if (rpcAPI == NULL) {
    BREAK();
    return SYSERR;
  }
  ret = OK;

  if (OK != rpcAPI->RPC_register("testFunction",
				 &testCallback)) {
    BREAK();
    ret = SYSERR;
  }

  args = RPC_paramNew();
  RPC_paramAdd(args,
	       "command",
	       strlen("Hello")+1,
	       "Hello");
  sign = SEMAPHORE_NEW(0);
  record = rpcAPI->RPC_start(coreAPI->myIdentity,
			     "testFunction",
			     args,
			     0,
			     5 * cronSECONDS,
			     (RPC_Complete) &async_RPC_Complete_callback,
			     sign);
  SEMAPHORE_UP(sign); /* allow callback now - forces async! */
  rets = RPC_paramNew();
  code = rpcAPI->RPC_execute(coreAPI->myIdentity,
			     "testFunction",
			     args,
			     rets,
			     0,
			     5 * cronSECONDS);
  if (code != RPC_ERROR_OK) {
    BREAK();
    ret = SYSERR; 
  }
  RPC_paramFree(args);     
  if ( (OK != RPC_paramValueByName(rets,
				   "response",
				   &dl,
				   (void**)&reply)) ||
       (strncmp("Hello RPC World",
		reply, dl) != 0) ) {
    BREAK();
    ret = SYSERR;
  }
  RPC_paramFree(rets);     
  gnunet_util_sleep(1 * cronSECONDS);
  if (RPC_ERROR_OK != rpcAPI->RPC_stop(record))
    LOG(LOG_WARNING,
	_("async RPC reply not received.\n"));

  if (OK != rpcAPI->RPC_unregister("testFunction",
				   &testCallback)) {
    BREAK();
    ret = SYSERR;
  }
  if (OK != capi->releaseService(rpcAPI)) { 
    BREAK();
    ret = SYSERR;
  }
  LOG(LOG_DEBUG, 
      "RPC testcase completed with status %s\n",
      ret == OK ? "SUCCESS" : "FAILURE");
  return ret;
}

/**
 * Does nothing (but must be present for clean unload of the
 * testcase!).
 */
int done_rpc_protocol() {
  return OK;
}

#endif

/* end of rpc.c */
