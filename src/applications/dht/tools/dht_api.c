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
 * @file tools/dht_api.c
 * @brief DHT-module's core API's implementation. 
 * @author Tomi Tukiainen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht.h"

/**
 * Information for each table that this client is responsible
 * for.
 */
typedef struct {
  /**
   * ID of the table.
   */
  DHT_TableId table;
  /**
   * The socket that was used to join GNUnet to receive
   * requests for this table.
   */
  GNUNET_TCP_SOCKET * sock;
  /**
   * The thread that is processing the requests received
   * from GNUnet on sock.
   */
  PTHREAD_T processor;
  /**
   * The Datastore provided by the client that performs the
   * actual storage operations.
   */
  DHT_Datastore * store;
  /**
   * Flags for the table.
   */
  int flags;
  /**
   * Did we receive a request to leave the table?
   */
  int leave_request;

  Mutex lock;
} TableList;

/**
 * Connections to GNUnet helt by this module.
 */
static TableList ** tables;

/**
 * Size of the tables array.
 */
static unsigned int tableCount;

/**
 * Lock for access to tables array.
 */
static Mutex lock;

/**
 * Check if the given message is an ACK.  If so,
 * return the status, otherwise SYSERR.
 */
static int checkACK(CS_HEADER * reply) {
  if ( (sizeof(DHT_CS_REPLY_ACK) == ntohs(reply->size)) &&
       (DHT_CS_PROTO_REPLY_ACK == ntohs(reply->tcpType)) ) 
    return ntohl(((DHT_CS_REPLY_ACK*)reply)->status);
  return SYSERR;
}

/**
 * Send an ACK message of the given value to gnunetd.
 */
static int sendAck(GNUNET_TCP_SOCKET * sock,
		   DHT_TableId * table,
		   int value) {
  DHT_CS_REPLY_ACK msg;

  msg.header.size = htons(sizeof(DHT_CS_REPLY_ACK));
  msg.header.tcpType = htons(DHT_CS_PROTO_REPLY_ACK);
  msg.status = htonl(value);
  msg.table = *table;
  return writeToSocket(sock,
		       &msg.header);
}

/**
 * Thread that processes requests from gnunetd (by forwarding
 * them to the implementation of list->store).
 */
static void * process_thread(TableList * list) {
  CS_HEADER * buffer;
  CS_HEADER * reply;
  DHT_CS_REQUEST_JOIN req;
  int ok;
  
  req.header.size = htons(sizeof(DHT_CS_REQUEST_JOIN));
  req.header.tcpType = htons(DHT_CS_PROTO_REQUEST_JOIN);  
  req.flags = htonl(list->flags);
  req.timeout = htonll(5 * cronSECONDS); /* ??? (no timeout needed for join so far...) */
  req.table = list->table;

  while (list->leave_request == NO) {
    if (list->sock == NULL) {     
      gnunet_util_sleep(500 * cronMILLIS);
      MUTEX_LOCK(&list->lock);
      if (list->leave_request == NO)
	list->sock  = getClientSocket();      
      MUTEX_LOCK(&list->lock);
    }
    if (list->sock == NULL)
      continue;

    ok = NO;
    /* send 'join' message via socket! */
    if (OK == writeToSocket(list->sock,
			    &req.header)) {
      if (OK == readFromSocket(list->sock,
			       &reply)) {
	if (OK == checkACK(reply))
	  ok = YES;
	FREE(reply);
      }
    }
    if (ok == NO) {
      MUTEX_LOCK(&list->lock);
      releaseClientSocket(list->sock);
      list->sock = NULL;
      MUTEX_UNLOCK(&list->lock);
      continue; /* retry... */
    }

    buffer = NULL;
    while (OK == readFromSocket(list->sock,
				&buffer)) {
      switch (ntohs(buffer->tcpType)) {
      case DHT_CS_PROTO_REQUEST_GET: {
	DHT_CS_REQUEST_GET * req;
	DHT_DataContainer * results;
	unsigned int maxResults;       
	unsigned int maxSize;
	int i;
	int resCount;

	if (sizeof(DHT_CS_REQUEST_GET) != ntohs(buffer->size)) {
	  LOG(LOG_ERROR,
	      "Received invalid GET request (size %d)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  FREE(buffer);
	}
	req = (DHT_CS_REQUEST_GET*) buffer;
	if (! equalsHashCode160(&req->table,
				&list->table)) {
	  LOG(LOG_ERROR,
	      "Received invalid GET request (wrong table)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  break;
	}
	
	maxResults = ntohl(req->maxResults);
	maxSize = ntohl(req->maxResultSize);
	results = MALLOC(maxResults * sizeof(DHT_DataContainer));
	for (i=0;i<maxResults;i++) {
	  if (maxSize == 0) {
	    results[i].data = NULL;
	    results[i].dataLength = 0;
	  } else {
	    results[i].data = MALLOC(maxSize);
	    results[i].dataLength = maxSize;
	  }
	}
	resCount = list->store->lookup(list->store->closure,
				       &req->key,
				       maxResults,
				       results,
				       ntohl(req->flags));
	if (resCount == SYSERR) {
	  if (OK != sendAck(list->sock,
			    &list->table,
			    SYSERR)) {
	    LOG(LOG_WARNING,
		"Failed to send ACK.  Closing connection.\n",
		ntohs(buffer->size));
	    MUTEX_LOCK(&list->lock);
	    releaseClientSocket(list->sock);
	    list->sock = NULL;
	    MUTEX_UNLOCK(&list->lock);
	  }
	} else {
	  DHT_CS_REPLY_RESULTS * reply;

	  for (i=0;i<resCount;i++) {
	    reply = MALLOC(sizeof(DHT_CS_REPLY_RESULTS) + results[i].dataLength);
	    reply->header.size = htons(sizeof(DHT_CS_REPLY_RESULTS) + results[i].dataLength);
	    reply->header.tcpType = htons(DHT_CS_PROTO_REPLY_GET);
	    reply->totalResults = htonl(resCount - i);
	    reply->table = list->table;
	    if (OK != writeToSocket(list->sock,
				    &reply->header)) {
	      LOG(LOG_WARNING,
		  "Failed to send result.  Closing connection.\n",
		  ntohs(buffer->size));
	      MUTEX_LOCK(&list->lock);
	      releaseClientSocket(list->sock);
	      list->sock = NULL;
	      MUTEX_UNLOCK(&list->lock);
	      break;
	    }
	    FREE(reply);
	  }
	}

	for (i=0;i<maxResults;i++) 
	  FREENONNULL(results[i].data);
	FREE(results);
	break;
      }


      case DHT_CS_PROTO_REQUEST_PUT: {
	DHT_CS_REQUEST_PUT * req;
	DHT_DataContainer value;

	if (sizeof(DHT_CS_REQUEST_PUT) > ntohs(buffer->size)) {
	  LOG(LOG_ERROR,
	      "Received invalid PUT request (size %d)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  break;
	}
	req = (DHT_CS_REQUEST_PUT*) buffer;
	if (! equalsHashCode160(&req->table,
				&list->table)) {
	  LOG(LOG_ERROR,
	      "Received invalid PUT request (wrong table)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  break;
	}

	value.dataLength = ntohs(buffer->size) - sizeof(DHT_CS_REQUEST_PUT);
	if (value.dataLength == 0) {
	  value.data = NULL;
	} else {
	  value.data = MALLOC(value.dataLength);
	  memcpy(value.data,
		 &((DHT_CS_REQUEST_PUT_GENERIC*)req)->value[0],
		 value.dataLength);
	}
	if (OK !=
	    sendAck(list->sock,
		    &req->table,
		    list->store->store(list->store->closure,
				       &req->key,
				       &value,
				       ntohl(req->flags)))) {
	  LOG(LOG_ERROR,
	      "Failed to send ACK for PUT.  Closing connection.\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	}
	FREENONNULL(value.data);
	break;
      }


      case DHT_CS_PROTO_REQUEST_REMOVE: {
	DHT_CS_REQUEST_REMOVE * req;
	DHT_DataContainer value;

	if (sizeof(DHT_CS_REQUEST_REMOVE) > ntohs(buffer->size)) {
	  LOG(LOG_ERROR,
	      "Received invalid REMOVE request (size %d)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  break;
	}
	req = (DHT_CS_REQUEST_REMOVE*) buffer;
	if (! equalsHashCode160(&req->table,
				&list->table)) {
	  LOG(LOG_ERROR,
	      "Received invalid REMOVE request (wrong table)\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	  break;
	}

	value.dataLength = ntohs(buffer->size) - sizeof(DHT_CS_REQUEST_REMOVE);
	if (value.dataLength == 0) {
	  value.data = NULL;
	} else {
	  value.data = MALLOC(value.dataLength);
	  memcpy(value.data,
		 &((DHT_CS_REQUEST_REMOVE_GENERIC*)req)->value[0],
		 value.dataLength);
	}
	if (OK !=
	    sendAck(list->sock,
		    &req->table,
		    list->store->remove(list->store->closure,
					&req->key,
					(value.dataLength == 0) ? NULL : &value,
					ntohl(req->flags)))) {
	  LOG(LOG_ERROR,
	      "Failed to send ACK for REMOVE.  Closing connection.\n",
	      ntohs(buffer->size));
	  MUTEX_LOCK(&list->lock);
	  releaseClientSocket(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(&list->lock);
	}
	FREENONNULL(value.data);
	break;
      }


      default:
	LOG(LOG_ERROR,
	    "Received unknown request type: %d\n",
	    ntohs(buffer->tcpType));
	MUTEX_LOCK(&list->lock);
	releaseClientSocket(list->sock);
	list->sock = NULL;
	MUTEX_UNLOCK(&list->lock);
      } /* end of switch */
      FREE(buffer);
      buffer = NULL;
    }
    MUTEX_LOCK(&list->lock);
    releaseClientSocket(list->sock);
    list->sock = NULL;
    MUTEX_UNLOCK(&list->lock);
  }

  return NULL;
}


/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to 
 *   the join request (has no impact on success or failure)
 * @param flags 
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_join(DHT_Datastore * store,
		 DHT_TableId * table,
		 cron_t timeout,
		 int flags) {
  TableList * list;
  int i;

  MUTEX_LOCK(&lock);
  for (i=0;i<tableCount;i++) 
    if (equalsHashCode160(&tables[i]->table,
			  table)) {
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
  list = MALLOC(sizeof(TableList));
  list->flags = flags;
  list->table = *table;
  list->store = store;
  list->leave_request = NO;
  if (list->sock == NULL) {
    FREE(list);
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  MUTEX_CREATE(&list->lock);
  if (OK != PTHREAD_CREATE(&list->processor,
			   (PThreadMain)&process_thread,
			   list,
			   16 * 1024)) {
    releaseClientSocket(list->sock);
    MUTEX_DESTROY(&list->lock);
    FREE(list);
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  } 
  GROW(tables,
       tableCount,
       tableCount+1);
  tables[tableCount-1] = list;
  MUTEX_UNLOCK(&lock);
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
int DHT_LIB_leave(DHT_TableId * table,
		  cron_t timeout,
		  int flags) {
  TableList * list;
  int i;
  void * unused;
  DHT_CS_REQUEST_LEAVE req;
  CS_HEADER * reply;
  int ret;
  
  list = NULL;
  MUTEX_LOCK(&lock);
  for (i=0;i<tableCount;i++) {
    if (equalsHashCode160(&tables[i]->table,
			  table)) {
      list = tables[i];
      tables[i] = tables[tableCount-1];
      GROW(tables,
	   tableCount,
	   tableCount-1);
      break;
    }
  }
  MUTEX_UNLOCK(&lock);
  if (list == NULL)
    return SYSERR; /* no such table! */

  list->leave_request = YES;
  /* send LEAVE message! */  
  req.header.size = htons(sizeof(DHT_CS_REQUEST_LEAVE));
  req.header.tcpType = htons(DHT_CS_PROTO_REQUEST_LEAVE);
  req.flags = htonl(flags);
  req.timeout = htonll(timeout);
  req.table = *table;

  ret = SYSERR;
  MUTEX_LOCK(&list->lock);
  if (list->sock != NULL) {
    if (OK == writeToSocket(list->sock,
			    &req.header)) {
      reply = NULL;
      if (OK == readFromSocket(list->sock,
			       &reply)) {
	if (OK == checkACK(reply))
	  ret = OK;	
	FREE(reply);
      }
    }
    closeSocketTemporarily(list->sock); /* signal process_thread */
  }
  MUTEX_UNLOCK(&list->lock);
  unused = NULL;
  PTHREAD_JOIN(&list->processor, &unused);
  releaseClientSocket(list->sock);
  MUTEX_DESTROY(&list->lock);
  FREE(list);
  return ret;
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
 * The peer does not have to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param maxResults maximum number of results to obtain, size of the results array
 * @param results where to store the results (on success)
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
int DHT_LIB_get(DHT_TableId * table,
		HashCode160 * key,
		cron_t timeout,
		unsigned int maxResults,
		DHT_DataContainer ** results) {
  GNUNET_TCP_SOCKET * sock;
  DHT_CS_REQUEST_GET req;
  DHT_CS_REPLY_RESULTS * res;
  CS_HEADER * reply;
  int ret;
  int i;
  unsigned int size;

  sock = getClientSocket();
  if (sock == NULL)
    return SYSERR;
  req.header.size = htons(sizeof(DHT_CS_REQUEST_GET));
  req.header.tcpType = htons(DHT_CS_PROTO_REQUEST_GET);
  req.table = *table;
  req.key = *key;
  req.flags = 0; /* FIXME */
  req.maxResults = htonl(maxResults);
  req.maxResultSize = htonl(0); /* FIXME: get from results! */
  req.timeout = htonll(timeout);
  if (OK != writeToSocket(sock,
			  &req.header)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  reply = NULL;
  if (OK != readFromSocket(sock,
			   &reply)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  if ( (sizeof(DHT_CS_REPLY_ACK) == ntohs(reply->size)) &&
       (DHT_CS_PROTO_REPLY_ACK == ntohs(reply->tcpType)) ) {
    releaseClientSocket(sock);
    ret = checkACK(reply);
    FREE(reply);
    return ret;
  }
  if ( (sizeof(DHT_CS_REPLY_RESULTS) < ntohs(reply->size)) ||
       (DHT_CS_PROTO_REPLY_GET != ntohs(reply->tcpType)) ) {
    LOG(LOG_WARNING,
	"Unexpected reply to GET operation.\n");
    releaseClientSocket(sock);
    FREE(reply);
    return SYSERR;
  }
  /* ok, we got some replies! */

  res = (DHT_CS_REPLY_RESULTS*) reply;
  ret = ntohl(res->totalResults);
  
  size = ntohs(reply->size) - sizeof(DHT_CS_REPLY_RESULTS);
  if (results[0]->dataLength == 0)
    results[0]->data = MALLOC(size);
  else
    if (results[0]->dataLength < size)
      size = results[0]->dataLength;
  results[0]->dataLength = size;
  memcpy(results[0]->data,
	 &((DHT_CS_REPLY_RESULTS_GENERIC*)res)->data[0],
	 size);  
  FREE(reply);
  for (i=1;i<ret;i++) {
    reply = NULL;
    if (OK != readFromSocket(sock,
			     &reply)) {
      releaseClientSocket(sock);
      return i;
    }  
    if ( (sizeof(DHT_CS_REPLY_ACK) == ntohs(reply->size)) &&
	 (DHT_CS_PROTO_REPLY_ACK == ntohs(reply->tcpType)) ) {
      releaseClientSocket(sock);
      ret = checkACK(reply);
      FREE(reply);
      return i;
    }
    if ( (sizeof(DHT_CS_REPLY_RESULTS) < ntohs(reply->size)) ||
	 (DHT_CS_PROTO_REPLY_GET != ntohs(reply->tcpType)) ) {
      LOG(LOG_WARNING,
	  "Unexpected reply to GET operation.\n");
      releaseClientSocket(sock);
      FREE(reply);
      return i;
    }
    if (i > maxResults) {
      FREE(reply);
      continue;
    }

    res = (DHT_CS_REPLY_RESULTS*) reply;
    ret = ntohl(res->totalResults);
  
    size = ntohs(reply->size) - sizeof(DHT_CS_REPLY_RESULTS);
    if (results[i]->dataLength == 0)
      results[i]->data = MALLOC(size);
    else
      if (results[i]->dataLength < size)
	size = results[i]->dataLength;
    results[i]->dataLength = size;
    memcpy(results[i]->data,
	   &((DHT_CS_REPLY_RESULTS_GENERIC*)res)->data[0],
	   size);  
    FREE(reply);
  }
  releaseClientSocket(sock);
  return ret;
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
int DHT_LIB_put(DHT_TableId * table,
		HashCode160 * key,
		cron_t timeout,
		DHT_DataContainer * value,
		int flags) {
  GNUNET_TCP_SOCKET * sock;
  DHT_CS_REQUEST_PUT * req;
  CS_HEADER * reply;
  int ret;

  sock = getClientSocket();
  if (sock == NULL)
    return SYSERR;
  req = MALLOC(sizeof(DHT_CS_REQUEST_PUT) + value->dataLength);
  req->header.size = htons(sizeof(DHT_CS_REQUEST_PUT) + value->dataLength);
  req->header.tcpType = htons(DHT_CS_PROTO_REQUEST_PUT);
  req->table = *table;
  req->key = *key;
  req->flags = htonl(flags);
  req->timeout = htonll(timeout);
  memcpy(&((DHT_CS_REQUEST_PUT_GENERIC*)req)->value[0],
	 value->data,
	 value->dataLength);
  ret = SYSERR;
  if (OK == writeToSocket(sock,
			  &req->header))
    if (OK == readFromSocket(sock,
			     &reply)) {
      if (OK == checkACK(reply))
	ret = OK;
      FREE(reply);
    }
  releaseClientSocket(sock);
  return ret;
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
int DHT_LIB_remove(DHT_TableId * table,
		   HashCode160 * key,
		   cron_t timeout,
		   DHT_DataContainer * value,
		   int flags) {
  GNUNET_TCP_SOCKET * sock;
  DHT_CS_REQUEST_REMOVE * req;
  CS_HEADER * reply;
  int ret;
  size_t n;

  sock = getClientSocket();
  if (sock == NULL)
    return SYSERR;
  n = sizeof(DHT_CS_REQUEST_REMOVE);
  if (value != NULL)
    n += value->dataLength;
  req = MALLOC(n);
  req->header.size = htons(n);
  req->header.tcpType = htons(DHT_CS_PROTO_REQUEST_REMOVE);
  req->table = *table;
  req->key = *key;
  req->flags = htonl(flags);
  req->timeout = htonll(timeout);
  if (value != NULL)
    memcpy(&((DHT_CS_REQUEST_REMOVE_GENERIC*)req)->value[0],
	   value->data,
	   value->dataLength);
  ret = SYSERR;
  if (OK == writeToSocket(sock,
			  &req->header))
    if (OK == readFromSocket(sock,
			     &reply)) {
      if (OK == checkACK(reply))
	ret = OK;
      FREE(reply);
    }
  releaseClientSocket(sock);
  return ret;
}


/**
 * Initialize DHT_LIB. Call first.
 */
void DHT_LIB_init() {
  MUTEX_CREATE(&lock);
}

/**
 * Initialize DHT_LIB. Call after leaving all tables!
 */
void DHT_LIB_done() {
  MUTEX_DESTROY(&lock);
}


/* end of dht_api.c */
