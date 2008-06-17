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
 * @file applications/afs/module/handler.c
 * @brief Handlers for incoming AFS requests (p2p and CS).
 * @author Christian Grothoff
 **/

#include "afs.h"
#include "bloomfilter.h"
#include "fileindex.h"
#include "manager.h"
#include "routing.h"
#include "policy.h"
#include "routing.h"

/* ********************* p2p handlers ****************** */

static int stat_p2p_query_count;
static int stat_p2p_superquery_count;
static int stat_p2p_chk_replies;
static int stat_p2p_3hash_replies;
#if VERBOSE_STATS
static int stat_cs_query_count;
static int stat_cs_insert_chk_count;
static int stat_cs_insert_3hash_count;
static int stat_cs_index_block_count;
static int stat_cs_index_file_count;
static int stat_cs_index_super_count;
static int stat_cs_delete_chk_count;
static int stat_cs_delete_3hash_count;
static int stat_cs_unindex_block_count;
static int stat_cs_unindex_file_count;
static int stat_cs_unindex_super_count;
static int stat_cs_upload_file_count;

static int stat_cs_insert_sblock_count;
static int stat_cs_nsquery_count;
#endif
static int stat_p2p_nsquery_count;
static int stat_p2p_sblock_replies;


#define DEBUG_HANDLER NO

/**
 * Initialize the handler module. Registers counters
 * with the statistics module.
 *
 * @return OK on success, SYSERR on failure
 **/
int initAFSHandler() {
  stat_p2p_query_count 
    = statHandle("# p2p queries received");
  stat_p2p_superquery_count
    = statHandle("# p2p super queries received");
  stat_p2p_chk_replies 
    = statHandle("# p2p CHK content received (kb)");
  stat_p2p_3hash_replies 
    = statHandle("# p2p search results received (kb)");
#if VERBOSE_STATS
  stat_cs_query_count 
    = statHandle("# client queries received");
  stat_cs_insert_chk_count 
    = statHandle("# client CHK content inserted (kb)");
  stat_cs_insert_3hash_count 
    = statHandle("# client 3HASH search results inserted (kb)");
  stat_cs_index_block_count 
    = statHandle("# client file index requests received");
  stat_cs_index_file_count 
    = statHandle("# file index requests received");
  stat_cs_index_super_count 
    = statHandle("# super query index requests received");
  stat_cs_delete_chk_count 
    = statHandle("# client CHK content deleted (kb)");
  stat_cs_delete_3hash_count 
    = statHandle("# client 3HASH search results deleted (kb)");
  stat_cs_unindex_block_count 
    = statHandle("# client file unindex requests received");
  stat_cs_unindex_file_count 
    = statHandle("# file unindex requests received");
  stat_cs_unindex_super_count 
    = statHandle("# super query unindex requests received");
  stat_cs_insert_sblock_count
    = statHandle("# client SBlock insert requests received");
  stat_cs_nsquery_count
    = statHandle("# client namespace queries received");
  stat_cs_upload_file_count
    = statHandle("# client file upload requests");
#endif
  stat_p2p_nsquery_count
    = statHandle("# p2p namespace queries received");
  stat_p2p_sblock_replies
    = statHandle("# p2p SBlocks received");
  return OK;
}

/**
 * Handle query for content. Depending on how we like the sender,
 * lookup, forward or even indirect.
 **/
int handleQUERY(HostIdentity * sender,
		p2p_HEADER * msg) {
  QUERY_POLICY qp;
  AFS_p2p_QUERY * qmsg;
#if DEBUG_HANDLER
  HexName hex;
  HexName hex2;
#endif
  int queries;
  int ttl;
  unsigned int prio;
  double preference;
      

  queries = (ntohs(msg->size) - sizeof(AFS_p2p_QUERY)) / sizeof(HashCode160);
  if ( (queries <= 0) || 
       (ntohs(msg->size) != sizeof(AFS_p2p_QUERY) + queries * sizeof(HashCode160)) ) {
    LOG(LOG_WARNING,
	"WARNING: query received was malformed\n");
    return SYSERR;
  }
  if (queries>1)
    statChange(stat_p2p_superquery_count,1);
  statChange(stat_p2p_query_count, 1);
  qmsg = (AFS_p2p_QUERY*) msg;

#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&((AFS_p2p_QUERY_GENERIC*)qmsg)->queries[0],
		 &hex));
  IFLOG(LOG_EVERYTHING,
	hash2hex(&sender->hashPubKey,
		 &hex2));
  LOG(LOG_EVERYTHING,
      "EVERYTHING: received query %s (%d) TTL %d PR %u from %s\n",
      &hex,
      queries,
      ntohl(qmsg->ttl),
      ntohl(qmsg->priority),
      &hex2);
#endif

  /* decrement ttl (always) */
  ttl = ntohl(qmsg->ttl);
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "DEBUG: received query for %s with ttl %d\n",
      &hex,
      ttl);
#endif
  if (ttl < 0) {
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
    if (ttl > 0)
      return OK; /* just abort */
  } else
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
  qp = evaluateQuery(sender,
		     ntohl(qmsg->priority));  
  if ((qp & QUERY_DROPMASK) == 0)
    return OK; /* straight drop. */

  preference = (double) (qp & QUERY_PRIORITY_BITMASK);
  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  /* adjust priority */
  prio = ntohl(qmsg->priority);
  if ( (qp & QUERY_PRIORITY_BITMASK) < prio) {
    prio = qp & QUERY_PRIORITY_BITMASK;
    qmsg->priority = htonl(prio);
  }  
  prio = prio / queries; /* effective priority for ttl */
  
  /* adjust TTL */
  if ( (ttl > 0) &&
       (ttl > (int)(prio+3)*TTL_DECREMENT) ) 
    ttl = (int) (prio+3)*TTL_DECREMENT; /* bound! */
  qmsg->ttl = htonl(ttl);

  execQuery(qp, qmsg, NULL);
  return OK;
}
 
/**
 * Receive content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to a client via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.
 **/
int handleCHK_CONTENT(HostIdentity * sender, 
		      p2p_HEADER * msg) {
  int prio;
  HashCode160 queryHash;
  ContentIndex ce;
  AFS_p2p_CHK_RESULT * cmsg;
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_CHK_RESULT)) {
    LOG(LOG_WARNING,
	"WARNING: CHK content message received was malformed\n");
    return SYSERR;
  }
  statChange(stat_p2p_chk_replies, 1);
  cmsg = (AFS_p2p_CHK_RESULT*) msg;
  hash(&cmsg->result,
       CONTENT_SIZE,
       &queryHash);
  prio = useContent(sender,
		    &queryHash,
		    msg);
  if (sender == NULL) /* no migration, this is already content
			 from the local node */
    return OK;  
  preference = (double) prio;
  prio = evaluateContent(&queryHash,
			 prio);
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  if (prio == SYSERR)
    return OK; /* straight drop */
  ce.hash          = queryHash;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_CHK);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
		      &cmsg->result, 
		      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &queryHash);
  return OK;
}

/**
 * Receive content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to a client via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.
 **/
int handle3HASH_CONTENT(HostIdentity * sender, 
			p2p_HEADER * msg) {
  int prio;
  AFS_p2p_3HASH_RESULT * cmsg;
  HashCode160 tripleHash;
  ContentIndex ce;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_3HASH_RESULT)) {
    LOG(LOG_WARNING,
	"WARNING: content message received was malformed\n");
    return SYSERR;
  }
  statChange(stat_p2p_3hash_replies, 1);
  cmsg = (AFS_p2p_3HASH_RESULT*) msg;
  hash(&cmsg->hash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&tripleHash,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received 3HASH search result for %s from peer\n",
      &hex);
#endif
  prio = useContent(sender,
		    &tripleHash,
		    msg);
  if (sender == NULL) { /* no migration, this is already content
			   from the local node */
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"DEBUG: content migration not needed, content is local\n");
#endif
    return OK;  
  }
  preference = (double) prio;
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "DEBUG: content migration with preference %d\n",
      prio);
#endif
  prio = evaluateContent(&tripleHash,
			 prio);
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);


  if (prio == SYSERR) {
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"DEBUG: content not important enough, not replicated\n");
#endif
    return OK; /* straight drop */
  } 
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"DEBUG: content replicated with total preference %d\n",
	prio);
#endif
  ce.hash          = cmsg->hash;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_3HASH);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
             	      &cmsg->result, 
                      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &tripleHash);
  return OK;
}

/* *********************** CS handlers ***************** */

/**
 * Process a query from the client. Forwards to the network.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/ 
int csHandleRequestQuery(ClientHandle sock,
			 AFS_CS_QUERY * queryRequest) {
  QUERY_POLICY qp = QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT|QUERY_PRIORITY_BITMASK; 
  AFS_p2p_QUERY * msg;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int queries;
  int ttl;
  int ret;

  queries = (ntohs(queryRequest->header.size) - sizeof(AFS_CS_QUERY)) / sizeof(HashCode160);
  if ( (queries <= 0) ||
       (ntohs(queryRequest->header.size) != 
	sizeof(AFS_CS_QUERY) + queries * sizeof(HashCode160)) ) {
    LOG(LOG_WARNING,
	"WARNING: received malformed query from client\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_query_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&((AFS_CS_QUERY_GENERIC*)queryRequest)->queries[0], 
		 &hex));
  LOG(LOG_DEBUG, 
      "DEBUG: received %d queries (%s) with ttl %d and priority %u.\n",
      queries,
      &hex,
      ntohl(queryRequest->ttl),
      ntohl(queryRequest->priority));
#endif
  msg = MALLOC(sizeof(AFS_p2p_QUERY)+queries * sizeof(HashCode160));
  msg->header.size 
    = htons(sizeof(AFS_p2p_QUERY)+queries * sizeof(HashCode160));
  msg->header.requestType 
    = htons(AFS_p2p_PROTO_QUERY);
  memcpy(&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
	 &((AFS_CS_QUERY_GENERIC*)queryRequest)->queries[0],
	 sizeof(HashCode160) * queries);
  msg->priority 
    = queryRequest->priority; /* no htonl here: is already in network byte order! */
  /* adjust TTL */
  ttl = ntohl(queryRequest->ttl);
  if ( (ttl > 0) &&
       (ttl > (int)(ntohl(msg->priority)+8)*TTL_DECREMENT) ) 
    ttl = (int) (ntohl(msg->priority)+8)*TTL_DECREMENT; /* bound! */
  msg->ttl = htonl(ttl);
  msg->returnTo = *coreAPI->myIdentity;
  ret = execQuery(qp, msg, sock);   
#if DEBUG_HANDLER
  LOG(LOG_DEBUG, 
      "DEBUG: executed %d queries with result %d.\n",
      queries,
      ret);
#endif
  FREE(msg);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestInsertCHK(ClientHandle sock,
			     AFS_CS_INSERT_CHK * insertRequest) {
  ContentIndex entry;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ret;
  int dupe;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_CHK)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed CHK insert request from client\n");
    return SYSERR;
  } 
#if VERBOSE_STATS
  statChange(stat_cs_insert_chk_count, 1);
#endif
  hash(&insertRequest->content,
       sizeof(CONTENT_Block),
       &entry.hash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&entry.hash,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received CHK insert request for block %s\n",
      &hex);
#endif
  entry.type
    = htons(LOOKUP_TYPE_CHK);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */

  ret = insertContent(&entry,
     	              sizeof(CONTENT_Block),
		      &insertRequest->content,
		      NULL,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &entry.hash);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestInsert3HASH(ClientHandle sock,
			       AFS_CS_INSERT_3HASH * insertRequest) {
  ContentIndex entry;
  HashCode160 tripleHash;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int dupe;
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_3HASH)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed 3HASH insert request from client\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_insert_3hash_count, 1);
#endif
  entry.hash = insertRequest->doubleHash;
  hash(&insertRequest->doubleHash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&tripleHash,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received 3HASH insert request for %s from client\n",
      &hex);
#endif
  entry.type
    = htons(LOOKUP_TYPE_3HASH);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  ret = insertContent(&entry,
		      sizeof(CONTENT_Block),
		      &insertRequest->content,
	   	      NULL,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &tripleHash);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to index content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestIndexBlock(ClientHandle sock,
			      AFS_CS_INDEX_BLOCK * indexingRequest) {
  int dupe;
#if DEBUG_HANDLER
  HexName hex;
#endif

  if (ntohs(indexingRequest->header.size) != 
      sizeof(AFS_CS_INDEX_BLOCK)) {
    LOG(LOG_WARNING, 
	"WARNING: block indexing request from client was malformed!\n");
    return SYSERR;
  }
#if DEBUG_HANDLER
  hash2hex(&indexingRequest->contentIndex.hash,
	   &hex);
  LOG(LOG_DEBUG,
      "DEBUG: indexing content %s at offset %u\n",
      (char*)&hex,
      ntohl(indexingRequest->contentIndex.fileOffset));
#endif  
  

#if VERBOSE_STATS
  statChange(stat_cs_index_block_count, 1);
#endif
  return coreAPI->sendTCPResultToClient
    (sock,
     insertContent(&indexingRequest->contentIndex,
		   0, 
		   NULL, 
		   NULL, 
		   &dupe));
}

/**
 * Process a query to list a file as on-demand encoded from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestIndexFile(ClientHandle sock,
			     AFS_CS_INDEX_FILE * listFileRequest) {
  HexName hex;
  char * filename;
  char * prefix;
  int ret;
  unsigned long long quota;
  unsigned long long usage;

  if (ntohs(listFileRequest->header.size) != 
      sizeof(AFS_CS_INDEX_FILE)) {
    LOG(LOG_WARNING, 
	"WARNING: file indexing request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_index_file_count, 1);
#endif
  hash2hex(&listFileRequest->hash,
	   &hex);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	"WARNING: rejecting content-unindex request, INDEX-DIRECTORY option not set!\n");
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);
  }
  prefix = expandFileName(filename);
  quota = getConfigurationInt("AFS",
			      "INDEX-QUOTA") * 1024 * 1024;
  if (quota != 0) {
    usage = getFileSizeWithoutSymlinks(prefix);
    /* FIXME: check that getFileSize does not count
       linked files; otherwise change the code here
       to make sure links don't count! */
    if (usage + ntohl(listFileRequest->filesize) > quota) {
      LOG(LOG_WARNING,
	  "WARNING: rejecting file index request, quota exeeded: %d of %d (MB)\n",
	  usage / 1024 / 1024,
	  quota / 1024 / 1024);
      FREE(filename);
      return coreAPI->sendTCPResultToClient(sock, 
					    -1);
    }
  }

  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &hex);
  ret = appendFilename(filename);
  if (ret == 0)
    ret = -1;
  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					ret);
}

/**
 * Process a client request to upload a file (indexing).
 **/
int csHandleRequestUploadFile(ClientHandle sock,
			      AFS_CS_UPLOAD_FILE * uploadRequest) {
  HexName hex;
  char * filename;
  char * prefix;
  int ret;
  int fd;

  if (ntohs(uploadRequest->header.size) <
      sizeof(AFS_CS_UPLOAD_FILE)) {
    LOG(LOG_WARNING, 
	"WARNING: file upload request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_upload_file_count, 1);
#endif
  hash2hex(&uploadRequest->hash,
	   &hex);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	"WARNING: rejecting content-upload request, INDEX-DIRECTORY option not set!\n");
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);
  }
  prefix = expandFileName(filename);
  mkdirp(prefix);

  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &hex);
  fd = OPEN(filename, 
	    O_CREAT|O_WRONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* 644 */
  if(fd == -1) {
    LOG(LOG_ERROR,
	"ERROR: OPEN() failed on %s, error %s\n",
	filename,
	strerror(errno));
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);
  }
  
  lseek(fd, 
	ntohl(uploadRequest->pos),
	SEEK_SET);
  ret = WRITE(fd,
	      &((AFS_CS_UPLOAD_FILE_GENERIC*)uploadRequest)->data[0],
	      ntohs(uploadRequest->header.size) - sizeof(AFS_CS_UPLOAD_FILE));
  if (ret == ntohs(uploadRequest->header.size) - sizeof(AFS_CS_UPLOAD_FILE))
    ret = OK;
  else
    ret = SYSERR;
  CLOSE(fd);  

  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					ret);
}

/**
 * Process a client request to extend our super-query bloom
 * filter.
 **/
int csHandleRequestIndexSuper(ClientHandle sock,
			      AFS_CS_INDEX_SUPER * superIndexRequest) {
  ContentIndex entry;
  int dupe;

  if (ntohs(superIndexRequest->header.size) != 
      sizeof(AFS_CS_INDEX_SUPER)) {
    LOG(LOG_WARNING, 
	"WARNING: super-hash indexing request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_index_super_count, 1);
#endif
  addToBloomfilter(superBloomFilter,
		   &superIndexRequest->superHash);
  entry.type
    = htons(LOOKUP_TYPE_SUPER);
  entry.importance
    = superIndexRequest->importance; /* both are in network byte order */ 
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  entry.hash 
    = superIndexRequest->superHash;
  return coreAPI->sendTCPResultToClient(sock, 
		       insertContent(&entry,
				     0, 
				     NULL, 
				     NULL, 
				     &dupe));
}

/**
 * Process a request from the client to delete content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestDeleteCHK(ClientHandle sock,
			     AFS_CS_INSERT_CHK * insertRequest) {
  HashCode160 hc;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_CHK)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed CHK remove request from client\n");
    return SYSERR;
  } 
#if VERBOSE_STATS
  statChange(stat_cs_delete_chk_count, 1);
#endif
  hash(&insertRequest->content,
       sizeof(CONTENT_Block),
       &hc);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&hc,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received CHK remove request for block %s\n",
      &hex);
#endif
  ret = removeContent(&hc,
                      -1);
  if (ret == OK)
    if (YES == testBloomfilter(singleBloomFilter,
			       &hc))
      delFromBloomfilter(singleBloomFilter,
			 &hc);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request from the client to delete content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestDelete3HASH(ClientHandle sock,
			       AFS_CS_INSERT_3HASH * insertRequest) {
  HashCode160 tripleHash;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_3HASH)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed 3HASH delete request from client\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_delete_3hash_count, 1);
#endif
  hash(&insertRequest->doubleHash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&tripleHash,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received 3HASH delete request for %s from client\n",
      &hex);
#endif
  ret = removeContent(&tripleHash,
                      -1);
  if (ret == OK)     
    delFromBloomfilter(singleBloomFilter,
		       &tripleHash);
		     
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request from the client to unindex content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestUnindexBlock(ClientHandle sock,
				AFS_CS_INDEX_BLOCK * indexingRequest) {
  if (ntohs(indexingRequest->header.size) != 
      sizeof(AFS_CS_INDEX_BLOCK)) {
    LOG(LOG_WARNING, 
	"WARNING: block unindexing request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_block_count, 1);
#endif
  return coreAPI->sendTCPResultToClient(sock,
					removeContent(&indexingRequest->contentIndex.hash,
						      -1));
}

/**
 * Callback used to select the file in the fileindex
 * that is to be removed.
 **/
static int removeMatch(char * fn,
		       int i,
		       char * search) {
  if (strcmp(fn, search) == 0)
    return SYSERR;
  else
    return OK;     
}

/**
 * Process a query from the client to remove an on-demand encoded file.
 * n.b. This function just zeroes the correct row in the list of 
 * on-demand encoded files, if match (deletion is done by forEachIndexedFile). 
 * The index of the filename that was removed is returned to the client.
 *
 * FIXME: It lookslike if listFileRequest->filename was NOT in database.list, 
 * it gets appended to it, removed from it, and client gets a false idx. 
 * This unnecessarily bloats the database.list by one empty line.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestUnindexFile(ClientHandle sock,
			       AFS_CS_INDEX_FILE * listFileRequest) {
  int idx;
  HexName hex;
  char * filename;
  char * prefix;

  if (ntohs(listFileRequest->header.size) != 
      sizeof(AFS_CS_INDEX_FILE)) {
    LOG(LOG_WARNING, 
	"WARNING: file unindexing request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_file_count, 1);
#endif
  hash2hex(&listFileRequest->hash,
	  &hex);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	"WARNING: rejecting content-unindex request, INDEX-DIRECTORY option not set!\n");
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);  
  }
  prefix = expandFileName(filename);
  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &hex);
  idx = appendFilename(filename);
  if (idx == -1) {
    FREE(filename);
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);  
  }  
  if (idx == 0) 
    errexit("FATAL: Assertion failed at %s:%d.\n",
	    __FILE__, __LINE__);
  
  forEachIndexedFile((IndexedFileNameCallback)&removeMatch,
		     filename);
  if (0 != UNLINK(filename)) {
    LOG(LOG_WARNING,
	"WARNING: could not remove indexed file %s\n",
	strerror(errno));
    idx = -1; /* remove failed!? */
  }
  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					idx);  
}

/**
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestLinkFile(ClientHandle sock,
			    AFS_CS_LINK_FILE * linkFileRequest) {
  HexName hex;
  char * filename;
  char * tname;
  char * prefix;
  HashCode160 hc;

  if (ntohs(linkFileRequest->header.size) <=
      sizeof(AFS_CS_LINK_FILE)) {
    LOG(LOG_WARNING, 
	"WARNING: file link request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  /* statChange(stat_cs_link_file_count, 1); */
#endif
  tname = MALLOC(ntohs(linkFileRequest->header.size) - sizeof(AFS_CS_LINK_FILE)+1);
  strncpy(tname,
	  &((AFS_CS_LINK_FILE_GENERIC*)linkFileRequest)->data[0],
	  ntohs(linkFileRequest->header.size) - sizeof(AFS_CS_LINK_FILE));
  if ( (SYSERR == getFileHash(tname,
			      &hc)) ||
       (0 != memcmp(&hc,
		    &linkFileRequest->hash,
		    sizeof(HashCode160))) ) {
    LOG(LOG_WARNING, 
	"WARNING: file link request (%s) from client pointed to file with the wrong data!\n",
	tname);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);    
  }
  hash2hex(&linkFileRequest->hash,
	   &hex);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	"WARNING: rejecting content-unindex request, INDEX-DIRECTORY option not set!\n");
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);  
  }
  prefix = expandFileName(filename);
  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  mkdirp(filename);
  strcat(filename, DIR_SEPARATOR_STR);
  strcat(filename, (char*) &hex);
 
  /* trash any previous entry so that SYMLINK() 
   * on existing won't cause retry attempts to fail */
  UNLINK(filename);
  
  if (0 == SYMLINK(tname,
		   filename)) {
    FREE(filename);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  OK);  
  } else {
    LOG(LOG_WARNING,
	"WARNING: could not create link from %s to %s: %s\n",
	tname,
	filename,
	strerror(errno));
    FREE(filename);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);  
  }
}

/**
 * Process a client request to limit our super-query bloom
 * filter.
 **/
int csHandleRequestUnindexSuper(ClientHandle sock,
				AFS_CS_INDEX_SUPER * superIndexRequest) {
  if (ntohs(superIndexRequest->header.size) != 
      sizeof(AFS_CS_INDEX_SUPER)) {
    LOG(LOG_WARNING, 
	"WARNING: super-hash unindexing request from client was malformed!\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_super_count, 1);
#endif
  delFromBloomfilter(superBloomFilter,
		     &superIndexRequest->superHash);
  return coreAPI->sendTCPResultToClient(sock, 
		       removeContent(&superIndexRequest->superHash,
		       -1));
}

/* *************************** SBlock stuff ***************************** */

int csHandleRequestInsertSBlock(ClientHandle sock,
				AFS_CS_INSERT_SBLOCK * insertRequest) {
  ContentIndex entry;
#if DEBUG_HANDLER
  HexName hex1;
  HexName hex2;
  HashCode160 ns;
#endif
  int dupe;
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_SBLOCK)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed SBLOCK insert request from client\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_insert_sblock_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&insertRequest->content.identifier,
		 &hex1);
	hash(&insertRequest->content.subspace,
	     sizeof(PublicKey),
	     &ns);
	hash2hex(&ns,
		 &hex2));
  LOG(LOG_DEBUG,
      "DEBUG: received SBlock for namespace %s with routing ID %s.\n",
      &hex2,
      &hex1);
#endif
  entry.type
    = htons(LOOKUP_TYPE_SBLOCK);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  entry.hash
    = insertRequest->content.identifier;
  dupe = NO;
  ret = insertContent(&entry,
		      sizeof(CONTENT_Block),
		      &insertRequest->content,
	   	      NULL,
		      &dupe);
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "DEBUG: received SBlock insert is dupe: %s (insert %s)\n",
      dupe == NO ? "NO" : "YES",
      ret == SYSERR ? "SYSERR" : "OK");
#endif
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &insertRequest->content.identifier);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

int csHandleRequestNSQuery(ClientHandle sock,
			   AFS_CS_NSQUERY * queryRequest) {
  QUERY_POLICY qp = QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT|QUERY_PRIORITY_BITMASK; 
  AFS_p2p_NSQUERY * msg;
#if DEBUG_HANDLER
  HexName hex1;
  HexName hex2;
#endif

  if (ntohs(queryRequest->header.size) != 
      sizeof(AFS_CS_NSQUERY)) {
    LOG(LOG_WARNING,
	"WARNING: received malformed NS query from client\n");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_nsquery_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&queryRequest->identifier, 
		 &hex1));
  IFLOG(LOG_DEBUG,
	hash2hex(&queryRequest->namespace, 
		 &hex2));
  LOG(LOG_DEBUG, 
      "DEBUG: received NS query (%s/%s) with ttl %d and priority %u.\n",
      &hex2,
      &hex1,
      ntohl(queryRequest->ttl),
      ntohl(queryRequest->priority));
#endif
  msg = MALLOC(sizeof(AFS_p2p_NSQUERY));
  msg->hdr.header.size 
    = htons(sizeof(AFS_p2p_NSQUERY));
  msg->hdr.header.requestType 
    = htons(AFS_p2p_PROTO_NSQUERY);
  msg->hdr.priority 
    = queryRequest->priority; /* no htonl here: is already in network byte order! */
  msg->hdr.ttl 
    = queryRequest->ttl; /* no htonl here: is already in network byte order! */
  msg->identifier
    = queryRequest->identifier;
  msg->namespace
    = queryRequest->namespace;
  msg->hdr.returnTo
    = *(coreAPI->myIdentity);
  execQuery(qp, &msg->hdr, sock);   
  FREE(msg);
  return OK;
}

int handleNSQUERY(HostIdentity * sender,
		  p2p_HEADER * msg) {
  QUERY_POLICY qp;
  AFS_p2p_NSQUERY * qmsg;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ttl;
  unsigned int prio;
  double preference;
  
  if (ntohs(msg->size) != sizeof(AFS_p2p_NSQUERY)) {
    LOG(LOG_WARNING,
	"WARNING: nsquery received was malformed\n");
    return SYSERR;
  }
  statChange(stat_p2p_nsquery_count, 1);
  qmsg = (AFS_p2p_NSQUERY*) msg;
  /* decrement ttl */
  ttl = ntohl(qmsg->hdr.ttl);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&qmsg->identifier,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received NS query for %s with ttl %d\n",
      &hex,
      ttl);
#endif
  if (ttl < 0) {
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
    if (ttl > 0)
      return OK; /* just abort */
  } else
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
  qp = evaluateQuery(sender,
		     ntohl(qmsg->hdr.priority));  
  if ((qp & QUERY_DROPMASK) == 0)
    return OK; /* straight drop. */

  preference = (double) (qp & QUERY_PRIORITY_BITMASK);
  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  /* adjust priority */
  prio = ntohl(qmsg->hdr.priority);
  if ( (qp & QUERY_PRIORITY_BITMASK) < prio) {
    prio = qp & QUERY_PRIORITY_BITMASK;
    qmsg->hdr.priority = htonl(prio);
  }  
  
  /* adjust TTL */
  if ( (ttl > 0) &&
       (ttl > (int)(prio+3)*TTL_DECREMENT) ) 
    ttl = (int) (prio+3)*TTL_DECREMENT; /* bound! */
  qmsg->hdr.ttl = htonl(ttl);

  execQuery(qp, &qmsg->hdr, NULL);
  return OK;
}


int handleSBLOCK_CONTENT(HostIdentity * sender, 
			 p2p_HEADER * msg) {
  int prio;
  AFS_p2p_SBLOCK_RESULT * cmsg;
  ContentIndex ce;
#if DEBUG_HANDLER
  HexName hex;
#endif
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_SBLOCK_RESULT)) {
    LOG(LOG_WARNING,
	"WARNING: signed content message received was malformed\n");
    return SYSERR;
  }
  statChange(stat_p2p_sblock_replies, 1);
  cmsg = (AFS_p2p_SBLOCK_RESULT*) msg;

  if (OK != verifySBlock(&cmsg->result))
    return SYSERR;

#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2hex(&cmsg->result.identifier,
		 &hex));
  LOG(LOG_DEBUG,
      "DEBUG: received SBLOCK search result for %s from peer\n",
      &hex);
#endif
  prio = useContent(sender,
		    &cmsg->result.identifier,
		    msg);
  if (sender == NULL) { /* no migration, this is already content
			   from the local node */
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"DEBUG: content migration not needed, content is local\n");
#endif
    return OK;  
  }
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"DEBUG: content migration with preference %d\n",
	prio);
#endif
  preference = (double) prio;
  prio = evaluateContent(&cmsg->result.identifier,
			 prio);
  if (prio == SYSERR) {
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"DEBUG: content not important enough, not replicated\n");
#endif
    return OK; /* straight drop */
  } 
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"DEBUG: content replicated with total preference %d\n",
	prio);
#endif
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);
  ce.hash          = cmsg->result.identifier;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_SBLOCK);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
             	      &cmsg->result, 
                      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &cmsg->result.identifier);
  return OK;
}


/* end of handler.c */
