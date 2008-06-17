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
 * @file applications/afs/esed2/sblock.c
 * @brief data structure SBlock
 * @author Christian Grothoff
 **/

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define ENCRYPTED_SIZE \
		   (sizeof(unsigned short) + \
		   sizeof(unsigned short) + \
		   sizeof(FileIdentifier)+ \
		   MAX_DESC_LEN +  \
		   MAX_FILENAME_LEN/2 + \
		   MAX_MIMETYPE_LEN/2 +\
		   sizeof(TIME_T) +\
		   sizeof(TIME_T) + \
		   sizeof(HashCode160) +\
		   sizeof(HashCode160) )

#define SIGNED_SIZE \
		   (ENCRYPTED_SIZE + \
 		   sizeof(HashCode160))

#define DEBUG_SBLOCK NO

/**
 * Verify that a given SBlock is well-formed.
 * @param sb the sblock
 **/
int verifySBlock(SBlock * sb) {
  HashCode160 S;
  HashCode160 NmI;
  HashCode160 HNmI;
  HashCode160 HNmIxS;
  int ret;

  /* if the SBlock is in plaintext, the signature
     will not match; if the block is in plaintext can be checked
     quickly by testing if R = H(N-I) ^ S.  If that is the case,
     we need to first encrypt the first part of the SBlock
     with K = N - I and *then* do the signature verification */
  hash(&sb->subspace,
       sizeof(PublicKey),
       &S);
  deltaId(&sb->identifierIncrement,
          &sb->nextIdentifier,
          &NmI);
  hash(&NmI,
       sizeof(HashCode160),
       &HNmI);
  xorHashCodes(&S, &HNmI, &HNmIxS);
  if (equalsHashCode160(&sb->identifier,
                        &HNmIxS)) {
    SBlock * tmp;
    SESSIONKEY skey;
    unsigned char iv[BLOWFISH_BLOCK_LENGTH];

    tmp = MALLOC(sizeof(SBlock));
    hashToKey(&NmI, &skey, &iv[0]);
    memcpy(tmp, sb, sizeof(SBlock));
    encryptBlock(sb,
                 ENCRYPTED_SIZE,
                 &skey,
                 &iv[0],
                 tmp);
    ret = verifySig(tmp,
                    SIGNED_SIZE,
                    &sb->signature,
                    &sb->subspace);
    FREE(tmp);
    if (OK == ret)
      addNamespace(&S);
    return ret;
  } else {
    ret = verifySig(sb,
                    SIGNED_SIZE,
                    &sb->signature,
                    &sb->subspace);
    if (OK == ret)
      addNamespace(&S);
    return ret;
  }
}

/**
 * Compute the "current" ID of an updateable SBlock.  Will set the ID
 * of the sblock itself for non-updateable content, the ID of the next
 * identifier for sporadically updated SBlocks and the ID computed from
 * the timing function for periodically updated SBlocks.
 *
 * @param sb the SBlock (must be in plaintext)
 * @param now the time for which the ID should be computed
 * @param c the resulting current ID (set)
 **/
void computeIdAtTime(SBlock * sb,
		     TIME_T now,
		     HashCode160 * c) {
  TIME_T pos;
  HashCode160 tmp;
#if DEBUG_SBLOCK 
  HexName hex;
#endif

  if (ntohl(sb->updateInterval) == (TIME_T) SBLOCK_UPDATE_SPORADIC) {
    memcpy(c, 
	   &sb->nextIdentifier, 
	   sizeof(HashCode160));
    return;
  } else if (ntohl(sb->updateInterval) == (TIME_T) SBLOCK_UPDATE_NONE) {
    /* H(N-I)^S is the current routing key, so N-I = k */
    deltaId(&sb->identifierIncrement,
	    &sb->nextIdentifier,
	    c);
    return;
  }
  pos = ntohl(sb->creationTime);
  deltaId(&sb->identifierIncrement,
	  &sb->nextIdentifier,
	  c);
  while (pos + ntohl(sb->updateInterval) < now) {
    pos += ntohl(sb->updateInterval);
    addHashCodes(c, 
		 &sb->identifierIncrement,
		 &tmp);
		  
    memcpy(c, &tmp, sizeof(HashCode160));
#if DEBUG_SBLOCK 
    hash2hex(c,
             &hex);
    LOG(LOG_DEBUG, "Update at %s should have key %s\n",
        GN_CTIME(&pos),
        (char*)&hex);
#endif
  }
}


void decryptSBlock(HashCode160 * k,
		   SBlock * in,
		   SBlock * out) {
  SESSIONKEY skey;
  unsigned char iv[BLOWFISH_BLOCK_LENGTH];

  memcpy(out, in, sizeof(SBlock));
  hashToKey(k, &skey, &iv[0]);
  if (ENCRYPTED_SIZE !=
      decryptBlock(&skey,
		   in,
		   ENCRYPTED_SIZE,
		   &iv[0],
		   out))
    errexit("FATAL: decryptBlock failed.\n");
}

/**
 * Build an (encrypted) SBlock.
 */
SBlock * buildSBlock(Hostkey pseudonym,
		     FileIdentifier * fi,
		     char * description,
		     char * filename,
		     char * mimetype,
		     TIME_T creationTime,
		     TIME_T interval,
		     HashCode160 * k,
 		     HashCode160 * n) {
  SBlock * result;
  SBlock plainSBlock;
  HashCode160 s; /* subspace identifier = H(PubKey) */ 
  HashCode160 i; /* identifier increment = n - k*/
  HashCode160 r; /* routing identifier = H(k) ^ s*/
  HashCode160 hk; /* H(k) */
  void * tmp;
  SESSIONKEY skey;
  unsigned char iv[BLOWFISH_BLOCK_LENGTH];
  HexName hex1;
  HexName hex2;
  
  IFLOG(LOG_DEBUG,
	hash2hex(k, &hex1);
	hash2hex(n, &hex2));
  LOG(LOG_DEBUG,
      "DEBUG: building SBlock %s: %s -- %s\n",
      filename,
      description,
      mimetype);
  LOG(LOG_DEBUG,
      "DEBUG: building SBlock with key %s and next key %s\n",
      &hex1, &hex2);

  result = MALLOC(sizeof(SBlock));
  memset(result, 0, sizeof(SBlock));
  result->major_formatVersion 
    = htons(SBLOCK_MAJOR_VERSION);
  result->minor_formatVersion 
    = htons(SBLOCK_MINOR_VERSION);
  memcpy(&result->fileIdentifier,
	 fi,
	 sizeof(FileIdentifier));
  if (strlen(description) >= MAX_DESC_LEN)
    description[MAX_DESC_LEN-1] = '\0';
  memcpy(&result->description[0],
	 description,
	 strlen(description));
  if (strlen(filename) >= MAX_FILENAME_LEN/2)
    filename[MAX_FILENAME_LEN/2-1] = '\0';
  memcpy(&result->filename[0],
	 filename,
	 strlen(filename));
  if (strlen(mimetype) >= MAX_MIMETYPE_LEN/2)
    mimetype[MAX_MIMETYPE_LEN/2-1] = '\0';
  memcpy(&result->mimetype[0],
	 mimetype,
	 strlen(mimetype));
  result->creationTime = htonl(creationTime);
  result->updateInterval = htonl(interval);
  getPublicKey(pseudonym,
	       &result->subspace);

  hash(&result->subspace,
       sizeof(PublicKey),
       &s);
  hash(k,
       sizeof(HashCode160),
       &hk);
  xorHashCodes(&hk, &s, &r);
  deltaId(k,
	  n,
	  &i); /* i = n - k */


  memcpy(&result->nextIdentifier,
	 n,
	 sizeof(HashCode160));
  memcpy(&result->identifierIncrement,
	 &i,
	 sizeof(HashCode160));

  IFLOG(LOG_DEBUG,
	hash2hex(&s, &hex1);
	hash2hex(&r, &hex2));
  LOG(LOG_DEBUG,
      "DEBUG: building SBlock for namespace %s and query %s\n",
      &hex1, &hex2);

  hashToKey(k, &skey, &iv[0]);
  tmp = MALLOC(ENCRYPTED_SIZE);
  encryptBlock(result,
	       ENCRYPTED_SIZE,
	       &skey,
	       &iv[0],
	       tmp);
  memcpy(result,
	 tmp, 
	 ENCRYPTED_SIZE);
  FREE(tmp);

  memcpy(&result->identifier,
	 &r,
	 sizeof(HashCode160));

  if (OK != sign(pseudonym,
		 SIGNED_SIZE,
		 result,
		 &result->signature)) {
    FREE(result);
    return NULL;
  }  

  decryptSBlock(k,
		result,
		&plainSBlock);
  makeRootNodeAvailable((RootNode*)&plainSBlock,
			DIR_CONTEXT_INSERT_SB);
  return result;
}


/**
 * Insert the SBlock
 *
 * @return OK on success, SYSERR on error
 **/
int insertSBlock(GNUNET_TCP_SOCKET * sock,
		 SBlock * sb) {
  AFS_CS_INSERT_SBLOCK * msg;
  int ok;
  int res;

  msg = MALLOC(sizeof(AFS_CS_INSERT_SBLOCK));
  msg->header.size = htons(sizeof(AFS_CS_INSERT_SBLOCK));
  msg->header.tcpType = htons(AFS_CS_PROTO_INSERT_SBLOCK);
  msg->importance = htonl(getConfigurationInt("GNUNET-INSERT",
					      "CONTENT-PRIORITY"));
  memcpy(&msg->content,
	 sb,
	 sizeof(SBlock));
  ok = writeToSocket(sock,
		     &msg->header);
  FREE(msg);
  if (SYSERR == readTCPResult(sock,
			      &res)) {
    LOG(LOG_WARNING, 
	"WARNING: server did not send confirmation of insertion\n");
    ok = SYSERR;
  } else {
    if (res == SYSERR)
      LOG(LOG_WARNING, 
	  "WARNING: server could not perform insertion\n");
    ok = res;
  }
  return ok;
}

typedef struct {
  /**
   * Time when the cron-job was first started.
   **/
  cron_t start;

  /**
   * How many cron-units may we run (total)?
   **/
  cron_t timeout;
  GNUNET_TCP_SOCKET * sock;
  AFS_CS_NSQUERY * query;
} SendNSQueryContext;

static void sendNSQuery(SendNSQueryContext * sqc) {
  cron_t now;
  int remTime;
  int new_ttl;
  int new_priority;

#if DEBUG_SBLOCK
  LOG(LOG_DEBUG, "DEBUG: enter sendNSQuery\n");
#endif
  
  cronTime(&now);
  if (sqc->timeout != 0) {
    remTime = sqc->start - now + sqc->timeout;
    if (remTime <= 0) {
      LOG(LOG_DEBUG, 
	  "DEBUG: exiting sendNSQuery without making a query\n");
      return;
    }
  } else
    remTime = 0x7FFFFFFF; /* max signed int */

  if (YES == checkAnonymityPolicy(AFS_CS_PROTO_NSQUERY,
				  sizeof(AFS_p2p_NSQUERY)) ) {
    if (OK == writeToSocket(sqc->sock,
			    &sqc->query->header)) {
      /* successful transmission to GNUnet,
	 increase ttl/priority for the next time */
      new_ttl = ntohl(sqc->query->ttl);
      if (new_ttl > 0xFFFFFF)
	new_ttl = randomi(0xFFFFFF); /* if we get too large, reduce! */
      sqc->query->ttl 
	= htonl(randomi(1+4*new_ttl));
      new_priority = ntohl(sqc->query->priority);
      if (new_priority > 0xFFFFFF)
	new_priority = randomi(0xFFFFFF); /* if we get too large, reduce! */
      sqc->query->priority 
	= htonl(randomi(1+4*new_priority));
    } else {
      new_ttl = 5 * cronSECONDS; /* wait at least 5s for gnunetd */				    
    }
  } else {
    new_ttl = TTL_DECREMENT; 
  }

  /* Don't repeat a search faster than TTL_DEC seconds */;
  if (new_ttl < TTL_DECREMENT)
    new_ttl = TTL_DECREMENT;
  
#if DEBUG_SBLOCK
  LOG(LOG_DEBUG,
      "DEBUG: will wait for min(%d, %d) ms\n",
      new_ttl, 
      remTime);
#endif
  /* Do not sleep longer than the amount of time we have until
     we shut down */
  if ((unsigned int)new_ttl >= (unsigned int)remTime)
    new_ttl = remTime; 

  if (remTime > 0) {
#if DEBUG_SBLOCK
    LOG(LOG_DEBUG, 
	"DEBUG: reinstating sendNSQuery in %d\n", 
	new_ttl);
#endif
    addCronJob((CronJob)&sendNSQuery,
	       new_ttl,
	       0,
	       sqc);
  }
}

/**
 * Retrieve an SBlock.
 * 
 * @param sock socket to use to contact gnunetd
 * @param s namespace which namespace to search
 * @param k key to decrypt the SBlock in the namespace (query
 *        to identify the block is derived from k)
 * @param testTerminate function to poll for abort
 * @param ttContext argument for testTerminate
 * @param resultCallback function to call for results
 * @param closure argument to pass to resultCallback
 * @return OK on success, SYSERR on error (= no result found)
 **/
int searchSBlock(GNUNET_TCP_SOCKET * sock,
		 HashCode160 * s,
		 HashCode160 * k,
		 TestTerminateThread testTerminate,
		 void * ttContext,
		 NSSearchResultCallback resultCallback,
		 void * closure) {
  CS_HEADER * buffer;
  AFS_CS_RESULT_SBLOCK * reply;
  int ret;
  HashCode160 hc;
  HashCode160 hk;
  HashCode160 r; /* r = H(k) ^ s */
  SendNSQueryContext sqc;
  SBlock result;

  hash(k,
       sizeof(HashCode160),
       &hk);
  xorHashCodes(&hk,
	       s,
	       &r);  /* compute routing key R */
  memset(&sqc,
         0,
	 sizeof(SendNSQueryContext));
  /* add cron job to send search query */
  sqc.sock = sock;
  sqc.query = MALLOC(sizeof(AFS_CS_NSQUERY));
  sqc.query->header.size = htons(sizeof(AFS_CS_NSQUERY));
  sqc.query->header.tcpType = htons(AFS_CS_PROTO_NSQUERY);
  sqc.query->priority = htonl(1);
  sqc.query->ttl = htonl(1+randomi(TTL_DECREMENT));
  memcpy(&sqc.query->namespace,
	 s,
	 sizeof(HashCode160));
  memcpy(&sqc.query->identifier,
	 &r,
	 sizeof(HashCode160));  

  addCronJob((CronJob)&sendNSQuery,
	     0,
	     0,
	     &sqc);  
  ret = SYSERR;
  while (NO == testTerminate(ttContext)) {
    buffer = NULL;
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER **) &buffer)) {
      if (YES == testTerminate(ttContext))
	break;
      sleep(1);
      continue;
    }
#if DEBUG_SBLOCK
    LOG(LOG_DEBUG,
	"DEBUG: received message from gnunetd\n");
#endif
    switch (ntohs(buffer->tcpType)) {
    case AFS_CS_PROTO_RESULT_SBLOCK: 
      if (ntohs(buffer->size) != 
	  sizeof(AFS_CS_RESULT_SBLOCK)) {
	closeSocketTemporarily(sock);
	LOG(LOG_WARNING,
	    "WARNING: received invalid reply from gnunetd, retrying\n");
	break;
      }
      reply = (AFS_CS_RESULT_SBLOCK*)buffer;
      if (OK != verifySBlock(&reply->result)) {
	LOG(LOG_WARNING,
	    "WARNING: SBlock received from gnunetd failed verification.\n");
	break;
      }
      /* internal identifier (for routing HT, etc.) is
	 "xor" of the user-identifier with the namespace
	 ID to avoid keyword collisions with realnames
	 in the global, 3HASH namespace */
      hash(&reply->result.subspace,
	   sizeof(PublicKey),
	   &hc); 
      if (! equalsHashCode160(&hc,
			      s)) {
	LOG(LOG_WARNING,
	    "WARNING: SBlock received from gnunetd belongs to wrong namespace.\n");
	break;	    
      }
      if (! equalsHashCode160(&r,
			      &reply->result.identifier) ) {
	LOG(LOG_WARNING,
	    "WARNING: SBlock received from gnunetd has wrong identifier.\n");
	break;	    
      }
      decryptSBlock(k, 
                    &reply->result,
		    &result);
      resultCallback(&result,
		     closure);
      ret = OK;
      break;
    default:
      LOG(LOG_WARNING,
	  "WARNING: message from server is of unexpected type\n");
      break;
    }
    FREE(buffer);
  }
  /* del cron job */
  delCronJob((CronJob)&sendNSQuery,
	     0,
	     &sqc);  
  FREE(sqc.query);

  return ret; 
}

/**
 * Print the information contained in an SBlock.
 * 
 * @param stream where to print the information to
 * @param sb the SBlock -- in plaintext.
 **/
void printSBlock(void * swrap,
		 SBlock * sb) {
  HexName hex;
  HashCode160 hc;
  TIME_T now;
  TIME_T pos;
  char * fstring;
  char * filename;
  FILE * stream;

  stream = (FILE*) swrap;
  
  sb->description[MAX_DESC_LEN-1] = 0;
  sb->filename[MAX_FILENAME_LEN/2-1] = 0;
  sb->mimetype[MAX_MIMETYPE_LEN/2-1] = 0;
  /* if it is a GNUnet directory, replace suffix '/' with ".gnd" */
  if (0 == strcmp(sb->mimetype,
  		  GNUNET_DIRECTORY_MIME)) {
    filename = expandDirectoryName(sb->filename);
  } else {
    filename = STRDUP(sb->filename);
  }
     
  hash(&sb->subspace,
       sizeof(PublicKey),
       &hc);
  hash2hex(&hc,
	   &hex);
  fprintf(stream,
	  "%s (%s) published by %s\n",
	  &sb->description[0],
	  &sb->mimetype[0],
	  (char*)&hex);
  fstring = fileIdentifierToString(&sb->fileIdentifier);
  fprintf(stream,
	  "gnunet-download -o \"%s\" %s\n",
	  filename,
	  fstring);
  FREE(filename);
  FREE(fstring);
  switch (ntohl(sb->updateInterval)) {
  case SBLOCK_UPDATE_SPORADIC:
    hash2hex(&sb->nextIdentifier,
	     &hex);
    fprintf(stream,
	    "Next update will be %s.\n",
	    (char*)&hex);  
    break;
  case SBLOCK_UPDATE_NONE:
    fprintf(stream,
	    "SBlock indicates no updates.\n");  
    break;
  default:    
    pos = (TIME_T) ntohl(sb->creationTime);
    deltaId(&sb->identifierIncrement,
	    &sb->nextIdentifier,
	    &hc);
    TIME(&now);
    while (pos + ntohl(sb->updateInterval) < now) {
      HashCode160 tmp;

      pos += ntohl(sb->updateInterval);
      addHashCodes(&hc,
		   &sb->identifierIncrement,
		   &tmp);
      memcpy(&hc,	
	     &tmp,
	     sizeof(HashCode160));
      hash2hex(&hc,
	       &hex);
      fprintf(stream,
	      "Update due at %s has key %s\n",
	      GN_CTIME(&pos),
	      (char*)&hex);
    }  
    break;    
  } /* end of switch on interval */
}


/* end of sblock.c */
