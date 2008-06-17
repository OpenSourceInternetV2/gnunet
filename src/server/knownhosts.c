/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file server/knownhosts.c
 * @brief maintains list of known peers
 *
 * Code to maintain the list of currently known hosts (in memory
 * structure of data/hosts) and (temporary) blacklisting information
 * and a list of HELOs that are temporary unless confirmed via PONG
 * (used to give the transport module the required information for the
 * PING).
 *
 * Todo:
 * - we may want to cache more HELOs in memory
 *
 * @author Christian Grothoff
 */ 

#include "gnunet_util.h"
#include "knownhosts.h"

#define DEBUG_KNOWNHOSTS NO

typedef struct {
  HostIdentity identity;
  /** how long is this host blacklisted? */
  cron_t until;
  /** what would be the next increment for blacklisting? */
  cron_t delta;
  /** for which protocol is this host known? */
  unsigned short protocol;
  /** should we also reject incoming messages? (YES/NO) */
  int strict;
} HostEntry;

/**
 * The current (allocated) size of knownHosts
 */
static int max_ = 0;

/**
 * The number of actual entries in knownHosts
 */
static int count_;

/**
 * A lock for accessing knownHosts
 */
static Mutex lock_;

/**
 * The list of known hosts.
 */
static HostEntry * hosts_ = NULL;

/**
 * Directory where the HELOs are stored in (data/hosts)
 */
static char * networkIdDirectory;

#define MAX_TEMP_HOSTS 32

/**
 * The list of temporarily known hosts
 */
static HELO_Message * tempHosts[MAX_TEMP_HOSTS];

/**
 * tempHosts is a ringbuffer, this is the current
 * index into it.
 */
static int tempHostsNextSlot;

/**
 * Get the directory in which we store the hostkeys/HELOs.
 */
static char * getHostsDirectory() {
  return getFileName("GNUNETD",
		     "HOSTS",
		     _("Configuration file must specify directory for "
		       "network identities in section %s under %s.\n"));
}

/**
 * Get the filename under which we would store the HELO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID.PROTOCOL
 */
static char * getHostFileName(const HostIdentity * id,
			      const unsigned short protocol) {
  EncName fil;
  char * fn;
  size_t n;

  hash2enc(&id->hashPubKey,
	   &fil);
  n = strlen(networkIdDirectory) + sizeof(EncName) + 1 + 5 + 1;
  fn = MALLOC(n);
  SNPRINTF(fn,
	   n,
	   "%s%s.%u",
	   networkIdDirectory,
	   (char*) &fil,
	   protocol);
  return fn;
}

/**
 * Initialize this module.
 */
void initKnownhosts() {
  int i;

  for (i=0;i<MAX_TEMP_HOSTS;i++)
    tempHosts[i] = NULL;
  tempHostsNextSlot = 0;
  count_ = 0;
  MUTEX_CREATE_RECURSIVE(&lock_);
  networkIdDirectory = getHostsDirectory();
  mkdirp(networkIdDirectory);
  cronScanDirectoryDataHosts(NULL);
  addCronJob(&cronScanDirectoryDataHosts,
	     15 * cronMINUTES,
	     15 * cronMINUTES,
	     NULL); 
}

/**
 * Shutdown the knownhosts module.
 */
void doneKnownhosts() {
  int i;

  delCronJob(&cronScanDirectoryDataHosts,
	     15 * cronMINUTES,
	     NULL);
  for (i=0;i<MAX_TEMP_HOSTS;i++)
    FREENONNULL(tempHosts[i]);
  MUTEX_DESTROY(&lock_);
  GROW(hosts_,
       max_,
       0);
  count_ = 0;
  FREE(networkIdDirectory);
}

/**
 * Add a host to the temporary list.
 */
void addTemporaryHost(HELO_Message * tmp) {
  MUTEX_LOCK(&lock_);   
  FREENONNULL(tempHosts[tempHostsNextSlot]);
  tempHosts[tempHostsNextSlot++] = tmp;
  if (tempHostsNextSlot >= MAX_TEMP_HOSTS)
    tempHostsNextSlot = 0;
  MUTEX_UNLOCK(&lock_);   
}

/**
 * Add a host to the list.
 * @param identity the identity of the host
 * @param protocol the protocol for the host
 */
static void addHostToKnown(HostIdentity * identity,
			   unsigned short protocol) {
  int i;

  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++)
    if ( (hostIdentityEquals(identity,
			     &hosts_[i].identity)) &&
	 (protocol == hosts_[i].protocol) ) {
      MUTEX_UNLOCK(&lock_);   
      return; /* already there */
    }
  if (count_ == max_)
    GROW(hosts_,
	 max_,
	 max_+32);
  memcpy(&hosts_[count_].identity,
	 identity,
	 sizeof(HostIdentity));
  hosts_[count_].until = 0;
  hosts_[count_].delta = 30 * cronSECONDS;
  hosts_[count_].protocol = protocol;
  hosts_[count_].strict = NO;
  count_++;
  MUTEX_UNLOCK(&lock_);   
}

/**
 * Delete a host from the list.
 */
void delHostFromKnown(const HostIdentity * identity,
		      const unsigned short protocol) {
  char * fn;
  int i;

  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++)
    if ( (hostIdentityEquals(identity,
			     &hosts_[i].identity)) &&
	 (protocol == hosts_[i].protocol) ) {
      memmove(&hosts_[i],
	      &hosts_[count_-1],
	      sizeof(HostEntry));
      count_--;   
      /* now remove the file */
      fn = getHostFileName(identity, protocol);
      if (0 != UNLINK(fn))
	LOG_FILE_STRERROR(LOG_WARNING, "unlink", fn);
      FREE(fn);
      MUTEX_UNLOCK(&lock_);   
      return; /* deleted */
    }
  MUTEX_UNLOCK(&lock_);   
}

/**
 * Bind a host address (helo) to a hostId.
 * @param msg the verified (!) HELO message
 */
void bindAddress(HELO_Message * msg) {
  char * fn;
  char * buffer;
  HELO_Message * oldMsg;
  int size;
  EncName enc;

  GNUNET_ASSERT(msg != NULL);
  IFLOG(LOG_INFO,
	hash2enc(&msg->senderIdentity.hashPubKey,
		 &enc));
#if DEBUG_KNOWNHOSTS
  LOG(LOG_INFO,
      "Binding address of node %s.%d\n",
      &enc, 
      ntohs(msg->protocol));
#endif
  fn = getHostFileName(&msg->senderIdentity,		       
		       ntohs(msg->protocol));
  buffer = MALLOC(MAX_BUFFER_SIZE);
  size = readFile(fn,
		  MAX_BUFFER_SIZE,
		  buffer);
  oldMsg = (HELO_Message*) buffer;
  if ((unsigned int)size == HELO_Message_size(oldMsg)) {
    if (ntohl(oldMsg->expirationTime) > ntohl(msg->expirationTime)) {
      FREE(fn);
      FREE(buffer);
      return; /* have more recent HELO in stock */    
    }
  }
  writeFile(fn,
	    msg, 
	    HELO_Message_size(msg),
	    "644"); 
  FREE(fn);
  FREE(buffer);
  addHostToKnown(&msg->senderIdentity,
		 ntohs(msg->protocol));
}

struct TempStorage_ {
  EncName enc;
  HELO_Message * helo;
  int result;
};

/**
 * Check if the filename matches the identity that we are searching
 * for. If yes, fill it in.
 */
static void identity2HeloHelper(const char * fn,
				const char * dirName,
				struct TempStorage_ * res) {
  if (strstr(fn, (char*)&res->enc) != NULL) {
    char * fileName;
    HELO_Message buffer;
    int size;
    size_t n;
        
    n = strlen(networkIdDirectory) + strlen(fn) + 1;
    fileName = MALLOC(n);
    SNPRINTF(fileName,
	     n,
	     "%s%s",
	     networkIdDirectory, 
	     fn);
    size = readFile(fileName, 
		    sizeof(HELO_Message), 
		    &buffer);
    if (size == sizeof(HELO_Message)) {
      HELO_Message * tmp;
      tmp = MALLOC(HELO_Message_size(&buffer));
      size = readFile(fileName, 
		      HELO_Message_size(&buffer),
		      tmp);
      if ((unsigned int)size != HELO_Message_size(&buffer)) {
	if (0 == UNLINK(fileName))	  
	  LOG(LOG_WARNING, 
	      _("Removed file '%s' containing invalid peer advertisement.\n"),
	      fileName);
	else
	  LOG_FILE_STRERROR(LOG_ERROR, "unlink", fileName);
	FREE(tmp);
      } else {
	if (NO == isTransportAvailable(ntohs(buffer.protocol)) ) {
	  FREE(tmp);
	} else if (res->result == SYSERR) {
	  res->result = OK;
	  res->helo = tmp;
	} else { 
	  unsigned int c1 = transportGetCost(ntohs(tmp->protocol));
	  unsigned int c2 = transportGetCost(ntohs(res->helo->protocol));
	  if ( (c1 != (unsigned int)-1) && (c1 > 0) )
	    c1 = randomi(c1);
	  if ( (c2 != (unsigned int)-1) && (c2 > 0) )
	    c2 = randomi(c2);
	  if (c1 > c2) {
	    FREE(res->helo);
	    res->helo = tmp;
	  } else
	    FREE(tmp);
	}
      }
    } else {
      if (0 == UNLINK(fileName)) {
	LOG(LOG_WARNING,
	    _("Removed file '%s' containing invalid peer advertisement.\n"),
	    fileName);
      } else {
	LOG_FILE_STRERROR(LOG_ERROR, "unlink", fileName);
      }
    }
    FREE(fileName);
  }
}

/**
 * Obtain the public key and address of a known host.  If no specific
 * protocol is specified (ANY_PROTOCOL_NUMBER), HELOs for cheaper
 * protocols are returned with preference (randomness!).
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        ANY_PROTOCOL_NUMBER if we do not care which protocol
 * @param tryTemporaryList is it ok to check the unverified HELOs?
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 */
int identity2Helo(const HostIdentity *  hostId,
		  const unsigned short protocol,
		  int tryTemporaryList,
		  HELO_Message ** result) {  
  struct TempStorage_ tempStorage;
  char * fn;
  HELO_Message buffer;
  int size;
  int i;

  *result = NULL;
  fn = getHostFileName(hostId, protocol);
  size = readFile(fn, 
		  sizeof(HELO_Message), 
		  &buffer);
  if (size == sizeof(HELO_Message)) {
    *result = MALLOC(HELO_Message_size(&buffer));
    size = readFile(fn, 
		    HELO_Message_size(&buffer),
		    *result);
    if ((unsigned int)size != HELO_Message_size(&buffer)) {
      if (0 == UNLINK(fn))
	LOG(LOG_WARNING, 
	    _("Removed file '%s' containing invalid HELO data.\n"),
	    fn);
      else 
	LOG_FILE_STRERROR(LOG_ERROR, "unlink", fn);
      FREE(fn);
      FREE(*result);
      *result = NULL;
      return SYSERR;
    }
    if (YES == isTransportAvailable(ntohs((*result)->protocol))) {
      FREE(fn);
      return OK;
    } else {
      FREE(*result);
      *result = NULL;
    }
  } else if (size != -1) {
    if (0 == UNLINK(fn))
      LOG(LOG_WARNING, 
	  _("Removed invalid HELO file '%s'\n"),
	  fn);
    else
      LOG_FILE_STRERROR(LOG_ERROR, "unlink", fn);
  }
  FREE(fn);

  if (YES == tryTemporaryList) {
    /* ok, then try temporary hosts */      
    MUTEX_LOCK(&lock_);   
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if ( (tempHosts[i] != NULL) &&
	   hostIdentityEquals(hostId,
			      &tempHosts[i]->senderIdentity) &&
	   ( (ntohs(tempHosts[i]->protocol) == protocol) ||
	     ( (protocol == ANY_PROTOCOL_NUMBER) &&
	       (YES == isTransportAvailable(ntohs(tempHosts[i]->protocol))) ) ) ) {
	*result = MALLOC(HELO_Message_size(tempHosts[i]));
	memcpy(*result,
	       tempHosts[i],
	       HELO_Message_size(tempHosts[i]));	    
	MUTEX_UNLOCK(&lock_);   
	return OK;
      }    
    }
    MUTEX_UNLOCK(&lock_);   
  }
  if (protocol != ANY_PROTOCOL_NUMBER) 
    return SYSERR; /* nothing found */
  /* ok, last chance, scan directory! */
  hash2enc(&hostId->hashPubKey,
	   &tempStorage.enc);

  tempStorage.result = SYSERR;
  tempStorage.helo = NULL;
#if DEBUG_KNOWNHOSTS
  LOG(LOG_DEBUG,
      "scanning directory %s for peer identity, proto %d\n",
      networkIdDirectory,
      protocol);
#endif
  scanDirectory(networkIdDirectory,
		(DirectoryEntryCallback)&identity2HeloHelper,
		&tempStorage);
  *result = tempStorage.helo;
  return tempStorage.result;
}

/**
 * Blacklist a host. This method is called if a host
 * failed to respond to a connection attempt.
 *
 * @param identity the ID of the peer to blacklist
 * @param desperation how desperate are we to connect? [0,MAXHOSTS]
 * @param strict should we reject incoming connection attempts as well?
 * @return OK on success SYSERR on error
 */
int blacklistHost(const HostIdentity * identity,
		  int desperation,
		  int strict) {
  int i;
  EncName hn;

  if (desperation < 0)
    desperation = 0;
  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++)
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      if (strict == YES) {
	/* Presumably runs a broken version of GNUnet;
	   blacklist for 1 day (we hope the other peer
	   updates the software eventually...) */
	hosts_[i].delta = 1 * cronDAYS;
      } else {
	hosts_[i].delta 
	  = hosts_[i].delta * 2 + randomi((desperation+1)*cronSECONDS);
	if (hosts_[i].delta > 4 * cronHOURS) 
	  hosts_[i].delta = 4 *  cronHOURS+randomi(desperation+1); 
      }
      cronTime(&hosts_[i].until);      
      hosts_[i].until += hosts_[i].delta;
      hosts_[i].strict = strict;
      hash2enc(&identity->hashPubKey,
	       &hn);
#if DEBUG_KNOWNHOSTS
      LOG(LOG_DEBUG, 
	  "Blacklisting host %s for %d seconds (strict=%d).\n",
	  (char*)&hn, 
	  hosts_[i].delta / cronSECONDS,
	  strict);
#endif
      MUTEX_UNLOCK(&lock_);   
     return OK;
    }
  MUTEX_UNLOCK(&lock_);   
  return SYSERR;
}

/**
 * Is the host currently 'strictly' blacklisted (i.e. we refuse to talk)? 
 * 
 * @param identity host to check
 * @return YES if true, else NO
 */
int isBlacklistedStrict(const HostIdentity * identity) {
  int i;
  cron_t now;
  
  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      cronTime(&now);			         
      if ( (now < hosts_[i].until) && (hosts_[i].strict == YES) ) {
        MUTEX_UNLOCK(&lock_);   
        return YES;
      } else {
        MUTEX_UNLOCK(&lock_);   
        return NO;
      }
    }
  }
  MUTEX_UNLOCK(&lock_);   
  return NO;
}

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return OK on success SYSERR on error
 */
int whitelistHost(const HostIdentity * identity) {
  int i;

  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      hosts_[i].delta = 30 * cronSECONDS;
      hosts_[i].until = 0;
      hosts_[i].strict = NO;
      MUTEX_UNLOCK(&lock_);   
      return OK;
    }
  }
  MUTEX_UNLOCK(&lock_);   
  return SYSERR;
}

/**
 * Call a method for each known host.
 *
 * @param callback the method to call for each host
 * @param now the time to use for excluding hosts due to blacklisting, use 0 
 *        to go through all hosts.
 * @param data an argument to pass to the method
 * @return the number of hosts matching
 */
int forEachHost(HostIterator callback,
		cron_t now,
		void * data) {
  int i;
  int count = 0;

  MUTEX_LOCK(&lock_);   
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(&hosts_[i].identity,
			   &myIdentity))
      continue;
    if ( (now == 0) || 
	 (now >= hosts_[i].until) ) {
      count++;
      if (callback != NULL) {
	HostIdentity hi;
	unsigned short proto;

	memcpy(&hi,
	       &hosts_[i].identity,
	       sizeof(HostIdentity));
	proto = hosts_[i].protocol;
	MUTEX_UNLOCK(&lock_);   
	callback(&hi, 
		 proto,
		 data);      
	MUTEX_LOCK(&lock_);   
      }
    }
  }
  MUTEX_UNLOCK(&lock_);   
  return count;
}

static void cronHelper(const char * filename, 
		       const char * dirname,
		       void * unused) {
  HostIdentity identity;
  EncName id;
  unsigned int protoNumber;
  char * fullname;

  GNUNET_ASSERT(sizeof(EncName) == 33);
  if (2 == sscanf(filename,
		  "%32c.%u",
		  (char*)&id,
		  &protoNumber)) {
    id.encoding[sizeof(EncName)-1] = '\0';
    if (OK == enc2hash((char*)&id, 
		       &identity.hashPubKey)) {
      addHostToKnown(&identity,
		     (unsigned short) protoNumber);
      return;
    }
  } 
  
  fullname = MALLOC(strlen(filename) + strlen(networkIdDirectory) + 1);
  fullname[0] = '\0';
  strcat(fullname, networkIdDirectory);
  strcat(fullname, filename);
  if (0 == UNLINK(fullname)) 
    LOG(LOG_WARNING,
	_("File '%s' in directory '%s' does not match naming convention. Removed.\n"),
	filename,
	networkIdDirectory);
  else
    LOG_FILE_STRERROR(LOG_ERROR, "unlink", fullname);
  FREE(fullname);
}

/**
 * Get an estimate of the network size.
 * @return the estimated number of nodes, SYSERR on error
 */
int estimateNetworkSize() {
  return count_;
}
 
/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
void cronScanDirectoryDataHosts(void * unused) {
  int count;

#if DEBUG_KNOWNHOSTS
  LOG(LOG_CRON,
      "enter cronScanDirectoryDataHosts\n");
#endif
  count = scanDirectory(networkIdDirectory,
			&cronHelper,
			NULL);
  if (count <= 0) {
    LOG(LOG_WARNING, 
	_("%s '%s' returned no known hosts!\n"),
	"scanDirectory",
	networkIdDirectory);
  }
#if DEBUG_KNOWNHOSTS
  LOG(LOG_CRON, 
      "exit cronScanDirectoryDataHosts\n");
#endif
}

/* end of knownhosts.c */
