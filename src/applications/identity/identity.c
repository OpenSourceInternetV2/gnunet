/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file identity/identity.c
 * @brief maintains list of known peers
 *
 * Code to maintain the list of currently known hosts (in memory
 * structure of data/hosts) and (temporary) blacklisting information
 * and a list of hellos that are temporary unless confirmed via PONG
 * (used to give the transport module the required information for the
 * PING).
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_core.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "identity.h"
#include "hostkey.h"

#define DEBUG_IDENTITY NO

#define MAX_TEMP_HOSTS 32

#define TRUSTDIR "data/credit/"
#define HOST_DIR "data/hosts/"

/**
 * Masks to keep track when the trust has changed and
 * to get the real trust value.
 */
#define TRUST_REFRESH_MASK 0x80000000

#define TRUST_ACTUAL_MASK  0x7FFFFFFF

#define MAX_DATA_HOST_FREQ (5 * cronMINUTES)

#define CRON_DATA_HOST_FREQ (15 * cronMINUTES)

#define CRON_TRUST_FLUSH_FREQ (5 * cronMINUTES)

#define CRON_DISCARD_HOSTS_INTERVAL (cronDAYS)

#define CRON_DISCARDS_HOSTS_AFTER (3 * cronMONTHS)

typedef struct {

  PeerIdentity identity;

  /**
   * How long is this host blacklisted? (if at all)
   */
  cron_t until;

  /**
   * what would be the next increment for blacklisting?
   */
  cron_t delta;

  /**
   * hellos for the peer (maybe NULL)!
   */
  P2P_hello_MESSAGE ** hellos;

  unsigned int helloCount;

  /**
   * for which protocols is this host known?
   */
  unsigned short * protocols;

  unsigned int protocolCount;

  /**
   * should we also reject incoming messages? (YES/NO)
   */
  int strict;

  /**
   * trust rating for this peer
   */
  unsigned int trust;

} HostEntry;

/**
 * The list of known hosts.
 */
static HostEntry ** hosts_ = NULL;

/**
 * The current (allocated) size of knownHosts
 */
static unsigned int sizeOfHosts_ = 0;

/**
 * The number of actual entries in knownHosts
 */
static unsigned int numberOfHosts_;

/**
 * A lock for accessing knownHosts
 */
static struct MUTEX * lock_;

/**
 * Directory where the hellos are stored in (data/hosts)
 */
static char * networkIdDirectory;

/**
 * Where do we store trust information?
 */
static char * trustDirectory;

/**
 * The list of temporarily known hosts
 */
static HostEntry tempHosts[MAX_TEMP_HOSTS];

static PeerIdentity myIdentity;

static struct GE_Context * ectx;

static CoreAPIForApplication * coreAPI;

/**
 * Get the filename under which we would store the P2P_hello_MESSAGE
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID.PROTOCOL
 */
static char * getHostFileName(const PeerIdentity * id,
			      unsigned short protocol) {
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
 * Find the host entry for the given peer.  Call
 * only when synchronized!
 * @return NULL if not found
 */
static HostEntry * findHost(const PeerIdentity * id) {
  int i;

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  for (i=0;i<numberOfHosts_;i++)
    if ( (0 == memcmp(id,
		      &hosts_[i]->identity,
		      sizeof(PeerIdentity))) )
      return hosts_[i];
  return NULL;
}

/**
 * Add a host to the list.
 *
 * @param identity the identity of the host
 * @param protocol the protocol for the host
 */
static void addHostToKnown(const PeerIdentity * identity,
			   unsigned short protocol) {
  HostEntry * entry;
  int i;
  EncName fil;
  char * fn;
  unsigned int trust;

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    entry = MALLOC(sizeof(HostEntry));

    entry->identity = *identity;
    entry->until    = 0;
    entry->delta    = 30 * cronSECONDS;
    entry->protocols = NULL;
    entry->protocolCount = 0;
    entry->strict    = NO;
    entry->hellos     = NULL;
    entry->helloCount = 0;
    hash2enc(&identity->hashPubKey,
	     &fil);
    fn = MALLOC(strlen(trustDirectory)+sizeof(EncName)+1);
    strcpy(fn, trustDirectory);
    strcat(fn, (char*) &fil);
    if ( (disk_file_test(ectx,
			 fn) == YES) &&
	 (sizeof(unsigned int) ==
	  disk_file_read(ectx,
			 fn,
			 sizeof(unsigned int),
			 &trust)) ) {
      entry->trust = ntohl(trust);
    } else {
      entry->trust = 0;
    }
    FREE(fn);

    if (numberOfHosts_ == sizeOfHosts_)
      GROW(hosts_,
	   sizeOfHosts_,
	   sizeOfHosts_+32);
    hosts_[numberOfHosts_++] = entry;
  }
  for (i=0;i<entry->protocolCount;i++) {
    if (entry->protocols[i] == protocol) {
      MUTEX_UNLOCK(lock_);
      return; /* already there */
    }
  }
  GROW(entry->protocols,
       entry->protocolCount,
       entry->protocolCount+1);
  entry->protocols[entry->protocolCount-1]
    = protocol;
  MUTEX_UNLOCK(lock_);
}

/**
 * Increase the host credit by a value.
 *
 * @param hostId is the identity of the host
 * @param value is the int value by which the
 *  host credit is to be increased or decreased
 * @returns the actual change in trust (positive or negative)
 */
static int changeHostTrust(const PeerIdentity * hostId,
			   int value){
  HostEntry * host;

  if (value == 0)
    return 0;

  MUTEX_LOCK(lock_);
  host = findHost(hostId);
  if (host == NULL) {
    addHostToKnown(hostId,
		   NAT_PROTOCOL_NUMBER);
    host = findHost(hostId);
    if (host == NULL) {
      GE_BREAK(ectx, 0);
      MUTEX_UNLOCK(lock_);
      return 0;
    }
  }
  if ( ((int) (host->trust & TRUST_ACTUAL_MASK)) + value < 0) {
    value = - (host->trust & TRUST_ACTUAL_MASK);
    host->trust = 0
      | TRUST_REFRESH_MASK; /* 0 remaining */
  } else {
    host->trust = ( (host->trust & TRUST_ACTUAL_MASK) + value)
      | TRUST_REFRESH_MASK;
  }
  MUTEX_UNLOCK(lock_);
  return value;
}

/**
 * Obtain the trust record of a peer.
 *
 * @param hostId the identity of the peer
 * @return the amount of trust we currently have in that peer
 */
static unsigned int getHostTrust(const PeerIdentity * hostId) {
  HostEntry * host;
  unsigned int trust;

  MUTEX_LOCK(lock_);
  host = findHost(hostId);
  if (host == NULL)
    trust = 0;
  else
    trust = host->trust & TRUST_ACTUAL_MASK;
  MUTEX_UNLOCK(lock_);
  return trust;
}


static int cronHelper(const char * filename,
		      const char * dirname,
		      void * unused) {
  PeerIdentity identity;
  EncName id;
  unsigned int protoNumber;
  char * fullname;

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  GE_ASSERT(ectx, sizeof(EncName) == 104);
  if (2 == sscanf(filename,
		  "%103c.%u",
		  (char*)&id,
		  &protoNumber)) {
    id.encoding[sizeof(EncName)-1] = '\0';
    if (OK == enc2hash((char*)&id,
		       &identity.hashPubKey)) {
      addHostToKnown(&identity,
		     (unsigned short) protoNumber);
      return OK;
    }
  }

  fullname = MALLOC(strlen(filename) +
		    strlen(networkIdDirectory) + 1);
  strcpy(fullname, networkIdDirectory);
  strcat(fullname, filename);
  if (disk_file_test(ectx, fullname) == YES) {
    if (0 == UNLINK(fullname))
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
	     _("File `%s' in directory `%s' does not match naming convention. "
	       "Removed.\n"),
	     filename,
	     networkIdDirectory);
    else
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_USER | GE_BULK,
			   "unlink",
			   fullname);
  } else if (disk_directory_test(ectx, fullname) == YES) {
    if (0 == RMDIR(fullname))
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
	     _("Directory `%s' in directory `%s' does not match naming convention. "
	       "Removed.\n"),
	     filename,
	     networkIdDirectory);
    else
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_USER | GE_BULK,
			   "rmdir",
			   fullname);
  }
  FREE(fullname);
  return OK;
}

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void cronScanDirectoryDataHosts(void * unused) {
  static cron_t lastRun;
  static int retries;
  int count;
  cron_t now;

  now = get_time();
  if (lastRun + MAX_DATA_HOST_FREQ > now)
    return; /* prevent scanning more than
	       once every 5 min */
  lastRun = now;
  count = disk_directory_scan(ectx,
			      networkIdDirectory,
			      &cronHelper,
			      NULL);
  if (count <= 0) {
    retries++;
    if ((retries & 32) > 0) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Still no peers found in `%s'!\n"),
	     networkIdDirectory);
    }
  }
  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
}


/**
 * Obtain identity from publicPrivateKey.
 * @param pubKey the public key of the host
 * @param result address where to write the identity of the node
 */
static void getPeerIdentity(const PublicKey * pubKey,
			    PeerIdentity * result) {
  if (pubKey == NULL) {
    memset(&result,
	   0,
	   sizeof(PeerIdentity));
  } else {
    hash(pubKey,
	 sizeof(PublicKey),
	 &result->hashPubKey);
  }
}

/**
 * Add a host to the temporary list.
 */
static void addHostTemporarily(const P2P_hello_MESSAGE * tmp) {
  static int tempHostsNextSlot;
  P2P_hello_MESSAGE * msg;
  HostEntry * entry;
  int i;
  int slot;
  PeerIdentity have;

  getPeerIdentity(&tmp->publicKey,
		  &have);
  if (0 != memcmp(&have,
		  &tmp->senderIdentity,
		  sizeof(PeerIdentity))) {
    GE_BREAK(NULL, 0);
    return;
  }
  MUTEX_LOCK(lock_);
  entry = findHost(&tmp->senderIdentity);
  if ( (entry != NULL) &&
       (entry->helloCount > 0) ) {
    MUTEX_UNLOCK(lock_);
    return;
  }
  msg = MALLOC(P2P_hello_MESSAGE_size(tmp));
  memcpy(msg,
	 tmp,
	 P2P_hello_MESSAGE_size(tmp));
  slot = tempHostsNextSlot;
  for (i=0;i<MAX_TEMP_HOSTS;i++)
    if (0 == memcmp(&tmp->senderIdentity,
		    &tempHosts[i].identity,
		    sizeof(PeerIdentity)))
      slot = i;
  if (slot == tempHostsNextSlot) {
    tempHostsNextSlot++;
    if (tempHostsNextSlot >= MAX_TEMP_HOSTS)
      tempHostsNextSlot = 0;
  }
  entry = &tempHosts[slot];
  entry->identity = msg->senderIdentity;
  entry->until = 0;
  entry->delta = 0;
  for (i=0;i<entry->helloCount;i++)
    FREE(entry->hellos[i]);
  GROW(entry->hellos,
       entry->helloCount,
       1);
  GROW(entry->protocols,
       entry->protocolCount,
       1);
  entry->hellos[0] = msg;
  entry->protocols[0] = ntohs(msg->protocol);
  entry->strict = NO;
  entry->trust = 0;  
  MUTEX_UNLOCK(lock_);
}

/**
 * Delete a host from the list.
 */
static void delHostFromKnown(const PeerIdentity * identity,
			     unsigned short protocol) {
  HostEntry * entry;
  char * fn;
  int i;
  int j;

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  GE_ASSERT(ectx, protocol != ANY_PROTOCOL_NUMBER);
  MUTEX_LOCK(lock_);
  for (i=0;i<numberOfHosts_;i++) {
    if ( (0 == memcmp(identity,
		      &hosts_[i]->identity,
		      sizeof(PeerIdentity))) ) {
      entry = hosts_[i];
      for (j=0;j<entry->protocolCount;j++) {
	if (protocol == entry->protocols[j]) {
	  entry->protocols[j]
	    = entry->protocols[entry->protocolCount-1];
	  GROW(entry->protocols,
	       entry->protocolCount,
	       entry->protocolCount-1);
	}
      }
      for (j=0;j<entry->helloCount;j++) {
	if (protocol == ntohs(entry->hellos[j]->protocol)) {
	  FREE(entry->hellos[j]);
	  entry->hellos[j]
	    = entry->hellos[entry->helloCount-1];
	  GROW(entry->hellos,
	       entry->helloCount,
	       entry->helloCount-1);
	}
      }
      /* also remove hello file itself */
      fn = getHostFileName(identity,
			   protocol);
      if (0 != UNLINK(fn))
	GE_LOG_STRERROR_FILE(ectx,
			     GE_WARNING | GE_USER | GE_BULK,
			     "unlink",
			     fn);
      FREE(fn);

      if (entry->protocolCount == 0) {
	if (entry->helloCount > 0) {
	  for (j=0;j<entry->helloCount;j++)
	    FREE(entry->hellos[j]);
	  GROW(entry->hellos,
	       entry->helloCount,
	       0);
	}
	hosts_[i] = hosts_[--numberOfHosts_];
	FREE(entry);
      }
      MUTEX_UNLOCK(lock_);
      GE_ASSERT(ectx,
		numberOfHosts_ <= sizeOfHosts_);
      return; /* deleted */
    }
  }
  MUTEX_UNLOCK(lock_);
}

/**
 * Bind a host address (hello) to a hostId.
 * @param msg the verified (!) hello message
 */
static void bindAddress(const P2P_hello_MESSAGE * msg) {
  char * fn;
  char * buffer;
  P2P_hello_MESSAGE * oldMsg;
  int size;
  HostEntry * host;
  int i;
  PeerIdentity have;

  getPeerIdentity(&msg->publicKey,
		  &have);
  if (0 != memcmp(&have,
		  &msg->senderIdentity,
		  sizeof(PeerIdentity))) {
    GE_BREAK(NULL, 0);
    return;
  }
  GE_ASSERT(ectx,
	    numberOfHosts_ <= sizeOfHosts_);
  GE_ASSERT(ectx,
	    msg != NULL);
  fn = getHostFileName(&msg->senderIdentity,
		       ntohs(msg->protocol));
  buffer = MALLOC(MAX_BUFFER_SIZE);
  if (disk_file_test(ectx,
		     fn) == YES) {
    size = disk_file_read(ectx,
			  fn,
			  MAX_BUFFER_SIZE,
			  buffer);
    if (size >= sizeof(P2P_hello_MESSAGE)) {
      oldMsg = (P2P_hello_MESSAGE*) buffer;
      if ((unsigned int)size == P2P_hello_MESSAGE_size(oldMsg)) {
	if (ntohl(oldMsg->expirationTime) > ntohl(msg->expirationTime)) {
	  FREE(fn);
	  FREE(buffer);
	  return; /* have more recent hello in stock */
	}
      }
    }
  }
  disk_file_write(ectx,
		  fn,
		  msg,
		  P2P_hello_MESSAGE_size(msg),
		  "644");
  FREE(fn);
  FREE(buffer);

  MUTEX_LOCK(lock_);
  addHostToKnown(&msg->senderIdentity,
		 ntohs(msg->protocol));
  host = findHost(&msg->senderIdentity);
  GE_ASSERT(ectx,
	    host != NULL);

  for (i=0;i<host->helloCount;i++) {
    if (msg->protocol == host->hellos[i]->protocol) {
      FREE(host->hellos[i]);
      host->hellos[i] = NULL;
      break;
    }
  }
  if (i == host->helloCount)
    GROW(host->hellos,
	 host->helloCount,
	 host->helloCount+1);
  host->hellos[i]
    = MALLOC(P2P_hello_MESSAGE_size(msg));
  memcpy(host->hellos[i],
	 msg,
	 P2P_hello_MESSAGE_size(msg));
  MUTEX_UNLOCK(lock_);
  GE_ASSERT(ectx,
	    numberOfHosts_ <= sizeOfHosts_);
}

/**
 * Obtain the public key and address of a known host.  If no specific
 * protocol is specified (ANY_PROTOCOL_NUMBER), hellos for cheaper
 * protocols are returned with preference (randomness!).
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        ANY_PROTOCOL_NUMBER if we do not care which protocol
 * @param tryTemporaryList is it ok to check the unverified hellos?
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 */
static P2P_hello_MESSAGE *
identity2Hello(const PeerIdentity *  hostId,
	       unsigned short protocol,
	       int tryTemporaryList) {
  P2P_hello_MESSAGE * result;
  HostEntry * host;
  char * fn;
  P2P_hello_MESSAGE buffer;
  PeerIdentity have;
  int size;
  int i;
  int j;

  GE_ASSERT(ectx,
	    numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(lock_);
  if (YES == tryTemporaryList) {
    /* ok, then first try temporary hosts
       (in memory, cheapest!) */
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      host = &tempHosts[i];
      if ( (host->helloCount > 0) &&
	   (0 == memcmp(hostId,
			&host->identity,
			sizeof(PeerIdentity))) ) {
	if (protocol == ANY_PROTOCOL_NUMBER) {
	  j = weak_randomi(host->helloCount);
	} else {
	  j = 0;
	  while ( (j < host->helloCount) &&
		  (host->protocols[j] != protocol) )
	    j++;
	}
	if (j == host->helloCount) {
	  /* not found */
	  MUTEX_UNLOCK(lock_);
	  return NULL;	
	}
	result = MALLOC(P2P_hello_MESSAGE_size(host->hellos[j]));
	memcpy(result,
	       host->hellos[j],
	       P2P_hello_MESSAGE_size(host->hellos[j]));
	MUTEX_UNLOCK(lock_);
	return result;
      }
    }
  }

  host = findHost(hostId);
  if ( (host == NULL) ||
       (host->protocolCount == 0) ) {
    MUTEX_UNLOCK(lock_);
    return NULL;
  }

  if (protocol == ANY_PROTOCOL_NUMBER)
    protocol = host->protocols[weak_randomi(host->protocolCount)];

  for (i=0;i<host->helloCount;i++) {
    if (ntohs(host->hellos[i]->protocol) == protocol) {
      result
	= MALLOC(P2P_hello_MESSAGE_size(host->hellos[i]));
      memcpy(result,
	     host->hellos[i],
	     P2P_hello_MESSAGE_size(host->hellos[i]));
      MUTEX_UNLOCK(lock_);
      return result;
    }
  }

  /* do direct read */
  fn = getHostFileName(hostId,
		       protocol);
  if (1 != disk_file_test(ectx,
			  fn)) {
    FREE(fn);
    MUTEX_UNLOCK(lock_);
    return NULL;
  }
  size = disk_file_read(ectx,
			fn,
			sizeof(P2P_hello_MESSAGE),
			&buffer);
  if (size != sizeof(P2P_hello_MESSAGE)) {
    if (0 == UNLINK(fn))
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Removed file `%s' containing invalid HELLO data.\n"),
	     fn);
    else
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
			   "unlink",
			   fn);
    FREE(fn);
    MUTEX_UNLOCK(lock_);
    return NULL;
  }
  result = MALLOC(P2P_hello_MESSAGE_size(&buffer));
  size = disk_file_read(ectx,
			fn,
			P2P_hello_MESSAGE_size(&buffer),
			result);
  getPeerIdentity(&result->publicKey,
		  &have);
  if ( ((unsigned int)size != P2P_hello_MESSAGE_size(&buffer)) ||
       (0 != memcmp(&have,
		    hostId,
		    sizeof(PeerIdentity))) ||
       (0 != memcmp(&have,
		    &result->senderIdentity,
		    sizeof(PeerIdentity))) ) {
    if (0 == UNLINK(fn))
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Removed file `%s' containing invalid HELLO data.\n"),
	     fn);
    else
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
			   "unlink",
			   fn);
    FREE(fn);
    FREE(result);
    MUTEX_UNLOCK(lock_);
    return NULL;
  }
  FREE(fn);
  GROW(host->hellos,
       host->helloCount,
       host->helloCount+1);
  host->hellos[host->helloCount-1]
    = MALLOC(P2P_hello_MESSAGE_size(&buffer));
  memcpy(host->hellos[host->helloCount-1],
	 result,
	 P2P_hello_MESSAGE_size(&buffer));
  MUTEX_UNLOCK(lock_);
  return result;
}


/**
 * @param signer the identity of the host that
 *        presumably signed the message
 * @param message the signed message
 * @param size the size of the message
 * @param sig the signature
 * @return OK on success, SYSERR on error (verification failed)
 */
static int verifyPeerSignature(const PeerIdentity * signer,
			       const void * message,
			       int size,
			       const Signature * sig) {
  P2P_hello_MESSAGE * hello;
  int res;

  hello = identity2Hello(signer,
		       ANY_PROTOCOL_NUMBER,
		       YES);
  if (hello == NULL) {
#if DEBUG_IDENTITY
    EncName enc;

    IF_GELOG(ectx,
	     GE_INFO | GE_USER | GE_BULK,
	     hash2enc(&signer->hashPubKey,
		      &enc));
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   _("Signature failed verification: peer `%s' not known.\n"),
	   &enc);
#endif
    return SYSERR;
  }
  res = verifySig(message, size, sig,
		  &hello->publicKey);
  if (res == SYSERR)
    GE_LOG(ectx,
	   GE_ERROR | GE_REQUEST | GE_DEVELOPER | GE_USER,
	   _("Signature failed verification: signature invalid.\n"));
  FREE(hello);
  return res;
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
static int blacklistHost(const PeerIdentity * identity,
			 unsigned int desperation,
			 int strict) {
  EncName hn;
  HostEntry * entry;
  int i;

  GE_ASSERT(ectx,
	    numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if (0 == memcmp(identity,
		      &tempHosts[i].identity,
		      sizeof(PeerIdentity))) {
	entry = &tempHosts[i];
	break;
      }
    }
  }
  if (entry == NULL) {
    MUTEX_UNLOCK(lock_);
    return SYSERR;
  }
  if (strict == YES) {
    /* Presumably runs a broken version of GNUnet;
       blacklist for 1 day (we hope the other peer
       updates the software eventually...) */
    entry->delta = 1 * cronDAYS;
  } else {
    entry->delta
      = entry->delta + weak_randomi(1+desperation*cronSECONDS);
    if (entry->delta > 4 * cronHOURS)
      entry->delta = 4 * cronHOURS;
  }
  entry->until = get_time() + entry->delta;
  entry->strict = strict;
  hash2enc(&identity->hashPubKey,
	   &hn);
#if DEBUG_IDENTITY
  GE_LOG(ectx,
	 GE_INFO | GE_REQUEST | GE_USER,
	 "Blacklisting host `%s' for %llu seconds"
	 " until %llu (strict=%d).\n",
	 &hn,
	 entry->delta / cronSECONDS,
	 entry->until,
	 strict);
#endif
  MUTEX_UNLOCK(lock_);
  return OK;
}

/**
 * Is the host currently 'strictly' blacklisted (i.e. we refuse to talk)?
 *
 * @param identity host to check
 * @return YES if true, else NO
 */
static int isBlacklistedStrict(const PeerIdentity * identity) {
  cron_t now;
  HostEntry * entry;

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    MUTEX_UNLOCK(lock_);
    return NO;
  }
  now = get_time();
  if ( (now < entry->until) &&
       (entry->strict == YES) ) {
    MUTEX_UNLOCK(lock_);
    return YES;
  } else {
    MUTEX_UNLOCK(lock_);
    return NO;
  }
}

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return OK on success SYSERR on error
 */
static int whitelistHost(const PeerIdentity * identity) {
  HostEntry * entry;
  int i;
#if DEBUG_IDENTITY
  EncName enc;
#endif

  GE_ASSERT(ectx, numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if (0 == memcmp(identity,
		      &tempHosts[i].identity,
		      sizeof(PeerIdentity))) {
	entry = &tempHosts[i];
	break;
      }
    }
  }
  if (entry == NULL) {
    MUTEX_UNLOCK(lock_);
    return SYSERR;
  }
#if DEBUG_IDENTITY
  IF_GELOG(ectx, GE_INFO | GE_REQUEST | GE_USER,
	hash2enc(&identity->hashPubKey,
		 &enc));
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 "Whitelisting host `%s'\n",
	 &enc);
#endif
  entry->delta = 30 * cronSECONDS;
  entry->until = 0;
  entry->strict = NO;
  MUTEX_UNLOCK(lock_);
  return OK;
}

/**
 * Call a method for each known host.
 *
 * @param callback the method to call for each host
 * @param now the time to use for excluding hosts
 *        due to blacklisting, use 0
 *        to go through all hosts.
 * @param data an argument to pass to the method
 * @return the number of hosts matching
 */
static int forEachHost(cron_t now,
		       HostIterator callback,
		       void * data) {
  int i;
  int j;
  int count;
  PeerIdentity hi;
  unsigned short proto;
  HostEntry * entry;
  int ret;

  ret = OK;
  GE_ASSERT(ectx,
	    numberOfHosts_ <= sizeOfHosts_);
  count = 0;
  MUTEX_LOCK(lock_);
  for (i=0;i<numberOfHosts_;i++) {
    entry = hosts_[i];
    if (0 == memcmp(&entry->identity,
		    &myIdentity,
		    sizeof(PeerIdentity)))
      continue;
    if ( (now == 0) ||
	 (now >= entry->until) ) {
      count++;
      if (callback != NULL) {
	hi = entry->identity;
	for (j=0;j<entry->protocolCount;j++) {
	  proto = entry->protocols[j];
	  MUTEX_UNLOCK(lock_);
	  ret = callback(&hi,
			 proto,
			 YES,
			 data);
	  MUTEX_LOCK(lock_);
	  if (ret != OK)
	    break;
	  /* we gave up the lock,
	     need to re-acquire entry (if possible)! */
	  if (i >= numberOfHosts_)
	    break;
	  entry = hosts_[i];
	  if (0 == memcmp(&entry->identity,
			  &myIdentity,
			  sizeof(PeerIdentity)))
	    break;
	}
      }
    }
    if (ret != OK)
      break;

  }
  for (i=0;i<MAX_TEMP_HOSTS;i++) {
    if (ret != OK)
      break;
    entry = &tempHosts[i];
    if (entry->helloCount == 0)
      continue;
    if ( (now == 0) ||
	 (now >= entry->until) ) {
      count++;
      if (callback != NULL) {
	hi = entry->identity;
	proto = entry->protocols[0];
	MUTEX_UNLOCK(lock_);
	ret = callback(&hi,
		       proto,
		       YES,
		       data);
	MUTEX_LOCK(lock_);
      }
    }
  }
  MUTEX_UNLOCK(lock_);
  return count;
}

/**
 * Write host-trust information to a file - flush the buffer entry!
 * Assumes synchronized access.
 */
static void flushHostCredit(HostEntry * host) {
  EncName fil;
  char * fn;
  unsigned int trust;

  if ((host->trust & TRUST_REFRESH_MASK) == 0)
    return; /* unchanged */
  host->trust = host->trust & TRUST_ACTUAL_MASK;
  hash2enc(&host->identity.hashPubKey,
	   &fil);
  fn = MALLOC(strlen(trustDirectory)+sizeof(EncName)+1);
  strcpy(fn, trustDirectory);
  strcat(fn, (char*) &fil);
  if (host->trust == 0) {
    if ( (0 != UNLINK(fn)) &&
	 (errno != ENOENT) )
      GE_LOG_STRERROR_FILE(ectx,
			   GE_WARNING | GE_USER | GE_BULK,			
			   "unlink",
			   fn);
  } else {
    trust = htonl(host->trust);
    disk_file_write(ectx,
		    fn,
		    &trust,
		    sizeof(unsigned int),
		    "644");
  }
  FREE(fn);
}

/**
 * Call once in a while to synchronize trust values with the disk.
 */
static void cronFlushTrustBuffer(void * unused) {
  int i;
  MUTEX_LOCK(lock_);
  for (i=0;i<numberOfHosts_;i++)
    flushHostCredit(hosts_[i]);
  MUTEX_UNLOCK(lock_);
}

/**
 * @brief delete expired HELLO entries in data/hosts/
 */
static int discardHostsHelper(const char *filename,
			      const char *dirname,
			      void *now) {
  char *fn;
  struct stat hostStat;
  int hostFile;

  fn = MALLOC(strlen(filename) + strlen(dirname) + 2);
  sprintf(fn,
	  "%s%s%s",
	  dirname,
	  DIR_SEPARATOR_STR,
	  filename);
  hostFile = disk_file_open(ectx,
			    fn,
			    O_WRONLY);
  if (hostFile != -1) {
    if (FSTAT(hostFile, &hostStat) == 0) {
      CLOSE(hostFile);

      if (hostStat.st_mtime + (CRON_DISCARDS_HOSTS_AFTER / cronSECONDS) < *((time_t *) now))
        UNLINK(fn);
    }
  }
  FREE(fn);

  return OK;
}

/**
 * @brief scan host directory for expired entries
 */
static void cronDiscardHosts(void *unused) {
  time_t timeNow;

  timeNow = time(NULL);
  disk_directory_scan(ectx,
		      networkIdDirectory,
		      &discardHostsHelper,
		      (void *) &timeNow);
}


static int identityRequestConnectHandler(struct ClientHandle * sock,
					 const MESSAGE_HEADER * message) {
  const CS_identity_connect_MESSAGE * msg;
  int ret;

  if (sizeof(CS_identity_connect_MESSAGE) != ntohs(message->size))
    return SYSERR;
  msg = (const CS_identity_connect_MESSAGE*) message;
  coreAPI->unicast(&msg->other,
		   NULL,
		   0,
		   0);
  ret = coreAPI->queryPeerStatus(&msg->other,
				 NULL,
				 NULL);
  return coreAPI->sendValueToClient(sock,
				    ret != OK ? NO : YES);
}

static int identityHelloHandler(struct ClientHandle * sock,
				const MESSAGE_HEADER * message) {
  const P2P_hello_MESSAGE * msg;
  P2P_hello_MESSAGE * hello;

  if (sizeof(P2P_hello_MESSAGE) > ntohs(message->size)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  msg = (const P2P_hello_MESSAGE*) message;
  if (P2P_hello_MESSAGE_size(msg) != ntohs(message->size)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  hello = MALLOC(ntohs(msg->header.size));
  memcpy(hello,
	 msg,
	 ntohs(msg->header.size));
  hello->header.type = htons(p2p_PROTO_hello);
  coreAPI->injectMessage(NULL,
			 (const char*) hello,
			 ntohs(msg->header.size),
			 NO,
			 NULL);
  FREE(hello);
  return OK;
}

static int identityRequestHelloHandler(struct ClientHandle * sock,
				       const MESSAGE_HEADER * message) {
  /* transport types in order of preference
     for location URIs (by best guess at what
     people are most likely to actually run) */
  static unsigned short types[] = {
    TCP_PROTOCOL_NUMBER,
    UDP_PROTOCOL_NUMBER,
    HTTP_PROTOCOL_NUMBER,
    TCP6_PROTOCOL_NUMBER,
    UDP6_PROTOCOL_NUMBER,
    SMTP_PROTOCOL_NUMBER,
    NAT_PROTOCOL_NUMBER,
    0,
  };
  Transport_ServiceAPI * tapi;
  P2P_hello_MESSAGE * hello;
  int pos;
  int ret;

  /* we cannot permanently load transport
     since that would cause a cyclic dependency;
     however, we can request it briefly here */
  tapi = coreAPI->requestService("transport");
  if (tapi == NULL)
    return SYSERR;
  hello = NULL;
  pos = 0;
  while ( (hello == NULL) &&
	  (types[pos] != 0) )
    hello = tapi->createhello(types[pos++]);
  coreAPI->releaseService(tapi);
  if (hello == NULL)
    return SYSERR;
  hello->header.type = htons(CS_PROTO_identity_HELLO);
  ret = coreAPI->sendToClient(sock,
			      &hello->header);
  FREE(hello);
  return ret;
}

static int identityRequestSignatureHandler(struct ClientHandle * sock,
					   const MESSAGE_HEADER * message) {
  CS_identity_signature_MESSAGE reply;

  if (ntohs(message->size) <= sizeof(MESSAGE_HEADER))
    return SYSERR;
  reply.header.size = htons(sizeof(CS_identity_signature_MESSAGE));
  reply.header.type = htons(CS_PROTO_identity_SIGNATURE);
  if (OK != signData(&message[1],
		     ntohs(message->size) - sizeof(MESSAGE_HEADER),
		     &reply.sig))
    return SYSERR;
  return coreAPI->sendToClient(sock,
			       &reply.header);
}

static int hostInfoIterator(const PeerIdentity * identity,
			    unsigned short protocol,
			    int confirmed,
			    void * data) {
  struct ClientHandle * sock = data;
  Transport_ServiceAPI * transport;
  CS_identity_peer_info_MESSAGE * reply;
  P2P_hello_MESSAGE * hello;
  void * address;
  int ret;
  unsigned int len;
  unsigned int bpm;
  cron_t last;

  if (confirmed == NO)
    return OK;
  hello = identity2Hello(identity,
			 protocol,
			 YES);
  if (hello == NULL) 
    return OK; /* ignore -- happens if HELLO just expired */
  transport = coreAPI->requestService("transport");
  len = 0;
  address = NULL;
  transport->helloToAddress(hello,
			    &address,
			    &len);
  FREE(hello);
  coreAPI->releaseService(transport);
  if (len >= MAX_BUFFER_SIZE - sizeof(CS_identity_peer_info_MESSAGE) ) {
    FREE(address);
    address = NULL;
    len = 0;
  }
  if (OK != coreAPI->queryPeerStatus(identity,
				     &bpm,
				     &last)) {
    last = 0;
    bpm = 0;
  }
  reply = MALLOC(sizeof(CS_identity_peer_info_MESSAGE) + len);
  reply->header.size = htons(sizeof(CS_identity_peer_info_MESSAGE) + len);
  reply->header.type = htons(CS_PROTO_identity_INFO);
  reply->peer = *identity;
  reply->last_message = htonll(last);
  reply->trust = htonl(getHostTrust(identity));
  reply->bpm = htonl(bpm);
  memcpy(&reply[1],
	 address,
	 len);
  FREENONNULL(address);
  ret = coreAPI->sendToClient(sock,
			      &reply->header);
  FREE(reply);
  return ret;
}

static int identityRequestInfoHandler(struct ClientHandle * sock,
				      const MESSAGE_HEADER * message) {
  forEachHost(0,
	      &hostInfoIterator,
	      sock);
  return coreAPI->sendValueToClient(sock,
				    OK);
}


/**
 * Provide the Identity service.
 *
 * @param capi the core API
 * @return NULL on errors, ID_API otherwise
 */
Identity_ServiceAPI *
provide_module_identity(CoreAPIForApplication * capi) {
  static Identity_ServiceAPI id;
  char * gnHome;
  char * tmp;
  int i;

  coreAPI = capi;
  ectx = coreAPI->ectx;
  id.getPublicPrivateKey = &getPublicPrivateKey;
  id.getPeerIdentity     = &getPeerIdentity;
  id.signData            = &signData;
  id.decryptData         = &decryptData;
  id.delHostFromKnown    = &delHostFromKnown;
  id.addHostTemporarily  = &addHostTemporarily;
  id.addHost             = &bindAddress;
  id.forEachHost         = &forEachHost;
  id.identity2Hello      = &identity2Hello;
  id.verifyPeerSignature = &verifyPeerSignature;
  id.blacklistHost       = &blacklistHost;
  id.isBlacklistedStrict = &isBlacklistedStrict;
  id.whitelistHost       = &whitelistHost;
  id.changeHostTrust     = &changeHostTrust;
  id.getHostTrust        = &getHostTrust;

  for (i=0;i<MAX_TEMP_HOSTS;i++)
    memset(&tempHosts[i],
	   0,
	   sizeof(HostEntry));
  numberOfHosts_ = 0;

  gnHome = NULL;
  GE_ASSERT(ectx,
	    -1 != GC_get_configuration_value_filename(coreAPI->cfg,
						      "GNUNETD",
						      "GNUNETD_HOME",
						      VAR_DAEMON_DIRECTORY,
						      &gnHome));
  if (gnHome == NULL)
    return NULL;
  disk_directory_create(ectx, gnHome);
  tmp = MALLOC(strlen(gnHome) + strlen(HOST_DIR) + 2);
  strcpy(tmp, gnHome);
  strcat(tmp, DIR_SEPARATOR_STR);
  strcat(tmp, HOST_DIR);
  networkIdDirectory = NULL;
  GE_ASSERT(ectx,
	    -1 != GC_get_configuration_value_filename(coreAPI->cfg,
						      "GNUNETD",
						      "HOSTS",
						      tmp,
						      &networkIdDirectory));
  FREE(tmp);
  disk_directory_create(ectx,
			networkIdDirectory);
  trustDirectory = MALLOC(strlen(gnHome) +
			  strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  strcat(trustDirectory, DIR_SEPARATOR_STR);
  strcat(trustDirectory, TRUSTDIR);
  disk_directory_create(ectx,
			trustDirectory);
  FREE(gnHome);

  lock_ = MUTEX_CREATE(YES);
  initPrivateKey(capi->ectx,
		 capi->cfg);
  getPeerIdentity(getPublicPrivateKey(),
		  &myIdentity);
  cronScanDirectoryDataHosts(NULL);
  cron_add_job(coreAPI->cron,
	       &cronScanDirectoryDataHosts,
	       CRON_DATA_HOST_FREQ,
	       CRON_DATA_HOST_FREQ,
	       NULL);
  cron_add_job(coreAPI->cron,
	       &cronFlushTrustBuffer,
	       CRON_TRUST_FLUSH_FREQ,
	       CRON_TRUST_FLUSH_FREQ,
	       NULL);
  cron_add_job(coreAPI->cron,
	       &cronDiscardHosts,
	       0,
	       CRON_DISCARD_HOSTS_INTERVAL,
	       NULL);
  coreAPI->registerClientHandler(CS_PROTO_identity_CONNECT,
				   &identityRequestConnectHandler);
  coreAPI->registerClientHandler(CS_PROTO_identity_HELLO,
				 &identityHelloHandler);
  coreAPI->registerClientHandler(CS_PROTO_identity_request_HELLO,
				 &identityRequestHelloHandler);
  coreAPI->registerClientHandler(CS_PROTO_identity_request_SIGN,
				 &identityRequestSignatureHandler);
  coreAPI->registerClientHandler(CS_PROTO_identity_request_INFO,
				 &identityRequestInfoHandler);
  return &id;
}

/**
 * Shutdown Identity service.
 */
void release_module_identity() {
  int i;
  int j;
  HostEntry * entry;

  coreAPI->unregisterClientHandler(CS_PROTO_identity_CONNECT,
				   &identityRequestConnectHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_identity_HELLO,
				   &identityHelloHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_identity_request_HELLO,
				   &identityRequestHelloHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_identity_request_SIGN,
				   &identityRequestSignatureHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_identity_request_INFO,
				   &identityRequestInfoHandler);
  for (i=0;i<MAX_TEMP_HOSTS;i++) {
    entry = &tempHosts[i];
    for (j=0;j<entry->helloCount;j++)
      FREE(entry->hellos[j]);
    GROW(entry->hellos,
	 entry->helloCount,
	 0);
    GROW(entry->protocols,
	 entry->protocolCount,
	 0);
  }
  cron_del_job(coreAPI->cron,
	       &cronScanDirectoryDataHosts,
	       CRON_DATA_HOST_FREQ,
	       NULL);
  cron_del_job(coreAPI->cron,
	       &cronFlushTrustBuffer,
	       CRON_TRUST_FLUSH_FREQ,
	       NULL);
  cron_del_job(coreAPI->cron,
	       &cronDiscardHosts,
	       CRON_DISCARD_HOSTS_INTERVAL,
	       NULL);
  cronFlushTrustBuffer(NULL);
  MUTEX_DESTROY(lock_);
  lock_ = NULL;
  for (i=0;i<numberOfHosts_;i++) {
    entry = hosts_[i];
    for (j=0;j<entry->helloCount;j++)
      FREE(entry->hellos[j]);
    GROW(entry->hellos,
	 entry->helloCount,
	 0);
    GROW(entry->protocols,
	 entry->protocolCount,
	 0);
    FREE(entry);
  }
  GROW(hosts_,
       sizeOfHosts_,
       0);
  numberOfHosts_ = 0;

  FREE(networkIdDirectory);
  networkIdDirectory = NULL;
  FREE(trustDirectory);
  trustDirectory = NULL;
  donePrivateKey();
}

/* end of identity.c */
