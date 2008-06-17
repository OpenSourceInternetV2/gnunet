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
 * @file server/transport.c
 * @brief Methods to access the transport layer.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "transport.h"
#include "core.h"
#include "heloexchange.h"
#include "keyservice.h"

#define DEBUG_TRANSPORT NO

static TransportAPI ** tapis = NULL;
static int tapis_count = 0;
static int helo_live;
static Mutex tapis_lock;

/**
 * What percentage of outbound messages
 * should be randomly dropped? (for testing
 * unreliability of the network).
 */
static int percentRandomOutboundDrop = 0;	 

void setPercentRandomOutboundDrop(int value) {
  percentRandomOutboundDrop = value;
}

/**
 * Initialize the transport layer.
 */
void initTransports() {
  CoreAPIForTransport * ctapi;
  TransportAPI * tapi;
  TransportMainMethod tptr;
  char * dso;
  char * next;
  char * pos;
  void * lib;

  helo_live = getConfigurationInt("GNUNETD",
				  "HELOEXPIRES") * 60; /* minutes to seconds */
  if (helo_live > MAX_HELO_EXPIRES) 
    helo_live = MAX_HELO_EXPIRES;
  
  if (helo_live <= 0) {
    helo_live = 60 * 60;
    LOG(LOG_WARNING,
	_("Option '%s' not set in configuration in section '%s', setting to %dm.\n"),
	"HELOEXPIRES", "GNUNETD", helo_live / 60);
  }
  GROW(tapis,
       tapis_count,
       UDP_PROTOCOL_NUMBER+1);
  
  MUTEX_CREATE(&tapis_lock);
  ctapi = getCoreAPIForTransport();  

  /* now load transports */
  dso = getConfigurationString("GNUNETD",
			       "TRANSPORTS");
  if (dso == NULL || dso[0] == 0) {
    LOG(LOG_FAILURE,
	_("You should specify at least one transport service under option '%s' in section '%s'.\n"),
	"TRANSPORTS", "GNUNETD");
    return;
  }
  next = dso;
  do {
    pos = next;
    while ( (*next != '\0') &&
	    (*next != ' ') )
      next++;
    if (*next == '\0')
      next = NULL; /* terminate! */
    else {
      *next = '\0'; /* add 0-termination for pos */
      next++;
    }
    lib = loadDynamicLibrary("libgnunettransport_",
			     pos);
    tptr = bindDynamicMethod(lib,
			     "inittransport_",
			     pos);  
    if (tptr == NULL) 
      errexit(_("Transport library '%s' did not provide required function '%s%s'.\n"),
	      pos,
	      "inittransport_",
	      pos);
    tapi = tptr(ctapi);
    tapi->libHandle = lib;
    tapi->transName = STRDUP(pos);
    addTransport(tapi); 
  } while (next != NULL);
  FREE(dso);
}

/**
 * Actually start the transport services and begin
 * receiving messages.
 */
void startTransports() {
  int i;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tapis[i]->startTransportServer();
}

/**
 * Stop the transport services, stop receiving messages.
 */
void stopTransports() {  
  int i;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tapis[i]->stopTransportServer();
}

/**
 * Create signed HELO for this transport and put it into
 * the cache tapi->helo.
 */
void createSignedHELO(TransportAPI * tapi) {
  MUTEX_LOCK(&tapis_lock);
  FREENONNULL(tapi->helo);
  tapi->helo = NULL;
  if (SYSERR == tapi->createHELO(&tapi->helo)) {
    tapi->helo = NULL;
    MUTEX_UNLOCK(&tapis_lock);
    return;
  }
  memcpy(&tapi->helo->publicKey,
	 getPublicHostkey(),
	 sizeof(PublicKey));
  memcpy(&tapi->helo->senderIdentity,
	 &myIdentity,
	 sizeof(HostIdentity));
  tapi->helo->expirationTime 
    = htonl(TIME(NULL) + helo_live);
  tapi->helo->header.requestType 
    = htons(p2p_PROTO_HELO);
  tapi->helo->header.size
    = htons(HELO_Message_size(tapi->helo));
  if (SYSERR == signData(&(tapi->helo)->senderIdentity,
			 HELO_Message_size(tapi->helo) 
			 - sizeof(Signature) 
			 - sizeof(PublicKey) 
			 - sizeof(p2p_HEADER),
			 &tapi->helo->signature)) {
    FREE(tapi->helo);
    tapi->helo = NULL;
  }
  MUTEX_UNLOCK(&tapis_lock);
}

/**
 * Shutdown the transport layer.
 */
void doneTransports() {
  int i;
  void (*ptr)();

  for (i=0;i<tapis_count;i++) {
    if (tapis[i] != NULL) {
      delCronJob((CronJob)&createSignedHELO,
		 helo_live*cronSECONDS/10,
		 tapis[i]);
      ptr = bindDynamicMethod(tapis[i]->libHandle,
			      "donetransport_",
			      tapis[i]->transName);
      if (ptr != NULL)
	ptr();
      FREE(tapis[i]->transName);
      FREENONNULL(tapis[i]->helo);
      tapis[i]->helo = NULL;
      if (0 == getConfigurationInt("GNUNETD",
				   "VALGRIND"))
	/* do not unload plugins if we're using
	   valgrind */
	unloadDynamicLibrary(tapis[i]->libHandle);
    }
  }

  MUTEX_DESTROY(&tapis_lock);
  GROW(tapis,
       tapis_count,
       0);
}

/**
 * Is this transport mechanism available (for sending)?
 * @return YES or NO
 */
int isTransportAvailable(unsigned short ttype) {
  if (ttype >= tapis_count) 
    return NO;
  if (NULL == tapis[ttype])
    return NO;
  return YES;
}

/**
 * Add an implementation of a transport protocol.
 */
int addTransport(TransportAPI * tapi) {  
  if (tapi->protocolNumber >= tapis_count) 
    GROW(tapis,
	 tapis_count,
	 tapi->protocolNumber+1);
  tapis[tapi->protocolNumber] = tapi;
  tapi->helo = NULL;
  addCronJob((CronJob)&createSignedHELO,
	     helo_live*cronSECONDS/10,
	     helo_live*cronSECONDS/10,
	     tapi);
  return OK;
}

/**
 * Convert HELO to string.
 */
char * heloToString(const HELO_Message * helo) {
  TransportAPI * tapi;
  unsigned short prot;
  
  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
    return NULL;
  }
  prot = ntohs(helo->protocol);
  tapi = tapis[prot];
  if (tapi == NULL) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
     return NULL;
  } else 
    return tapi->addressToString(helo);
}


/**
 * Iterate over all available transport mechanisms.
 * @param callback the method to call on each transport API implementation
 * @param data second argument to callback
 */
void forEachTransport(TransportCallback callback,
		      void * data) {
  int i;
  
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      callback(tapis[i], data);
}

/**
 * Connect to a remote host using the advertised
 * transport layer. This may fail if the appropriate
 * transport mechanism is not available.
 *
 * @param helo the HELO of the target node. The
 *        callee is responsible for freeing the HELO (!), except
 *        if SYSERR is returned!
 * @param tsession the transport session to create
 * @return OK on success, SYSERR on error
 */
int transportConnect(HELO_Message * helo,
		     TSession ** tsession) { 
  TransportAPI * tapi;
  unsigned short prot;
  
  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
    return SYSERR;
  }
  prot = ntohs(helo->protocol);
  tapi = tapis[prot];
  if (tapi == NULL) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
     return SYSERR;
  } else {

    if (OK == tapi->connect(helo,
			    tsession)) {      
      (*tsession)->ttype = prot;
#if DEBUG_TRANSPORT
      LOG(LOG_DEBUG,
	  "Core connected to tsession %p.\n",
	  *tsession);
#endif
      return OK;
    } else
      return SYSERR;
  }
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
int transportAssociate(TSession * tsession) {
  TransportAPI * tapi;
  
  if (tsession == NULL)
    return SYSERR;
  if (tsession->ttype >= tapis_count)
    return SYSERR;
  tapi = tapis[tsession->ttype];
  if (tapi == NULL)
    return SYSERR;
  else {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG,
	"Core associates with tsession %p.\n",
	tsession);
#endif
    return tapi->associate(tsession);
  }
}


/**
 * Get the cost of a message in for the given transport mechanism.
 */
unsigned int transportGetCost(int ttype) {
  TransportAPI * tapi;
  
  if (ttype >= tapis_count)
    return SYSERR; /* -1 = INFTY */
  tapi = tapis[ttype];
  if (tapi == NULL)
    return SYSERR; /* -1 = INFTY */
  return tapi->cost;
}

/**
 * Send a message.
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC of the (plaintext) message
 * @return OK on success, SYSERR on error
 */
int transportSend(TSession * tsession,
		  const void * msg,
		  const unsigned int size,
		  int isEncrypted,
		  const int crc) {
  TransportAPI * tapi;

  if (tsession == NULL)
    return SYSERR; /* can't do that, can happen for unidirectional pipes
		      that call core with TSession being NULL. */
  if (tsession->ttype >= tapis_count) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  if ( (percentRandomOutboundDrop > 0) &&
       (percentRandomOutboundDrop > randomi(100)) )
    return OK; /* simulate 'random' network loss */
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  } else
    return tapi->send(tsession,
		      msg, 
		      size, 
		      isEncrypted,
		      crc);
}

/**
 * Send a message.  Try to be more reliable than usual.
 *
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC of the (plaintext) message
 * @return OK on success, SYSERR on error
 */
int transportSendReliable(TSession * tsession,
			  const void * msg,
			  const unsigned int size,
			  int isEncrypted,
			  const int crc) {
  TransportAPI * tapi;

  if (tsession == NULL)
    return SYSERR; /* can't do that, can happen for unidirectional pipes
		      that call core with TSession being NULL. */
  if (tsession->ttype >= tapis_count) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  else
    return tapi->sendReliable(tsession,
			      msg, 
			      size, 
			      isEncrypted,
			      crc);
}

/**
 * Close the session with the remote node.
 * @return OK on success, SYSERR on error
 */ 
int transportDisconnect(TSession * tsession) {
  TransportAPI * tapi;
  
  if (tsession == NULL) {
    BREAK();
    return SYSERR;
  }
  if (tsession->ttype >= tapis_count) {
    BREAK();
    return SYSERR;
  }
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    BREAK();
    return SYSERR;
  } else {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG,
	"Core calls disconnect on tsession %p.\n",
	tsession);
#endif
    return tapi->disconnect(tsession);
  }
}

/**
 * Verify that a HELO is ok. Call a method
 * if the verification was successful.
 * @return OK if the attempt to verify is on the way,
 *        SYSERR if the transport mechanism is not supported
 */
int transportVerifyHelo(const HELO_Message * helo) {
  TransportAPI * tapi;

  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_EVERYTHING,
	"Advertised transport type %d"
	" does not match any known transport.\n",
	ntohs(helo->protocol));
    return SYSERR;
  }
  tapi = tapis[ntohs(helo->protocol)];
  if (tapi == NULL) {
    LOG(LOG_EVERYTHING,
	"Advertised transport type %d"
	" does not match any known transport.\n",
	ntohs(helo->protocol));
    return SYSERR;
  } else 
    return tapi->verifyHelo(helo);  
}

/**
 * Get the MTU for a given transport type.
 */
int transportGetMTU(unsigned short ttype) {
  TransportAPI * tapi;
  
  if (ttype >= tapis_count)
    return SYSERR;
  tapi = tapis[ttype];
  if (tapi == NULL)
    return SYSERR;
  else
    return tapi->mtu;
}

/**
 * Create a HELO advertisement for the given
 * transport type for this node.
 */
int transportCreateHELO(unsigned short ttype,
			HELO_Message ** helo) {
  TransportAPI * tapi;

  MUTEX_LOCK(&tapis_lock);
  *helo = NULL;
  if (ttype == ANY_PROTOCOL_NUMBER) {
    int * perm;

    perm = permute(tapis_count);
    ttype = tapis_count-1;
    while ( ((tapis[perm[ttype]] == NULL) ||
            (tapis[perm[ttype]] != NULL && 
	     tapis[perm[ttype]]->helo == NULL)) &&
	    (ttype < 0xFFFF) )
      ttype--;
    if (ttype == 0xFFFF) {
      FREE(perm);
      return SYSERR;
    }
    ttype = perm[ttype];
    FREE(perm);    
  }
  if (ttype >= tapis_count) {
    LOG(LOG_WARNING, 
	_("No transport of type %d known.\n"),
	ttype);
    MUTEX_UNLOCK(&tapis_lock);
    return SYSERR;
  }
  tapi = tapis[ttype];
  if (tapi == NULL) {
    LOG(LOG_WARNING, 
	_("No transport of type %d known.\n"),
	ttype);
    MUTEX_UNLOCK(&tapis_lock);
    return SYSERR;
  } 
  if (tapi->helo == NULL) {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG, 
	"Transport of type %d configured for sending only.\n",
	ttype);
#endif
    MUTEX_UNLOCK(&tapis_lock);
    return SYSERR;
  }

  *helo = MALLOC(HELO_Message_size(tapi->helo));
  memcpy(*helo,
	 tapi->helo,
	 HELO_Message_size(tapi->helo));
  MUTEX_UNLOCK(&tapis_lock);
  return OK;
}

/**
 * Get a message consisting of (if possible) all addresses that this
 * node is currently advertising.  This method is used to send out
 * possible ways to contact this node when sending a (plaintext) PING
 * during node discovery. Note that if we have many transport
 * implementations, it may not be possible to advertise all of our
 * addresses in one message, thus the caller can bound the size of the
 * advertisements.
 *
 * @param maxLen the maximum size of the HELO message collection in bytes
 * @param buff where to write the HELO messages
 * @return the number of bytes written to buff, -1 on error
 */
int getAdvertisedHELOs(int maxLen,
		       char * buff) {
  int i;
  int j;
  int tcount;
  HELO_Message ** helos;
  int used;
  
  tcount = 0;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tcount++;
  
  helos = MALLOC(tcount * sizeof(HELO_Message*));
  tcount = 0;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      if (OK == transportCreateHELO(i, &helos[tcount]))
	tcount++;
  if (tcount == 0)
    return SYSERR;
  j = 0;
  used = 0;
  while (j < 10) {
    j++;
    i = randomi(tcount); /* select a HELO at random */
    if (helos[i] == NULL)
      continue; /* copied this one already */
    if ((int)HELO_Message_size(helos[i]) > maxLen - used)
      continue;
    memcpy(&buff[used],
	   helos[i],
	   HELO_Message_size(helos[i]));
    used += HELO_Message_size(helos[i]);
    FREE(helos[i]);
    helos[i] = NULL; 
    j = 0; /* try until 10 attempts fail, restart after every success! */
  }

  for (i=0;i<tcount;i++)
    if (helos[i] != NULL)
      FREE(helos[i]);
  FREE(helos);
  return used;
}    

/* end of transport.c */			
