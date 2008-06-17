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
 * @file server/core.c
 * @brief implementation of the GNUnet core API for applications
 * @author Christian Grothoff
 */
#include "gnunet_util.h"

#include "handler.h"
#include "knownhosts.h"
#include "pingpong.h"
#include "tcpserver.h"
#include "traffic.h"
#include "core.h"

#define DEBUG_CORE NO

/**
 * Linked list of loaded protocols (for clean shutdown).
 */
typedef struct ShutdownList {
  /**
   * Pointer to the library (as returned by dlopen).
   */
  void * library;  
  /**
   * Textual name of the library ("libgnunet_afs_protocol").
   */
  char * dsoName;
  /**
   * YES or NO: is the application initialized at this point?
   */
  int applicationInitialized;
  /**
   * Current number of users of the service API.
   */
  unsigned int serviceCount;
  /**
   * Pointer to the service API (or NULL if service not in use).
   */
  void * servicePTR;
  /**
   * This is a linked list.
   */
  struct ShutdownList * next;
} ShutdownList;

/**
 * Global for the transport API.
 */
static CoreAPIForTransport transportCore;

/**
 * Global for the core API.
 */
static CoreAPIForApplication applicationCore;

/**
 * List of loaded modules and their status.
 */
static ShutdownList * shutdownList = NULL;

#define DSO_PREFIX "libgnunet"

/**
 * @param signer the identity of the host that presumably signed the message
 * @param message the signed message
 * @param size the size of the message
 * @param sig the signature
 * @return OK on success, SYSERR on error (verification failed)
 */
static int verifySigHelper(const HostIdentity * signer,
			   void * message,
			   int size,
			   Signature * sig) {
  HELO_Message * helo;
  int res;

  if (SYSERR == identity2Helo(signer,
			      ANY_PROTOCOL_NUMBER,
			      YES,
			      &helo))
    return SYSERR;
  res = verifySig(message, size, sig,
		  &helo->publicKey);
  FREE(helo);
  return res;
}


/* **************** inbound message queue for all transports ************** */

/**
 * How many incoming packages do we have in the buffer
 * (max.). Must be >= THREAD_COUNT to make sense.
 */
#define QUEUE_LENGTH 16

/**
 * How many threads do we start? 
 */
#define THREAD_COUNT 2


static MessagePack * bufferQueue_[QUEUE_LENGTH];
static int bq_firstFree_;
static int bq_lastFree_;
static int bq_firstFull_;

static Semaphore * bufferQueueRead_;
static Semaphore * bufferQueueWrite_;   
static Mutex globalLock_;
static Semaphore * mainShutdownSignal = NULL;
static PTHREAD_T threads_[THREAD_COUNT];

/**
 * This is the main loop of each thread.  It loops *forever* waiting
 * for incomming packets in the packet queue. Then it calls "handle"
 * (defined in handler.c) on the packet.
 */
static void * threadMain(int id) {
  MessagePack * mp;
  
  while (mainShutdownSignal == NULL) {
    SEMAPHORE_DOWN(bufferQueueRead_);
    /* handle buffer entry */
    /* sync with other handlers to get buffer */
    if (mainShutdownSignal != NULL)
      break;
    MUTEX_LOCK(&globalLock_);
    mp = bufferQueue_[bq_firstFull_++];
    bufferQueue_[bq_lastFree_++] = NULL;
    if (bq_firstFull_ == QUEUE_LENGTH)
      bq_firstFull_ = 0;
    if (bq_lastFree_ == QUEUE_LENGTH)
      bq_lastFree_ = 0;
    MUTEX_UNLOCK(&globalLock_);
    /* end of sync */
    SEMAPHORE_UP(bufferQueueWrite_);    

    /* handle buffer - now out of sync */    
    handleMessage(mp->tsession,
		  &mp->sender,
		  mp->msg,
		  mp->size,
		  mp->isEncrypted,
		  mp->crc);
    if (mp->tsession != NULL)
      transportDisconnect(mp->tsession);
    FREE(mp->msg);
    FREE(mp);
  }
  SEMAPHORE_UP(mainShutdownSignal);
  return NULL;
} /* end of threadMain */

/**
 * Processing of a message from the transport layer
 * (receive implementation).
 */
void core_receive(MessagePack * mp) {
  if (SYSERR == SEMAPHORE_DOWN_NONBLOCKING(bufferQueueWrite_)) {
    /* discard message, buffer is full! */
    FREE(mp->msg);
    FREE(mp);
    return;
  } 
  /* aquire buffer */
  if (SYSERR == transportAssociate(mp->tsession))
    mp->tsession = NULL;
  
  MUTEX_LOCK(&globalLock_);
  if (bq_firstFree_ == QUEUE_LENGTH)
    bq_firstFree_ = 0;
  bufferQueue_[bq_firstFree_++] = mp;    
  MUTEX_UNLOCK(&globalLock_);
  SEMAPHORE_UP(bufferQueueRead_);  
}

/**
 * Load the application module named "pos".
 * @return OK on success, SYSERR on error
 */ 
static int loadApplicationModule(const char * pos) {
  int ok;
  ShutdownList * nxt;
  ApplicationInitMethod mptr;
  CoreAPIForApplication * capi;
  void * library;
  char * name;

  name = MALLOC(strlen(pos) + strlen("_protocol") + 1);
  strcpy(name, pos);
  strcat(name, "_protocol");

  nxt = shutdownList;
  while (nxt != NULL) {
    if (0 == strcmp(name, 
		    nxt->dsoName)) {
      if (nxt->applicationInitialized == YES) {
	LOG(LOG_WARNING,
	    _("Application %s already initialized!\n"),
	    name);
	FREE(name);
	return SYSERR;
      } else {
	mptr = bindDynamicMethod(nxt->library,
				 "initialize_",
				 name);
	if (mptr == NULL) {
	  FREE(name);
	  return SYSERR;
	}
	capi = getCoreAPIForApplication();  
	ok = mptr(capi);
	if (ok == OK)
	  nxt->applicationInitialized = YES;
	FREE(name);
	return ok;
      }      
    }
    nxt = nxt->next;
  }

  library = loadDynamicLibrary(DSO_PREFIX,
			       name);
  if (library == NULL) {
    FREE(name);
    return SYSERR;
  }
  mptr = bindDynamicMethod(library,
			   "initialize_",
			   name);
  if (mptr == NULL) {
#if DEBUG_CORE     
    LOG(LOG_DEBUG,
	"Unloading library %s at %s:%d.\n", 
	name, __FILE__, __LINE__);
#endif
    unloadDynamicLibrary(library);
    FREE(name);
    return SYSERR;
  }
  nxt = MALLOC(sizeof(ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = YES;
  nxt->serviceCount = 0;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  capi = getCoreAPIForApplication();  
  ok = mptr(capi);
  if (OK != ok) 
    nxt->applicationInitialized = NO;
  return ok;
}

static int unloadApplicationModule(const char * name) {
  ShutdownList * pos;
  ShutdownList * prev;
  ApplicationDoneMethod mptr;

  prev = NULL;
  pos = shutdownList;
  while ( (pos != NULL) &&
	  (0 != strcmp(name,
		       pos->dsoName) ) )
    pos = pos->next;

  if (pos == NULL) {
    LOG(LOG_ERROR,
	_("Could not shutdown '%s': application not loaded\n"),
	name);
    return SYSERR;
  }
  
  if (pos->applicationInitialized != YES) {
    LOG(LOG_WARNING,
	_("Could not shutdown application '%s': not initialized\n"),
	name);
    return SYSERR;
  }      
  mptr = bindDynamicMethod(pos->library,
			   "done_",
			   pos->dsoName);
  if (mptr == NULL) {
    LOG(LOG_ERROR,
	_("Could not find '%s%s' method in library '%s'.\n"),
	"done_",
	pos->dsoName,
	pos->dsoName);
    return SYSERR;
  }

  mptr();
  pos->applicationInitialized = NO;
  if (pos->serviceCount > 0) {
#if DEBUG_CORE
    LOG(LOG_DEBUG,
	"Application shutdown, but service '%s' is still in use.\n",
	pos->dsoName);
#endif	
    return OK;
  }

  /* compute prev! */
  if (pos == shutdownList) {
    prev = NULL; 
  } else {
    prev = shutdownList;
    while (prev->next != pos)
      prev = prev->next;
  }
 
  if (0 == getConfigurationInt("GNUNETD",
			       "VALGRIND")) {
    /* do not unload plugins if we're using
       valgrind */
#if DEBUG_CORE     
    LOG(LOG_DEBUG,
	"Unloading application plugin '%s' at %s:%d.\n", 
	pos->dsoName, __FILE__, __LINE__);
#endif
    unloadDynamicLibrary(pos->library);
  }    
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;
  FREE(pos->dsoName);
  FREE(pos);
  return OK;
}

static void * requestService(const char * pos) {
  ShutdownList * nxt;
  ServiceInitMethod mptr;
  CoreAPIForApplication * capi;
  void * library;
  char * name;
  void * api;

  name = MALLOC(strlen(pos) + strlen("_protocol") + 1);
  strcpy(name, pos);
  strcat(name, "_protocol");

  nxt = shutdownList;
  while (nxt != NULL) {
    if (0 == strcmp(name, 
		    nxt->dsoName)) {
      if (nxt->serviceCount > 0) {
	if (nxt->servicePTR != NULL)
	  nxt->serviceCount++;
	FREE(name);
#if DEBUG_CORE
	LOG(LOG_DEBUG,
	    "Already have service '%s' as %p.\n",
	    pos,
	    nxt->servicePTR);
#endif
	return nxt->servicePTR;
      } else {
	mptr = bindDynamicMethod(nxt->library,
				 "provide_",
				 name);
	if (mptr == NULL) {
	  FREE(name);
	  return NULL;
	}
	capi = getCoreAPIForApplication();  
	nxt->servicePTR = mptr(capi);
	if (nxt->servicePTR != NULL) 
	  nxt->serviceCount++;
	FREE(name);
#if DEBUG_CORE
	LOG(LOG_DEBUG,
	    "Initialized service '%s' as %p.\n",
	    pos,
	    nxt->servicePTR);
#endif
	return nxt->servicePTR;
      }      
    }
    nxt = nxt->next;
  }

  library = loadDynamicLibrary(DSO_PREFIX,
			       name);
  if (library == NULL) {
    FREE(name);
    return NULL;
  }
  mptr = bindDynamicMethod(library,
			   "provide_",
			   name);
  if (mptr == NULL) {
#if DEBUG_CORE     
	LOG(LOG_DEBUG,
	    "Unloading library '%s' at %s:%d.\n", 
	    name, __FILE__, __LINE__);
#endif
    unloadDynamicLibrary(library);
    FREE(name);
    return NULL;
  }
  capi = getCoreAPIForApplication();  
  nxt = MALLOC(sizeof(ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = NO;
  nxt->serviceCount = 1;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  api = mptr(capi);
  if (api != NULL) 
    nxt->servicePTR = api;    
  else
    nxt->serviceCount = 0;
  LOG(LOG_DEBUG,
      "Loaded service %s as %p\n",
      pos,
      api);

  return api;
}

static int releaseService(void * service) {
  ShutdownList * pos;
  ShutdownList * prev;
  ApplicationDoneMethod mptr;

  prev = NULL;
  pos = shutdownList;
  while ( (pos != NULL) &&
	  (pos->servicePTR != service) )
    pos = pos->next;

  if (pos == NULL) {
    LOG(LOG_ERROR,
	_("Could not release %p: service not loaded\n"),
	service);
    return SYSERR; 
  }
#if DEBUG_CORE
  LOG(LOG_DEBUG,
      "Unloading %p, found service %s.\n", 
      service,
      pos->dsoName);
#endif
    
  mptr = bindDynamicMethod(pos->library,
			   "release_",
			   pos->dsoName);
  if (mptr == NULL) {
    LOG(LOG_ERROR,
	_("Could not find '%s%s' method in library '%s'.\n"),
	"release_",
	pos->dsoName,
	pos->dsoName);
    return SYSERR;
  }
  if (pos->serviceCount > 1) {
#if DEBUG_CORE
    LOG(LOG_DEBUG,
	"Service %s still in use, not unloaded.\n",
	pos->dsoName);
#endif
    pos->serviceCount--;
    return OK; /* service still in use elsewhere! */
  }
  
#if DEBUG_CORE
  LOG(LOG_DEBUG,
      "Calling 'release_%s'.\n",
      pos->dsoName);
#endif
  mptr();
  pos->serviceCount--;
  pos->servicePTR = NULL;

  if (pos->applicationInitialized == YES) {
#if DEBUG_CORE
    LOG(LOG_DEBUG,
	"Protocol '%s' still in use, not unloaded.\n",
	pos->dsoName);
#endif
    return OK; /* protocol still in use! */
  }

  /* compute prev */
  if (pos == shutdownList) {
    prev = NULL;
  } else {
    prev = shutdownList;
    while (prev->next != pos)
      prev = prev->next;
  }
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;

  if (0 == getConfigurationInt("GNUNETD",
			       "VALGRIND")) {
    /* do not unload plugins if we're using valgrind */
#if DEBUG_CORE     
    LOG(LOG_DEBUG,
	"Unloading library '%s' at %s:%d.\n", 
	pos->dsoName, __FILE__, __LINE__);
#endif
    unloadDynamicLibrary(pos->library);
  }
#if DEBUG_CORE     
  LOG(LOG_DEBUG,
      "Unloaded '%s' plugin.\n", 
      pos->dsoName);
#endif
  FREE(pos->dsoName);
  FREE(pos);    
  return OK;
}


/**
 * Initialize the CORE's globals.
 */
void initCore() {
  int i;

  MUTEX_CREATE(&globalLock_);
  for (i=0;i<QUEUE_LENGTH;i++)
    bufferQueue_[i] = NULL;
  bq_firstFree_ = 0;
  bq_lastFree_ = 0;
  bq_firstFull_ = 0;
  
  /* initialize sync mechanisms for message handling threads */
  bufferQueueRead_ = SEMAPHORE_NEW(0);
  bufferQueueWrite_ = SEMAPHORE_NEW(QUEUE_LENGTH);
  /* create message handling threads */
  for (i=0;i<THREAD_COUNT;i++) {
    PTHREAD_CREATE(&threads_[i], 
		   (PThreadMain) &threadMain,
		   (void *) &i,
		   8 * 1024); 
  }

  transportCore.version = 0;
  transportCore.myIdentity = &myIdentity; /* keyservice.c */
  transportCore.receive = &core_receive; /* core.c */

  applicationCore.version = 0;
  applicationCore.myIdentity = &myIdentity; /* keyservice.c */
  applicationCore.pingAction = &pingAction; /* pingpong.c */
  applicationCore.sign = &signData; /* keyservice.c */
  applicationCore.verifySig = &verifySigHelper; /* core.c */
  applicationCore.preferTrafficFrom = &updateTrafficPreference; /* connection.c */
  applicationCore.changeTrust = &changeHostCredit; /* connection.c */
  applicationCore.getTrust = &getHostCredit; /* connection.c */
  applicationCore.sendToNode = &sendToNode; /* connection.c */
  applicationCore.unicast = &unicast; /* connection.c */
  applicationCore.queryBPMfromPeer = &getBandwidthAssignedTo; /* connection.c */
  applicationCore.forAllConnectedNodes = &forEachConnectedNode; /* connection.c */
  applicationCore.broadcastToConnected = &broadcast; /* connection.c */
  applicationCore.registerSendCallback = &registerSendCallback; /* connection.c */
  applicationCore.unregisterSendCallback = &unregisterSendCallback; /* connection.c */
  applicationCore.registerClientHandler = &registerCSHandler; /* tcpserver.c */
  applicationCore.isClientHandlerRegistered = &isCSHandlerRegistered; /* tcpserver.c */
  applicationCore.unregisterClientHandler = &unregisterCSHandler; /* tcpserver.c */
  applicationCore.registerClientExitHandler = &registerClientExitHandler; /* tcpserver.c */
  applicationCore.unregisterClientExitHandler = &unregisterClientExitHandler; /* tcpserver.c */
  applicationCore.sendToClient = &sendToClient; /* tcpserver.c */
  applicationCore.sendTCPResultToClient = &sendTCPResultToClient; /* tcpserver.c */ 
  applicationCore.registerHandler = &registerp2pHandler; /* handler.c*/
  applicationCore.isHandlerRegistered = &isp2pHandlerRegistered; /* handler.c*/
  applicationCore.unregisterHandler = &unregisterp2pHandler; /* handler.c*/
  applicationCore.estimateNetworkSize = &estimateNetworkSize; /* knownhosts.c */
  applicationCore.computeIndex = &computeIndex; /* connection.c */
  applicationCore.getConnectionModuleLock = &getConnectionModuleLock; /* connection.c */
  applicationCore.getTrafficStats = &getTrafficStats; /* traffic.c */
  applicationCore.identity2Helo = &identity2Helo; /* knownhosts.c */
  applicationCore.bindAddress = &bindAddress; /* knownhosts.c */
  applicationCore.disconnectFromPeer = &disconnectFromPeer; /* connection.c */
  applicationCore.disconnectPeers = &shutdownConnections; /* connection.c */
  applicationCore.loadApplicationModule = &loadApplicationModule; /* core.c */
  applicationCore.unloadApplicationModule = &unloadApplicationModule; /* core.c */
  applicationCore.setPercentRandomInboundDrop = &setPercentRandomInboundDrop; /* handler.c */
  applicationCore.setPercentRandomOutboundDrop = &setPercentRandomInboundDrop; /* transport.c */  
  applicationCore.requestService = &requestService;
  applicationCore.releaseService = &releaseService;  
  applicationCore.terminateClientConnection = &terminateClientConnection;  /* tcpserver.c */
}

CoreAPIForTransport * getCoreAPIForTransport() {
  return &transportCore;
}

CoreAPIForApplication * getCoreAPIForApplication() { 
  return &applicationCore;
}

void loadApplicationModules() {
  char * dso;
  char * next;
  char * pos;
  
  dso = getConfigurationString("GNUNETD",
			       "APPLICATIONS");
  if (dso == NULL) {
    LOG(LOG_WARNING,
	_("No applications defined in configuration!\n"));
    return;
  }
  LOG(LOG_DEBUG,
      "loading applications %s\n",
      dso);
  next = dso;
  do {
    pos = next;
    while ( (*next != '\0') &&
	    (*next != ' ') )
      next++;
    if (*next == '\0') {
      next = NULL; /* terminate! */
    } else {
      *next = '\0'; /* add 0-termination for pos */
      next++;
    }
    if (OK != loadApplicationModule(pos))
      LOG(LOG_ERROR,
	  _("Could not initialize application '%s'\n"),
	  pos);
  } while (next != NULL);
  FREE(dso);
}

/**
 * Shutdown the CORE modules (shuts down all application modules).
 */
void doneCore() {
  int i;
  void * unused;
  ShutdownList * pos;
  ShutdownList * prev;
  ShutdownList * nxt;

  /* send HANGUPs for connected hosts */
  shutdownConnections();

  /* stop receiving messages, note that "send" may still be called! */ 
  stopTransports();

  /* shutdown processing of inbound  messages... */
  mainShutdownSignal = SEMAPHORE_NEW(0);
  for (i=0;i<THREAD_COUNT;i++) {
    SEMAPHORE_UP(bufferQueueRead_);
    SEMAPHORE_DOWN(mainShutdownSignal);
  }
  for (i=0;i<THREAD_COUNT;i++) 
    PTHREAD_JOIN(&threads_[i], &unused);

  /* shutdown application modules */
  pos = shutdownList;
  while (pos != NULL) {
    nxt = pos->next;
    if ( (pos->applicationInitialized == YES) &&
	 (OK != unloadApplicationModule(pos->dsoName)) )
      LOG(LOG_ERROR,
	  _("Could not properly shutdown application '%s'.\n"),
	  pos->dsoName);    
    pos = nxt;
  }   

  /* unload modules */
  pos = shutdownList;
  prev = NULL;
  while (pos != NULL) {
    if ( (pos->applicationInitialized == NO) &&
	 (pos->serviceCount == 0) ) {
      if (0 == getConfigurationInt("GNUNETD",
				   "VALGRIND")) {
	/* do not unload plugins if we're using valgrind */
#if DEBUG_CORE     
	LOG(LOG_DEBUG,
	    "Unloading library '%s' at %s:%d.\n", 
	    pos->dsoName, __FILE__, __LINE__);
#endif	
	unloadDynamicLibrary(pos->library);
      }

      nxt = pos->next;
      if (prev == NULL)
	shutdownList = nxt;
      else
	prev->next = nxt;
      FREE(pos->dsoName);
      FREE(pos);
      pos = nxt;
    } else {
      LOG(LOG_ERROR,
	  _("Could not properly unload application '%s'.\n"),
	  pos->dsoName);
      pos = pos->next;
    }         
  }
  

  /* free datastructures */
  MUTEX_DESTROY(&globalLock_);
  SEMAPHORE_FREE(bufferQueueRead_);
  SEMAPHORE_FREE(bufferQueueWrite_);
  for (i=0;i<QUEUE_LENGTH;i++) {
    if (bufferQueue_[i] != NULL) {
      FREENONNULL(bufferQueue_[i]->msg);
    }
    FREENONNULL(bufferQueue_[i]);
  }

  SEMAPHORE_FREE(mainShutdownSignal);
  mainShutdownSignal = NULL;
}

/* end of core.c */
