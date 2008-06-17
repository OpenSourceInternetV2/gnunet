/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/migration.c
 * @brief This module is responsible for pushing content out
 * into the network.
 * @author Christian Grothoff
 */

#include "migration.h"
#include "manager.h"

#if VERBOSE_STATS
static int stat_handle_content_pushed;
#endif

/* use a 64-entry RCB buffer */
#define RCB_SIZE 128

/**
 * Semaphore on which the RCB aquire thread waits
 * if the RCB buffer is full.
 */
static Semaphore * aquireMoreSignal;

static Semaphore * doneSignal;

/**
 * Lock for the RCB buffer.
 */
static Mutex lock;

/**
 * Buffer with pre-fetched random content for migration.
 */
static ContentIndex * randomContentBuffer[RCB_SIZE];

/**
 * Highest index in RCB that is valid.
 */
static int rCBPos;

static void * rcbAquire(void * unused) {
  int ok;

  while (1) {
    ContentIndex ce;

    SEMAPHORE_DOWN(aquireMoreSignal);
    if (doneSignal != NULL)
      break;
    ok = retrieveRandomContent(&ce);
    if (ok == OK)
      if (ntohs(ce.type) == LOOKUP_TYPE_3HASH ||
	  ntohs(ce.type) == LOOKUP_TYPE_SUPER)
	ok = SYSERR; /* can not migrate these */
    if (ok == OK) {
      ContentIndex * cp = MALLOC(sizeof(ContentIndex));
      memcpy(cp, &ce, sizeof(ContentIndex));
      MUTEX_LOCK(&lock);
      randomContentBuffer[rCBPos++] = cp;
      MUTEX_UNLOCK(&lock);
    } else {
      int load = getCPULoad();
      if (load < 10)
	load = 10;
      sleep(load / 5); /* the higher the load, the longer the sleep,
			  but at least 2 seconds */
      SEMAPHORE_UP(aquireMoreSignal); /* send myself signal to go again! */
    }
  }
  SEMAPHORE_UP(doneSignal);
  return NULL;
}


/**
 * Select content for active migration.  Takes the best match from the
 * randomContentBuffer (if the RCB is non-empty) and returns it.
 *
 * @return SYSERR if the RCB is empty
 */
static int selectMigrationContent(HostIdentity * receiver,
				  ContentIndex * ce) {
  unsigned int dist;
  unsigned int minDist;
  int minIdx;
  int i;
  
  minIdx = -1;
  minDist = -1; /* max */
  MUTEX_LOCK(&lock);
  for (i=0;i<rCBPos;i++) {
    dist = distanceHashCode160(&randomContentBuffer[i]->hash,
			       &receiver->hashPubKey);
    if (dist < minDist) {
      minIdx = i;
      minDist = dist;
    }
  }
  if (minIdx == -1) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }  
  memcpy(ce,
	 randomContentBuffer[minIdx],
	 sizeof(ContentIndex));
  FREE(randomContentBuffer[minIdx]);
  randomContentBuffer[minIdx] = randomContentBuffer[--rCBPos];
  randomContentBuffer[rCBPos] = NULL;
  MUTEX_UNLOCK(&lock);
  SEMAPHORE_UP(aquireMoreSignal);
  return OK;
}
				  
/**
 * Build a CHK reply message for some content
 * selected for migration.
 * @return OK on success, SYSERR on error
 */
static int buildCHKReply(ContentIndex * ce,
			 AFS_p2p_CHK_RESULT * pmsg) {
  CONTENT_Block * data;
  int ret;
  
  if (ntohs(ce->type) == LOOKUP_TYPE_3HASH ||
      ntohs(ce->type) == LOOKUP_TYPE_SUPER)
    return SYSERR;
  
  data = NULL;
  ret = retrieveContent(&ce->hash,
			ce,
			(void**)&data,
			0,
			NO /* low prio! & should not matter for CHK anyway */);
  if (ret == -1) /* can happen if we're concurrently inserting, 
		    _should be_ rare but is OK! */
    return SYSERR;
  if (ret != sizeof(CONTENT_Block)) {
    BREAK();
    FREENONNULL(data);
    return SYSERR;
  }
  pmsg->header.size 
    = htons(sizeof(AFS_p2p_CHK_RESULT));
  pmsg->header.requestType
    = htons(AFS_p2p_PROTO_CHK_RESULT);
  memcpy(&pmsg->result,
	 data,
	 sizeof(CONTENT_Block));
  FREE(data);
  return OK;
}

/**
 * Callback method for pushing content into the network.
 * The method chooses either a "recently" deleted block
 * or content that has a hash close to the receiver ID
 * (randomized to guarantee diversity, unpredictability
 * etc.).<p>
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static int activeMigrationCallback(HostIdentity * receiver,
				   char * position,
				   int padding) {
  AFS_p2p_CHK_RESULT * pmsg;
  int res;
  void * data;
  ContentIndex ce;
  
  res = 0;
  memset(&ce, 0, sizeof(ContentIndex));
  while (padding - res > (int) sizeof(AFS_p2p_CHK_RESULT)) {
    data = NULL;
    if (SYSERR == selectMigrationContent(receiver,
					 &ce)) 
      return res; /* nothing selected, that's the end */
    /* append it! */
    pmsg = (AFS_p2p_CHK_RESULT*) &position[res];
    if (OK == buildCHKReply(&ce,
			    pmsg)) {
#if VERBOSE_STATS
      statChange(stat_handle_content_pushed, 1);
#endif
      res += sizeof(AFS_p2p_CHK_RESULT);
    } else 
      return res; /* abort early after any error */    
  }
  return res;
}

static PTHREAD_T gather_thread;

void initMigration() {

#if VERBOSE_STATS
  stat_handle_content_pushed
    = statHandle(_("# kb content pushed out as padding"));
#endif
  memset(&randomContentBuffer,
	 0, 
	 sizeof(ContentIndex*)*RCB_SIZE);
  aquireMoreSignal = SEMAPHORE_NEW(RCB_SIZE);
  doneSignal = NULL;
  MUTEX_CREATE(&lock);
  if (0 != PTHREAD_CREATE(&gather_thread,
			  (PThreadMain)&rcbAquire,
			  NULL,
			  64*1024)) 
    DIE_STRERROR("pthread_create");
  coreAPI->registerSendCallback(sizeof(AFS_p2p_CHK_RESULT),
				(BufferFillCallback)&activeMigrationCallback);
}

void doneMigration() {
  int i;
  void * unused;

  coreAPI->unregisterSendCallback(sizeof(AFS_p2p_CHK_RESULT),
				  (BufferFillCallback)&activeMigrationCallback);
  doneSignal = SEMAPHORE_NEW(0);
  SEMAPHORE_UP(aquireMoreSignal);
  SEMAPHORE_DOWN(doneSignal);
  SEMAPHORE_FREE(aquireMoreSignal);
  SEMAPHORE_FREE(doneSignal);
  MUTEX_DESTROY(&lock);
  for (i=0;i<RCB_SIZE;i++)
    FREENONNULL(randomContentBuffer[i]);
  PTHREAD_JOIN(&gather_thread, &unused);
}

/* end of migration.c */
