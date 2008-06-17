/*
     This file is part of GNUnet
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/fragmentation.c
 * @brief fragmentation and defragmentation, this code allows
 *        sending and receiving messages that are larger than
 *        the MTU of the transport.  Messages are still limited
 *        to a maximum size of 65535 bytes, which is a good
 *        idea because otherwise we may need ungainly fragmentation
 *        buffers.  Each connected peer can have at most one
 *        fragmented packet at any given point in time (prevents
 *        DoS attacks).  Fragmented messages that have not been
 *        completed after a certain amount of time are discarded.
 * @author Christian Grothoff
 *
 * todo: 
 * - test
 * - integrate into knapsack, but in such a way that
 *   if we send fragments, we'll send them _all_.
 *   (otherwise we'll waste too much bandwidth...)
 */

#include "gnunet_core.h"
#include "platform.h"
#include "handler.h"
#include "fragmentation.h"

/**
 * How many buckets does the fragment hash table
 * have?  
 */
#define DEFRAG_BUCKET_COUNT 16

/**
 * After how long do fragments time out?
 */
#ifndef DEFRAGMENTATION_TIMEOUT
#define DEFRAGMENTATION_TIMEOUT (3 * cronMINUTES)
#endif

/**
 * Entry in the linked list of fragments.
 */
typedef struct FL {
  struct FL * link;
  FRAGMENT_Message * frag;
} FL;

/**
 * Entry in the hash table of fragments.
 */
typedef struct FC {
  struct FC * next;
  FL * head;
  HostIdentity sender;
  int id;
  cron_t ttl;
} FC;

#define FRAGSIZE(fl) ((ntohs(fl->frag->header.size)-sizeof(FRAGMENT_Message)))

/**
 * Hashtable *with* collision management!
 */
static FC * defragmentationCache[DEFRAG_BUCKET_COUNT];

/**
 * Lock for the defragmentation cache.
 */
static Mutex defragCacheLock;

static void freeFL(FL * fl) {
  while (fl != NULL) {
    FL * link = fl->link;    
    FREE(fl->frag);
    FREE(fl);
    fl = link;
  }
}

/**
 * This cron job ensures that we purge buffers of fragments
 * that have timed out.  It can run in much longer intervals
 * than the defragmentationCron, e.g. every 60s.
 * <p>
 * This method goes through the hashtable, finds entries that
 * have timed out and removes them (and all the fragments that
 * belong to the entry).  It's a bit more complicated as the
 * collision list is also collapsed.
 */
static void defragmentationPurgeCron() {
  int i;
  FC * smf;
  FC * next;
  FC * last;

  MUTEX_LOCK(&defragCacheLock);
  for (i=0;i<DEFRAG_BUCKET_COUNT;i++) {
    last = NULL;
    smf = defragmentationCache[i];
    while (smf != NULL) {
      if (smf->ttl < cronTime(NULL)) {
	/* free linked list of fragments */
	freeFL(smf->head);
	next = smf->next;
	FREE(smf);	
	if (last == NULL)
	  defragmentationCache[i] = next;
	else
	  last->next = next;	
	smf = next;
      } else {
	last = smf;
	smf = smf->next;
      }
    } /* while smf != NULL */
  } /* for all buckets */
  MUTEX_UNLOCK(&defragCacheLock);
}

/**
 * Check if this fragment-list is complete.  If yes, put it together,
 * process and free all buffers.  Does not free the pep
 * itself (but sets the TTL to 0 to have the cron free it
 * in the next iteration).
 *
 * @param pep the entry in the hash table
 */
static void checkComplete(FC * pep) {
  FL * pos;
  unsigned short off;
  unsigned short len;
  char * msg;

  GNUNET_ASSERT(pep != NULL);
  
  pos = pep->head;
  if (pos == NULL)
    return;
  len = ntohs(pos->frag->len);
  if (len == 0)
    goto CLEANUP; /* really bad error! */
  off = 0;
  while ( (pos != NULL) &&
	  (ntohs(pos->frag->off) <= off) ) {
    if (off >= off + FRAGSIZE(pos))
      goto CLEANUP; /* error! */
    if (ntohs(pos->frag->off) + FRAGSIZE(pos) > off)
      off = ntohs(pos->frag->off) + FRAGSIZE(pos);
    else
      goto CLEANUP; /* error! */
    pos = pos->link;
  }
  if (off < len)
    return; /* some fragment is still missing */

  msg = MALLOC(len);
  pos = pep->head;
  while (pos != NULL) {
    memcpy(&msg[ntohs(pos->frag->off)],
	   &((FRAGMENT_Message_GENERIC*)pos->frag)->data[0],
	   FRAGSIZE(pos));
    pos = pos->link;
  }

  /* handle message! */
  handleHelper(msg,
	       &pep->sender,
	       len,
	       crc32N(msg, len));
  FREE(msg);

 CLEANUP:
  /* free fragment buffers */
  freeFL(pep->head);
  pep->head = NULL;
  pep->ttl = 0;
}

/**
 * See if the new fragment is a part of this entry and join them if
 * yes.  Return SYSERR if the fragments do not match.  Return OK if
 * the fragments do match and the fragment has been processed.  The
 * defragCacheLock is already aquired by the caller whenever this
 * method is called.<p>
 *
 * @param entry the entry in the cache
 * @param pep the new entry
 * @param packet the ip part in the new entry
 */
static int tryJoin(FC * entry,
		   const HostIdentity * sender,
		   const FRAGMENT_Message * packet) {
  /* frame before ours; may end in the middle of
     our frame or before it starts; NULL if we are
     the earliest position we have received so far */
  FL * before;
  /* frame after ours; may start in the middle of
     our frame or after it; NULL if we are the last
     fragment we have received so far */
  FL * after;
  /* current position in the frame-list */
  FL * pos;
  /* the new entry that we're inserting */
  FL * pep;
  FL * tmp;
  unsigned short end;

  GNUNET_ASSERT(entry != NULL);
  if (! hostIdentityEquals(sender, 
			   &entry->sender))
    return SYSERR; /* wrong fragment list, try another! */
  if (ntohl(packet->id) != entry->id)
    return SYSERR; /* wrong fragment list, try another! */

  pos = entry->head;
  if ( (pos != NULL) &&
       (packet->len != pos->frag->len) )
    return SYSERR; /* wrong fragment size */

  before = NULL;
  /* find the before-frame */
  while ( (pos != NULL) &&
	  (ntohs(pos->frag->off) < 
	   ntohs(packet->off)) ) {
    before = pos;
    pos = pos->link;
  }
  
  /* find the after-frame */
  end = ntohs(packet->off) + ntohs(packet->header.size) - sizeof(FRAGMENT_Message);
  if (end <= ntohs(packet->off)) {
    LOG(LOG_DEBUG,
	"Received invalid fragment at %s:%d\n",
	__FILE__, __LINE__);
    return SYSERR; /* yuck! integer overflow! */
  }
  
  if (before != NULL)
    after = before; 
  else
    after = entry->head; 
  while ( (after != NULL) &&
	  (ntohs(after->frag->off)<end) )
    after = after->link;

  if ( (before != NULL) &&
       (before == after) ) {
    /* this implies after or before != NULL and thereby the new
       fragment is redundant as it is fully enclosed in an earlier
       fragment */
    return OK; /* drop, there is a packet that spans our range! */
  }    

  if ( (before != NULL) &&
       (after != NULL) &&
       ( (htons(before->frag->off) + 
	  FRAGSIZE(before)) 
	 >= htons(after->frag->off)) ) {
    /* this implies that the fragment that starts before us and the
       fragment that comes after this one leave no space in the middle
       or even overlap; thus we can drop this redundant piece */
    return OK;
  }

  /* allocate pep */
  pep = MALLOC(sizeof(FC));
  pep->frag = MALLOC(ntohs(packet->header.size));
  memcpy(pep->frag, packet, ntohs(packet->header.size));
  pep->link = NULL;

  if (before == NULL) {
    pep->link = after;
    pos = entry->head; 
    while (pos != after) {
      tmp = pos->link;
      FREE(pos->frag);
      FREE(pos);
      pos = tmp;
    }
    entry->head = pep; 
    goto FINISH;
    /* end of insert first */
  }

  if (after == NULL) {    
    /* insert last: find the end, free everything after it */
    freeFL(before->link);
    before->link = pep;
    goto FINISH;
  }

  /* ok, we are filling the middle between two fragments; insert.  If
     there is anything else in the middle, it can be dropped as we're
     bigger & cover that area as well */
  /* free everything between before and after */
  pos = before->link;
  while (pos != after) {
    tmp = pos->link;
    FREE(pos->frag);
    FREE(pos);
    pos = tmp;
  }
  before->link = pep;
  pep->link = after;

 FINISH:
  entry->ttl = cronTime(NULL) + DEFRAGMENTATION_TIMEOUT;
  checkComplete(entry);
  return OK;
}

/**
 * Defragment the given fragment and pass to handler once
 * defragmentation is complete.
 *
 * @param frag the packet to defragment
 * @return SYSERR if the fragment is invalid
 */
static int processFragment(const HostIdentity * sender,
			   const p2p_HEADER * frag) {
  unsigned int hash;
  FC * smf;

  if (ntohs(frag->size) < sizeof(FRAGMENT_Message))
    return SYSERR;
    
  MUTEX_LOCK(&defragCacheLock);
  hash = sender->hashPubKey.a % DEFRAG_BUCKET_COUNT;
  smf = defragmentationCache[hash];
  while (smf != NULL) {
    if (OK == tryJoin(smf, sender, (FRAGMENT_Message*) frag)) {
      MUTEX_UNLOCK(&defragCacheLock);
      return OK;
    }
    if (hostIdentityEquals(sender,
			   &smf->sender)) {
      freeFL(smf->head);
      break;
    }
    smf = smf->next;
  }
  if (smf == NULL) {
    smf = MALLOC(sizeof(FC));    
    smf->next = defragmentationCache[hash];
    defragmentationCache[hash] = smf;
    smf->ttl = cronTime(NULL) + DEFRAGMENTATION_TIMEOUT;
    smf->sender = *sender;
  }
  smf->id = ntohl(((FRAGMENT_Message*)frag)->id);
  smf->head = MALLOC(sizeof(FL));
  smf->head->link = NULL;
  smf->head->frag = MALLOC(ntohs(frag->size));
  memcpy(smf->head->frag, 
	 frag, 
	 ntohs(frag->size));

  MUTEX_UNLOCK(&defragCacheLock);
  return OK;
}

/**
 * Initialize Fragmentation
 */
void initFragmentation() {
  int i;

  for (i=0;i<DEFRAG_BUCKET_COUNT;i++) 
    defragmentationCache[i] = NULL;
  MUTEX_CREATE(&defragCacheLock);
  addCronJob((CronJob) &defragmentationPurgeCron,
	     60 * cronSECONDS, 
	     60 * cronSECONDS,
	     NULL);
  registerp2pHandler(p2p_PROTO_FRAGMENT,
		     &processFragment);
}

/**
 * Shutdown fragmentation.
 */
void doneFragmentation() {
  int i;

  unregisterp2pHandler(p2p_PROTO_FRAGMENT,
		       &processFragment);
  delCronJob((CronJob) &defragmentationPurgeCron,
	     60 * cronSECONDS,
	     NULL);
  for (i=0;i<DEFRAG_BUCKET_COUNT;i++) {
    FC * pos = defragmentationCache[i];
    while (pos != NULL) {
      FC * next = pos->next;
      freeFL(pos->head);
      FREE(pos);
      pos = next;
    }    
  }
  MUTEX_DESTROY(&defragCacheLock);
}


/* end of fragmentation.c */
