/*
     This file is part of GNUnet
     (C) 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file fragmentation/fragmentation.c
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
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_stats_service.h"
#include "gnunet_fragmentation_service.h"

/**
 * Message fragment.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Fragment identity.
   */
  int id;

  /**
   * Fragment offset.
   */
  unsigned short off;

  /**
   * Total fragment size
   */
  unsigned short len;

} P2P_fragmentation_MESSAGE;

/**
 * How many buckets does the fragment GNUNET_hash table
 * have?
 */
#define DEFRAG_BUCKET_COUNT 16

/**
 * After how long do fragments time out?
 */
#ifndef DEFRAGMENTATION_TIMEOUT
#define DEFRAGMENTATION_TIMEOUT (3 * GNUNET_CRON_MINUTES)
#endif

/**
 * Entry in the linked list of fragments.
 */
typedef struct FL
{
  struct FL *link;
  P2P_fragmentation_MESSAGE *frag;
} FL;

/**
 * Entry in the GNUNET_hash table of fragments.
 */
typedef struct FC
{
  struct FC *next;
  FL *head;
  GNUNET_PeerIdentity sender;
  int id;
  GNUNET_CronTime ttl;
} FC;

#define FRAGSIZE(fl) ((ntohs(fl->frag->header.size)-sizeof(P2P_fragmentation_MESSAGE)))

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_defragmented;

static int stat_fragmented;

static int stat_discarded;

/**
 * Hashtable *with* collision management!
 */
static FC *defragmentationCache[DEFRAG_BUCKET_COUNT];

/**
 * Lock for the defragmentation cache.
 */
static struct GNUNET_Mutex *defragCacheLock;

static void
freeFL (FL * fl, int c)
{
  while (fl != NULL)
    {
      FL *link = fl->link;
      if (stats != NULL)
        stats->change (stat_discarded, c);
      GNUNET_free (fl->frag);
      GNUNET_free (fl);
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
static void
defragmentationPurgeCron (void *unused)
{
  int i;
  FC *smf;
  FC *next;
  FC *last;

  GNUNET_mutex_lock (defragCacheLock);
  for (i = 0; i < DEFRAG_BUCKET_COUNT; i++)
    {
      last = NULL;
      smf = defragmentationCache[i];
      while (smf != NULL)
        {
          if (smf->ttl < GNUNET_get_time ())
            {
              /* free linked list of fragments */
              freeFL (smf->head, 1);
              next = smf->next;
              GNUNET_free (smf);
              if (last == NULL)
                defragmentationCache[i] = next;
              else
                last->next = next;
              smf = next;
            }
          else
            {
              last = smf;
              smf = smf->next;
            }
        }                       /* while smf != NULL */
    }                           /* for all buckets */
  GNUNET_mutex_unlock (defragCacheLock);
}

/**
 * Check if this fragment-list is complete.  If yes, put it together,
 * process and free all buffers.  Does not free the pep
 * itself (but sets the TTL to 0 to have the cron free it
 * in the next iteration).
 *
 * @param pep the entry in the GNUNET_hash table
 */
static void
checkComplete (FC * pep)
{
  FL *pos;
  unsigned short off;
  unsigned short len;
  char *msg;

  GNUNET_GE_ASSERT (NULL, pep != NULL);
  pos = pep->head;
  if (pos == NULL)
    return;
  len = ntohs (pos->frag->len);
  if (len == 0)
    goto CLEANUP;               /* really bad error! */
  off = 0;
  while ((pos != NULL) && (ntohs (pos->frag->off) <= off))
    {
      if (off >= off + FRAGSIZE (pos))
        goto CLEANUP;           /* error! */
      if (ntohs (pos->frag->off) + FRAGSIZE (pos) > off)
        off = ntohs (pos->frag->off) + FRAGSIZE (pos);
      else
        goto CLEANUP;           /* error! */
      pos = pos->link;
    }
  if (off < len)
    return;                     /* some fragment is still missing */

  msg = GNUNET_malloc (len);
  pos = pep->head;
  while (pos != NULL)
    {
      memcpy (&msg[ntohs (pos->frag->off)], &pos->frag[1], FRAGSIZE (pos));
      pos = pos->link;
    }
  if (stats != NULL)
    stats->change (stat_defragmented, 1);
#if 0
  printf ("Finished defragmentation!\n");
#endif
  /* handle message! */
  coreAPI->loopback_send (&pep->sender, msg, len, GNUNET_YES, NULL);
  GNUNET_free (msg);
CLEANUP:
  /* free fragment buffers */
  freeFL (pep->head, 0);
  pep->head = NULL;
  pep->ttl = 0;
}

/**
 * See if the new fragment is a part of this entry and join them if
 * yes.  Return GNUNET_SYSERR if the fragments do not match.  Return GNUNET_OK if
 * the fragments do match and the fragment has been processed.  The
 * defragCacheLock is already acquired by the caller whenever this
 * method is called.<p>
 *
 * @param entry the entry in the cache
 * @param pep the new entry
 * @param packet the ip part in the new entry
 */
static int
tryJoin (FC * entry,
         const GNUNET_PeerIdentity * sender,
         const P2P_fragmentation_MESSAGE * packet)
{
  /* frame before ours; may end in the middle of
     our frame or before it starts; NULL if we are
     the earliest position we have received so far */
  FL *before;
  /* frame after ours; may start in the middle of
     our frame or after it; NULL if we are the last
     fragment we have received so far */
  FL *after;
  /* current position in the frame-list */
  FL *pos;
  /* the new entry that we're inserting */
  FL *pep;
  FL *tmp;
  unsigned short end;

  GNUNET_GE_ASSERT (NULL, entry != NULL);
  if (0 != memcmp (sender, &entry->sender, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;       /* wrong fragment list, try another! */
  if (ntohl (packet->id) != entry->id)
    return GNUNET_SYSERR;       /* wrong fragment list, try another! */
#if 0
  printf ("Received fragment %u from %u to %u\n",
          ntohl (packet->id),
          ntohs (packet->off),
          ntohs (packet->off) + ntohs (packet->header.size) -
          sizeof (P2P_fragmentation_MESSAGE));
#endif
  pos = entry->head;
  if ((pos != NULL) && (packet->len != pos->frag->len))
    return GNUNET_SYSERR;       /* wrong fragment size */

  before = NULL;
  /* find the before-frame */
  while ((pos != NULL) && (ntohs (pos->frag->off) < ntohs (packet->off)))
    {
      before = pos;
      pos = pos->link;
    }

  /* find the after-frame */
  end =
    ntohs (packet->off) + ntohs (packet->header.size) -
    sizeof (P2P_fragmentation_MESSAGE);
  if (end <= ntohs (packet->off))
    {
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_DEVELOPER | GNUNET_GE_DEBUG | GNUNET_GE_BULK,
                     "Received invalid fragment at %s:%d\n", __FILE__,
                     __LINE__);
      return GNUNET_SYSERR;     /* yuck! integer overflow! */
    }

  if (before != NULL)
    after = before;
  else
    after = entry->head;
  while ((after != NULL) && (ntohs (after->frag->off) < end))
    after = after->link;

  if ((before != NULL) && (before == after))
    {
      /* this implies after or before != NULL and thereby the new
         fragment is redundant as it is fully enclosed in an earlier
         fragment */
      if (stats != NULL)
        stats->change (stat_defragmented, 1);
      return GNUNET_OK;         /* drop, there is a packet that spans our range! */
    }

  if ((before != NULL) &&
      (after != NULL) &&
      ((htons (before->frag->off) +
        FRAGSIZE (before)) >= htons (after->frag->off)))
    {
      /* this implies that the fragment that starts before us and the
         fragment that comes after this one leave no space in the middle
         or even overlap; thus we can drop this redundant piece */
      if (stats != NULL)
        stats->change (stat_defragmented, 1);
      return GNUNET_OK;
    }

  /* allocate pep */
  pep = GNUNET_malloc (sizeof (FC));
  pep->frag = GNUNET_malloc (ntohs (packet->header.size));
  memcpy (pep->frag, packet, ntohs (packet->header.size));
  pep->link = NULL;

  if (before == NULL)
    {
      pep->link = after;
      pos = entry->head;
      while (pos != after)
        {
          tmp = pos->link;
          GNUNET_free (pos->frag);
          GNUNET_free (pos);
          pos = tmp;
        }
      entry->head = pep;
      goto FINISH;
      /* end of insert first */
    }

  if (after == NULL)
    {
      /* insert last: find the end, free everything after it */
      freeFL (before->link, 1);
      before->link = pep;
      goto FINISH;
    }

  /* ok, we are filling the middle between two fragments; insert.  If
     there is anything else in the middle, it can be dropped as we're
     bigger & cover that area as well */
  /* free everything between before and after */
  pos = before->link;
  while (pos != after)
    {
      tmp = pos->link;
      GNUNET_free (pos->frag);
      GNUNET_free (pos);
      pos = tmp;
    }
  before->link = pep;
  pep->link = after;

FINISH:
  entry->ttl = GNUNET_get_time () + DEFRAGMENTATION_TIMEOUT;
  checkComplete (entry);
  return GNUNET_OK;
}

/**
 * Defragment the given fragment and pass to handler once
 * defragmentation is complete.
 *
 * @param frag the packet to defragment
 * @return GNUNET_SYSERR if the fragment is invalid
 */
static int
processFragment (const GNUNET_PeerIdentity * sender,
                 const GNUNET_MessageHeader * frag)
{
  unsigned int hash;
  FC *smf;

  if (ntohs (frag->size) < sizeof (P2P_fragmentation_MESSAGE))
    return GNUNET_SYSERR;

  GNUNET_mutex_lock (defragCacheLock);
  hash = sender->hashPubKey.bits[0] % DEFRAG_BUCKET_COUNT;
  smf = defragmentationCache[hash];
  while (smf != NULL)
    {
      if (GNUNET_OK ==
          tryJoin (smf, sender, (P2P_fragmentation_MESSAGE *) frag))
        {
          GNUNET_mutex_unlock (defragCacheLock);
          return GNUNET_OK;
        }
      if (0 == memcmp (sender, &smf->sender, sizeof (GNUNET_PeerIdentity)))
        {
          freeFL (smf->head, 1);
          break;
        }
      smf = smf->next;
    }
  if (smf == NULL)
    {
      smf = GNUNET_malloc (sizeof (FC));
      smf->next = defragmentationCache[hash];
      defragmentationCache[hash] = smf;
      smf->ttl = GNUNET_get_time () + DEFRAGMENTATION_TIMEOUT;
      smf->sender = *sender;
    }
  smf->id = ntohl (((P2P_fragmentation_MESSAGE *) frag)->id);
  smf->head = GNUNET_malloc (sizeof (FL));
  smf->head->link = NULL;
  smf->head->frag = GNUNET_malloc (ntohs (frag->size));
  memcpy (smf->head->frag, frag, ntohs (frag->size));

  GNUNET_mutex_unlock (defragCacheLock);
  return GNUNET_OK;
}

typedef struct
{
  GNUNET_PeerIdentity sender;
  /* maximums size of each fragment */
  unsigned short mtu;
  /** how long is this message part expected to be? */
  unsigned short len;
  /** when did we intend to transmit? */
  GNUNET_CronTime transmissionTime;
} FragmentBMC;

/**
 * Send a message that had to be fragmented (right now!).  First grabs
 * the first part of the message (obtained from ctx->se) and stores
 * that in a P2P_fragmentation_MESSAGE envelope.  The remaining fragments are
 * added to the send queue with GNUNET_EXTREME_PRIORITY (to ensure that they
 * will be transmitted next).  The logic here is that if the priority
 * for the first fragment was sufficiently high, the priority should
 * also have been sufficiently high for all of the other fragments (at
 * this time) since they have the same priority.  And we want to make
 * sure that we send all of them since just sending the first fragment
 * and then going to other messages of equal priority would not be
 * such a great idea (i.e. would just waste bandwidth).
 */
static int
fragmentBMC (void *buf, void *cls, unsigned short len)
{
  FragmentBMC *ctx = cls;
  static int idGen = 0;
  P2P_fragmentation_MESSAGE *frag;
  unsigned int pos;
  int id;
  unsigned short mlen;

  if ((len < ctx->mtu) || (buf == NULL))
    {
      GNUNET_free (ctx);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_fragmented, 1);
  id = (idGen++) + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 512);
  /* write first fragment to buf */
  frag = (P2P_fragmentation_MESSAGE *) buf;
  frag->header.size = htons (len);
  frag->header.type = htons (GNUNET_P2P_PROTO_MESSAGE_FRAGMENT);
  frag->id = id;
  frag->off = htons (0);
  frag->len = htons (ctx->len);
  memcpy (&frag[1], &ctx[1], len - sizeof (P2P_fragmentation_MESSAGE));

  /* create remaining fragments, add to queue! */
  pos = len - sizeof (P2P_fragmentation_MESSAGE);
  frag = GNUNET_malloc (ctx->mtu);
  while (pos < ctx->len)
    {
      mlen = sizeof (P2P_fragmentation_MESSAGE) + ctx->len - pos;
      if (mlen > ctx->mtu)
        mlen = ctx->mtu;
      GNUNET_GE_ASSERT (NULL, mlen > sizeof (P2P_fragmentation_MESSAGE));
      frag->header.size = htons (mlen);
      frag->header.type = htons (GNUNET_P2P_PROTO_MESSAGE_FRAGMENT);
      frag->id = id;
      frag->off = htons (pos);
      frag->len = htons (ctx->len);
      memcpy (&frag[1],
              &((char *) (&ctx[1]))[pos],
              mlen - sizeof (P2P_fragmentation_MESSAGE));
      coreAPI->ciphertext_send (&ctx->sender,
                                &frag->header,
                                GNUNET_EXTREME_PRIORITY,
                                ctx->transmissionTime - GNUNET_get_time ());
      pos += mlen - sizeof (P2P_fragmentation_MESSAGE);
    }
  GNUNET_GE_ASSERT (NULL, pos == ctx->len);
  GNUNET_free (frag);
  GNUNET_free (ctx);
  return GNUNET_OK;
}

/**
 * The given message must be fragmented.  Produce a placeholder that
 * corresponds to the first fragment.  Once that fragment is scheduled
 * for transmission, the placeholder should automatically add all of
 * the other fragments (with very high priority).
 */
void
fragment (const GNUNET_PeerIdentity * peer,
          unsigned int mtu,
          unsigned int prio,
          unsigned int targetTime,
          unsigned int len, GNUNET_BuildMessageCallback bmc, void *bmcClosure)
{
  FragmentBMC *fbmc;
  int xlen;

  GNUNET_GE_ASSERT (NULL, len > mtu);
  GNUNET_GE_ASSERT (NULL, mtu > sizeof (P2P_fragmentation_MESSAGE));
  fbmc = GNUNET_malloc (sizeof (FragmentBMC) + len);
  fbmc->mtu = mtu;
  fbmc->sender = *peer;
  fbmc->transmissionTime = targetTime;
  fbmc->len = len;
  if (bmc == NULL)
    {
      memcpy (&fbmc[1], bmcClosure, len);
      GNUNET_free (bmcClosure);
    }
  else
    {
      if (GNUNET_SYSERR == bmc (&fbmc[1], bmcClosure, len))
        {
          GNUNET_free (fbmc);
          return;
        }
    }
  xlen = mtu - sizeof (P2P_fragmentation_MESSAGE);
  coreAPI->ciphertext_send_with_callback (peer, &fragmentBMC, fbmc, mtu, prio * xlen / len,     /* compute new priority */
                                          targetTime);
}

/**
 * Initialize Fragmentation module.
 */
GNUNET_Fragmentation_ServiceAPI *
provide_module_fragmentation (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Fragmentation_ServiceAPI ret;
  int i;

  coreAPI = capi;
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_defragmented =
        stats->create (gettext_noop ("# messages defragmented"));
      stat_fragmented =
        stats->create (gettext_noop ("# messages fragmented"));
      stat_discarded = stats->create (gettext_noop ("# fragments discarded"));
    }
  for (i = 0; i < DEFRAG_BUCKET_COUNT; i++)
    defragmentationCache[i] = NULL;
  defragCacheLock = GNUNET_mutex_create (GNUNET_NO);
  GNUNET_cron_add_job (coreAPI->cron,
                       &defragmentationPurgeCron,
                       60 * GNUNET_CRON_SECONDS, 60 * GNUNET_CRON_SECONDS,
                       NULL);
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _("`%s' registering handler %d\n"), "fragmentation",
                 GNUNET_P2P_PROTO_MESSAGE_FRAGMENT);
  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_MESSAGE_FRAGMENT,
                                         &processFragment);

  ret.fragment = &fragment;
  return &ret;
}

/**
 * Shutdown fragmentation.
 */
void
release_module_fragmentation ()
{
  int i;

  coreAPI->p2p_ciphertext_handler_unregister
    (GNUNET_P2P_PROTO_MESSAGE_FRAGMENT, &processFragment);
  GNUNET_cron_del_job (coreAPI->cron, &defragmentationPurgeCron,
                       60 * GNUNET_CRON_SECONDS, NULL);
  for (i = 0; i < DEFRAG_BUCKET_COUNT; i++)
    {
      FC *pos = defragmentationCache[i];
      while (pos != NULL)
        {
          FC *next = pos->next;
          freeFL (pos->head, 1);
          GNUNET_free (pos);
          pos = next;
        }
    }
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  GNUNET_mutex_destroy (defragCacheLock);
  defragCacheLock = NULL;
  coreAPI = NULL;
}

/* end of fragmentation.c */
