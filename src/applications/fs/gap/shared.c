/*
      This file is part of GNUnet
      (C) 2008 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file fs/gap/shared.c
 * @brief shared helper functions and data structures
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "shared.h"
#include "fs.h"

/**
 * Free the request list, including the associated
 * list of pending requests, its entries in the
 * plans for various peers and known responses.
 */
void
GNUNET_FS_SHARED_free_request_list (struct RequestList *rl)
{
  struct ResponseList *repl;
  struct QueryPlanEntry *planl;

  while (rl->responses != NULL)
    {
      repl = rl->responses;
      rl->responses = repl->next;
      GNUNET_free (repl);
    }
  while (rl->plan_entries != NULL)
    {
      planl = rl->plan_entries;
      rl->plan_entries = planl->plan_entries_next;
      if (planl->next != NULL)
        planl->next->prev = planl->prev;
      else
        planl->list->tail = planl->prev;
      if (planl->prev != NULL)
        planl->prev->next = planl->next;
      else
        planl->list->head = planl->next;
      GNUNET_free (planl);
    }
  if (rl->bloomfilter != NULL)
    GNUNET_bloomfilter_free (rl->bloomfilter);
  GNUNET_FS_PT_change_rc (rl->primary_target, -1);
  GNUNET_FS_PT_change_rc (rl->response_target, -1);
  memset (rl, 0, sizeof (struct RequestList));  /* mark as freed */
  GNUNET_free (rl);
}



/**
 * Check if the given value is a valid
 * and new response for the given request list
 * entry.
 *
 * @param hc set to the hash of the data if successful
 * @return GNUNET_OK if so, GNUNET_NO if not new or not
 *         applicable, GNUNET_SYSERR on error
 */
int
GNUNET_FS_SHARED_test_valid_new_response (struct RequestList *rl,
                                          const GNUNET_HashCode * primary_key,
                                          unsigned int size,
                                          const DBlock * data,
                                          GNUNET_HashCode * hc)
{
  struct ResponseList *seen;
  GNUNET_HashCode m;
  int ret;

  /* check that type and primary key match */
  if (((rl->type != GNUNET_ECRS_BLOCKTYPE_ANY) &&
       (rl->type != ntohl (data->type))) ||
      (0 != memcmp (primary_key, &rl->queries[0], sizeof (GNUNET_HashCode))))
    return GNUNET_NO;

  /* check that content matches query */
  ret = GNUNET_EC_is_block_applicable_for_query (ntohl (data->type),
                                                 size,
                                                 data,
                                                 &rl->queries[0],
                                                 rl->key_count,
                                                 &rl->queries[0]);
  if (ret != GNUNET_OK)
    return ret;

  /* check that this is a new response */
  GNUNET_hash (data, size, hc);
  GNUNET_FS_HELPER_mingle_hash (hc, rl->bloomfilter_mutator, &m);
  if ((rl->bloomfilter != NULL) &&
      (GNUNET_YES == GNUNET_bloomfilter_test (rl->bloomfilter, &m)))
    return GNUNET_NO;           /* not useful */
  /* bloomfilter should cover these already */
  seen = rl->responses;
  while (seen != NULL)
    {
      if (0 == memcmp (hc, &seen->hash, sizeof (GNUNET_HashCode)))
        return GNUNET_NO;
      seen = seen->next;
    }
  return GNUNET_OK;
}


/**
 * Mark the response corresponding to the given
 * hash code as seen (update linked list and bloom filter).
 */
void
GNUNET_FS_SHARED_mark_response_seen (struct RequestList *rl,
                                     const GNUNET_HashCode * hc)
{
  struct ResponseList *seen;
  GNUNET_HashCode m;

  if (rl->bloomfilter != NULL)
    {
      GNUNET_FS_HELPER_mingle_hash (hc, rl->bloomfilter_mutator, &m);
      GNUNET_bloomfilter_add (rl->bloomfilter, &m);
    }
  /* update seen list */
  seen = GNUNET_malloc (sizeof (struct ResponseList));
  seen->hash = *hc;
  seen->next = rl->responses;
  rl->responses = seen;
}


/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
int
GNUNET_FS_HELPER_complete_value_from_database_callback (const GNUNET_HashCode
                                                        * key,
                                                        const
                                                        GNUNET_DatastoreValue
                                                        * value,
                                                        void *closure,
                                                        unsigned long long
                                                        uid)
{
  GNUNET_DatastoreValue *comp = closure;

  if ((comp->size != value->size) ||
      (0 != memcmp (&value[1],
                    &comp[1],
                    ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
    return GNUNET_OK;
  *comp = *value;
  return GNUNET_SYSERR;
}


/**
 * Mingle hash with the mingle_number to
 * produce different bits.
 */
void
GNUNET_FS_HELPER_mingle_hash (const GNUNET_HashCode * in,
                              int mingle_number, GNUNET_HashCode * hc)
{
  GNUNET_HashCode m;

  GNUNET_hash (&mingle_number, sizeof (int), &m);
  GNUNET_hash_xor (&m, in, hc);
}


/**
 * The priority level imposes a bound on the maximum
 * value for the ttl that can be requested.
 *
 * @param ttl_in requested ttl
 * @param prio given priority
 * @return ttl_in if ttl_in is below the limit,
 *         otherwise the ttl-limit for the given priority
 */
int
GNUNET_FS_HELPER_bound_ttl (int ttl_in, unsigned int prio)
{
  if (ttl_in <= 0)
    return ttl_in;
  if (ttl_in >
      ((unsigned long long) prio) * TTL_DECREMENT / GNUNET_CRON_SECONDS)
    {
      if (((unsigned long long) prio) * TTL_DECREMENT / GNUNET_CRON_SECONDS >=
          (1 << 30))
        return 1 << 30;
      return (int) ((unsigned long long) prio) * TTL_DECREMENT /
        GNUNET_CRON_SECONDS;
    }
  return ttl_in;
}


/* end of shared.c */
