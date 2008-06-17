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
 * @file include/gnunet_datastore_service.h
 * @brief API that can be used manage the
 *   datastore for files stored on a GNUnet node;
 *   note that the datastore is NOT responsible for
 *   on-demand encoding, that is achieved using
 *   a special kind of entry.
 * @author Christian Grothoff
 */

#ifndef GNUNET_DATASTORE_SERVICE_H
#define GNUNET_DATASTORE_SERVICE_H

#include "gnunet_core.h"

/**
 * A value in the datastore.
 */
typedef struct {

  /**
   * The total size of the Value, including this header, in network
   * byte order.
   */
  unsigned int size;

  /**
   * Type of the item.  The datastore does not care about this value;
   * in network byte order.  0 is reserved and should not be used
   * by applications for anything other than 'any type'.  In network
   * byte order.
   */
  unsigned int type;

  /**
   * How important is it to keep this item?  Items with the lowest
   * priority are discarded if the datastore is full.  In network
   * byte order.
   */
  unsigned int prio;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).  In network byte order.
   */
  unsigned int anonymityLevel;

  /**
   * Expiration time for this item, in NBO (use htonll to read!).  Use
   * "-1" for items that never expire.
   */
  cron_t expirationTime;

} Datastore_Value;

/**
 * An entry (key-value pair) in the datastore.
 */
typedef struct {

  /**
   * A key (not unique) that can be used to lookup this Datum in the
   * datastore.
   */
  HashCode512 key;

  /**
   * The value associated with the key.
   */
  Datastore_Value value;

} Datastore_Datum;

/**
 * An iterator over a set of Datastore items.
 *
 * @param datum called with the next item
 * @param closure user-defined extra argument
 * @return SYSERR to abort the iteration, OK to continue.
 */
typedef int (*Datum_Iterator)(const HashCode512 * key,
			      const Datastore_Value * value,
			      void * closure);


/**
 * @brief Definition of the datastore API.
 *
 * Note that a datastore implementation is supposed to do much more
 * than just trivially implement this API.  A good datastore discards
 * old entries and low-priority entries in the background as the
 * database fills up to its limit.  It uses a bloomfilter to avoid
 * disk-IO.  A datastore should pre-fetch some set of random entries
 * to quickly respond to getRandom().
 *
 * Finally, the datastore should try to detect corruption and if
 * so automatically attempt to repair itself (i.e. by keeping
 * a flag in the state-DB to indicate if the last shutdown was
 * clean, and if not, trigger a repair on startup).
 *
 * Once GNUnet has IO load management the DS should integrate with
 * that and refuse IO if the load is too high.
 */
typedef struct {

  /**
   * Get the current on-disk size of the datastore.
   */
  unsigned long long (*getSize)(void);

  /**
   * Store an item in the datastore.  If the item is
   * already present, a second copy is created.
   *
   * @return YES on success, NO if the datastore is
   *   full and the priority of the item is not high enough
   *   to justify removing something else, SYSERR on
   *   other serious error (i.e. IO permission denied)
   */
  int (*put)(const HashCode512 * key,
	     const Datastore_Value * value);

  /**
   * Store an item in the datastore.  If the item is already present,
   * the priorities are summed up and the higher expiration time and
   * lower anonymity level is used.
   *
   * @return YES on success, NO if the datastore is
   *   full and the priority of the item is not high enough
   *   to justify removing something else, SYSERR on
   *   other serious error (i.e. IO permission denied)
   */
  int (*putUpdate)(const HashCode512 * key,
		   const Datastore_Value * value);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param key maybe NULL (to match all entries)
   * @param type entries of which type are relevant?
   *     Use 0 for any type.
   * @param iter maybe NULL (to just count)
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration,
   *   0 if no matches were found.  May NOT return
   *   SYSERR unless the iterator aborted!
   */
  int (*get)(const HashCode512 * key,
	     unsigned int type,
	     Datum_Iterator iter,
	     void * closure);

  /**
   * Do a quick test if we MAY have the content.
   */ 
  int (*fast_get)(const HashCode512 * key);

  /**
   * Get a random value from the datastore that has
   * a key close to the given approx value.
   *
   * @param approx maybe NULL (if any random entry
   *   will do)
   * @param key set to the key of the match
   * @param value set to an approximate match
   * @param type if a particular type is desired, 0
   *        for any type.
   * @return OK if a value was found, SYSERR if not
   */
  int (*getRandom)(const HashCode512 * approx,
		   unsigned int sizeLimit,
		   HashCode512 * key,
		   Datastore_Value ** value,
		   unsigned int type);

  /**
   * Delete an item from the datastore.
   *
   * @param value maybe NULL, then all items under the
   *         given key are deleted
   * @return the number of items deleted, 0 if
   *         none were found, SYSERR on errors
   */
  int (*del)(const HashCode512 * key,
	     const Datastore_Value * value);

} Datastore_ServiceAPI;


/* end of gnunet_datastore_service.h */
#endif
