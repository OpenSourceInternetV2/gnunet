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
 * @file include/gnunet_dht_lib.h
 * @brief convenience API to the DHT infrastructure for use by clients
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_LIB_H
#define GNUNET_DHT_LIB_H 

#include "gnunet_dht_service.h"

/**
 * Initialize DHT_LIB. Call first.
 */
void DHT_LIB_init();

/**
 * Initialize DHT_LIB. Call after leaving all tables!
 */
void DHT_LIB_done();

/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to 
 *   the join request (has no impact on success or failure)
 * @param flags 
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_join(DHT_Datastore * store,
		 DHT_TableId * table,
		 cron_t timeout,
		 int flags);


/**
 * Leave a table (stop storing data for the table).  Leave
 * fails if the node is not joint with the table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to 
 *   the leave request (has no impact on success or failure);
 *   but only timeout time is available for migrating data, so
 *   pick this value with caution.
 * @param flags 
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_leave(DHT_TableId * table,
		  cron_t timeout,
		  int flags); 


/**
 * Perform a synchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key; store the result in 'result'.  If
 * result->dataLength == 0 the result size is unlimited and
 * result->data needs to be allocated; otherwise result->data refers
 * to dataLength bytes and the result is to be stored at that
 * location; dataLength is to be set to the actual size of the
 * result.
 *
 * The peer does not have to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to look up  
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param maxResults maximum number of results to obtain, size of the results array
 * @param results where to store the results (on success)
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
int DHT_LIB_get(DHT_TableId * table,
		HashCode160 * key,
		cron_t timeout,
		unsigned int maxResults,
		DHT_DataContainer ** results);
	
/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to store
 * @param flags bitmask
 * @return OK on success, SYSERR on error (or timeout)
 */
int DHT_LIB_put(DHT_TableId * table,
		HashCode160 * key,
		cron_t timeout,
		DHT_DataContainer * value,
		int flags);

/**
 * Perform a synchronous remove operation.  The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to remove; NULL for all values matching the key
 * @param flags bitmask
 * @return OK on success, SYSERR on error (or timeout)
 */
int DHT_LIB_remove(DHT_TableId * table,
		   HashCode160 * key,
		   cron_t timeout,
		   DHT_DataContainer * value,
		   int flags);

#endif /* GNUNET_DHT_LIB_H */
