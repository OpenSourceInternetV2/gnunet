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
 * @file include/gnunet_dht_service.h
 * @brief API to the DHT-module.  This API is what will be used by
 *     DHT clients that run as modules within gnunetd.  If you
 *     are writing a client look at either gnunet_dht.h (if you
 *     want to handle the communication with gnunetd yourself) or
 *     at gnunet_dht_lib to use the convenience library.
 * @author Christian Grothoff
 */

#ifndef DHT_SERVICE_API_H
#define DHT_SERVICE_API_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_dht.h"

/* ************* DHT flags ************************ */

/**
 * Anding the flags with this bitmask results in the level
 * of content replication that is desired for this table.
 * All data should be replicated at the resulting number of
 * peers (to ensure it is not lost).  0 means no replication
 * (only one copy).
 */
#define DHT_FLAGS_TABLE_REPLICATION_MASK 7

/**
 * Should the data in this table be migrated if the peer
 * leaves the DHT?  If the flag is not set, the data is
 * completely lost each time a peer leaves the table.
 */
#define DHT_FLAGS_TABLE_MIGRATION_FLAG 8

/**
 * Should lookups on values of this table be cached?
 * (if set, the time of caching depends on available memory and
 *  is potentially unbounded; thus caching is only sound if
 *  the value associated with a key is unique).
 */
#define DHT_FLAGS_TABLE_CACHE_FLAG 16


/* *********** DHT Datastore interface *************** */

/**
 * Callback function type for items in the DHT datastore.
 *
 * @param key the current key
 * @param value the current value
 * @param cls argument passed for context (closure)
 * @return OK to continue with iteration, SYSERR to abort
 */
typedef int (*DHT_DataProcessor)(const HashCode160 * key,
				 const DHT_DataContainer * value,
				 int flags,
				 void * cls);

struct DHT_GET_RECORD;

struct DHT_PUT_RECORD;

struct DHT_REMOVE_RECORD;

typedef void (*DHT_GET_Complete)(const DHT_DataContainer * value,
				 void * closure);

/**
 * @param store identity of a peer that agreed to store the content
 */
typedef void (*DHT_PUT_Complete)(const HostIdentity * store,
				 void * closure);

/**
 * @param store identity of a peer that removed the content
 */
typedef void (*DHT_REMOVE_Complete)(const HostIdentity * store,
				    void * closure);

/**
 * DHT clients must implement this interface to create a DHT
 * table.  The clients are then called to perform the local
 * HT operations.
 */
typedef struct {

  /**
   * Lookup an item in the datastore.
   * @param key the value to lookup
   * @param maxResults maximum number of results
   * @param results where to store the result
   * @return number of results, SYSERR on error
   */
  int (*lookup)(void * closure,
		const HashCode160 * key,
		unsigned int maxResults,
		DHT_DataContainer * results,
		int flags);
  
  /**
   * Store an item in the datastore.
   * @param key the key of the item
   * @param value the value to store
   * @return OK if the value could be stored, SYSERR if not (i.e. out of space)
   */
  int (*store)(void * closure,
	       const HashCode160 * key,
	       const DHT_DataContainer * value,
	       int flags);

  /**
   * Remove an item from the datastore.
   * @param key the key of the item
   * @param value the value to remove, NULL for all values of the key
   * @return OK if the value could be removed, SYSERR if not (i.e. not present)
   */
  int (*remove)(void * closure,
		const HashCode160 * key,
		const DHT_DataContainer * value,
		int flags);

  /**
   * Iterate over all keys in the local datastore
   *
   * @param processor function to call on each item
   * @param cls argument to processor
   * @return number of results, SYSERR on error
   */
  int (*iterate)(void * closure,		 
		 int flags,
		 DHT_DataProcessor processor,
		 void * cls);

  /**
   * First argument to be passed to all functions in this struct.
   */
  void * closure;

} DHT_Datastore;

/* *********** DHT Service API **************************** */

/**
 * Functions of the DHT Service API.
 */
typedef struct {

  /**
   * Perform a synchronous GET operation on the DHT identified by
   * 'table' using 'key' as the key; store the result in 'result'.  If
   * result->dataLength == 0 the result size is unlimited and
   * result->data needs to be allocated; otherwise result->data refers
   * to dataLength bytes and the result is to be stored at that
   * location; dataLength is to be set to the actual size of the
   * result.
   *
   * The peer does not have to be part of the table! This method
   * must not be called from within a cron-job!
   *
   * @param table table to use for the lookup
   * @param key the key to look up  
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param maxResults maximum number of results to obtain, size of the results array
   * @param results where to store the results (on success)
   * @return number of results on success, SYSERR on error (i.e. timeout)
   */
  int (*get)(const DHT_TableId * table,
	     const HashCode160 * key,
	     cron_t timeout,
	     unsigned int maxResults,
	     DHT_DataContainer * results);
	
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
  int (*put)(const DHT_TableId * table,
	     const HashCode160 * key,
	     cron_t timeout,
	     const DHT_DataContainer * value,
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
  int (*remove)(const DHT_TableId * table,
		const HashCode160 * key,
		cron_t timeout,
		const DHT_DataContainer * value,
		int flags);


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
  int (*join)(DHT_Datastore * datastore,
	      const DHT_TableId * table,
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
  int (*leave)(const DHT_TableId * table,
	       cron_t timeout,
	       int flags); 


  /**
   * Perform an asynchronous GET operation on the DHT identified by
   * 'table' using 'key' as the key.  The peer does not have to be part
   * of the table (if so, we will attempt to locate a peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up  
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param maxResults maximum number of results to obtain;
   *        also used to determine the level of parallelism; is that wise?
   * @param callback function to call on each result
   * @param closure extra argument to callback
   * @return handle to stop the async get
   */
  struct DHT_GET_RECORD * (*get_start)(const DHT_TableId * table,
						 const HashCode160 * key,
						 cron_t timeout,
						 unsigned int maxResults,
						 DHT_GET_Complete callback,
						 void * closure);

  /**
   * Stop async DHT-get.  Frees associated resources.
   */
  int (*get_stop)(struct DHT_GET_RECORD * record);

  /**
   * Perform an asynchronous PUT operation on the DHT identified by
   * 'table' storing a binding of 'key' to 'value'.  The peer does not
   * have to be part of the table (if so, we will attempt to locate a
   * peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up  
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param replicationLevel how many copies should we make?
   * @param callback function to call on successful completion
   * @param closure extra argument to callback
   * @return handle to stop the async put
   */
  struct DHT_PUT_RECORD * (*put_start)(const DHT_TableId * table,
				       const HashCode160 * key,
				       cron_t timeout,
				       const DHT_DataContainer * value,
				       unsigned int replicationLevel,
				       DHT_PUT_Complete callback,
				       void * closure);
  
  /**
   * Stop async DHT-put.  Frees associated resources.
   */
  int (*put_stop)(struct DHT_PUT_RECORD * record);

  /**
   * Perform an asynchronous REMOVE operation on the DHT identified by
   * 'table' removing the binding of 'key' to 'value'.  The peer does not
   * have to be part of the table (if so, we will attempt to locate a
   * peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up  
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param replicationLevel how many copies should we make?
   * @param callback function to call on successful completion
   * @param closure extra argument to callback
   * @return handle to stop the async remove
   */
  struct DHT_REMOVE_RECORD * (*remove_start)(const DHT_TableId * table,
					     const HashCode160 * key,
					     cron_t timeout,
					     const DHT_DataContainer * value,
					     unsigned int replicationLevel,
					     DHT_REMOVE_Complete callback,
					     void * closure); 
    
  /**
   * Stop async DHT-remove.  Frees associated resources.
   */
  int (*remove_stop)(struct DHT_REMOVE_RECORD * record);
  
} DHT_ServiceAPI;

#endif /* DHT_SERVICE_API_H */
