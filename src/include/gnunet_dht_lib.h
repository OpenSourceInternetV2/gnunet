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
 *        (for library in applications/dht/tools/dht_api.c)
 * @author Tomi Tukiainen
 * @version dht_api.h,v 1.11 2004/05/11 12:14:02 mjraiha Exp 
 *
 *
 * Todo:
 * - rename all symbols (method names!) to be prefixed with "DHT_".
 */

#ifndef GNUNET_DHT_LIB_H
#define GNUNET_DHT_LIB_H 

#include "gnunet_util.h"
#include "gnunet_dht.h"


/* sleeping time to be used when waiting for data to be received */
#define API_SLEEP_MILLIS 50

/* sleeping time between receive thread polling for any operation waiting for data */
#define RECEIVE_THREAD_SLEEP_MILLIS 50

/* timeouts (ms) for different operations or suboperations */
#define API_INITIALIZE_RESULTS_TIMEOUT 2000

#define API_CREATE_ACK_TIMEOUT         1000
#define API_CREATE_RESULTS_TIMEOUT     4000

#define API_INSERT_ACK_TIMEOUT         1000
#define API_INSERT_RESULTS_TIMEOUT     4000

#define API_FETCH_ACK_TIMEOUT          1000
#define API_FETCH_RESULTS_TIMEOUT      9000

#define API_JOIN_ACK_TIMEOUT           1000
#define API_JOIN_RESULTS_TIMEOUT       9000

#define API_LEAVE_ACK_TIMEOUT           1000
#define API_LEAVE_RESULTS_TIMEOUT       4000

#define API_TABLES_ACK_TIMEOUT           1000
#define API_TABLES_RESULTS_TIMEOUT       9000

#define API_INSERTED_ACK_TIMEOUT         1000
#define API_INSERTED_RESULTS_TIMEOUT     4000

#define API_DROP_ACK_TIMEOUT             1000
#define API_DROP_RESULTS_TIMEOUT         4000

/* operation status numbering, we are only interested in waitfor-statuses */
#define OPERATION_STATUS_OTHER 0
#define OPERATION_STATUS_WAITFOR_ACK 1
#define OPERATION_STATUS_WAITFOR_RESULTS 2
#define OPERATION_STATUS_WAITFOR_STATUS 3



typedef struct {
  unsigned int errorCode;
  DHT_TableId tableId; 
} DHT_TableHandle; 



/* ************************* MAIN FUCNTIONALITY *********************** */
/* These functions offer the main interface to DHT's functionality      */

/**
 * Initializes API for application use. 
 *
 * @return errorcode for the execution, see error_handling.h
 */
int initializeApi(); 

/**
 * Destroys API and free's resources that it uses. 
 *
 * @return errorcode for the execution, see error_handling.h
 */
int destroyApi();

/**
 * Creates a new DHT-table. 
 *
 * @param meta description for the table
 * @param config configuration for the table
 * @return handle to the created table
 */
DHT_TableHandle *create(DHT_TableMetaData * meta,
			DHT_TableConfig * config);

/**
 * Joins to a DHT-table. 
 *
 * @param address address of the DHT-node that is used to join the network
 * @param table_id id of the table that is to be joined to
 * @return handle to the joined table
 */
DHT_TableHandle *join(DHT_TableId * table_id);

/**
 * Leaves a DHT-table.
 *
 * @param handle of the table that is to be leaved from
 * @return errorcode for the execution, see error_handling.h
 */
int leave(DHT_TableHandle * table);

/**
 * Inserts a <key,value>-mapping into a DHT-table. 
 *
 * @param table handle of the table where insertion is to be done
 * @param key key of the <key,value>-mapping
 * @param value value of the <key,value>-mapping
 * @return errorcode for the execution, see error_handling.h
 */
int insert(DHT_TableHandle * table, 
	   DHT_DataContainer * key,
	   DHT_DataContainer * value);


/**
 * Retrieves values that are mapped to given key in a DHT-table.
 *
 * @param table handle of the table where retrieval is to be done
 * @param key key that is used when searching mappings
 * @return set that contains values that are mapped to the key
 */
DHT_ResultSet *fetch(DHT_TableHandle * table,
		     DHT_DataContainer * key);

/**
 * Retrieves a listing of tables to whom a DHT-node is joined. Information is 
 * received only about public tables.
 *
 * @param address address of the DHT-node whose joined tables are to be listed.
 * @return set that contains information about tables to whom DHT-node is joined.
 */
DHT_TableSet *listTables();

/**
 * Lists all <key,value>-pairs that are inserted to a DHT-table by DHT-node.
 *
 * @param handle of the table where data is inserted
 * @return set that contains information about all inserted keys. 
 */
DHT_DataList *listInsertedData(DHT_TableHandle * table);


/**
 * Drops data that is inserted to a DHT-table by DHT-node.
 *
 * @param table table where <key,value>-pair is
 * @param reference to the <key,value>-mapping to be dropped
 * @return errorcode for the execution, see error_handling.h
 */
int dropInsertedData(DHT_TableHandle * table, 
		     DHT_StoredDataReference * uniqueReference);


/* ************************* UTILITY FUNCTIONS *********************** */
/* These functions are used to handle results of the DHT main functions */

/**
 * Returns a boolean value that indicates if errorcode returned by a
 * DHT's API function is actually an error. 
 *
 * @param errorcode to check 
 * @return 1 on error, 0 otherwise
 */
int isError(int errorCode); 

/**
 * Sets dataPointer to point to the next data item that is in the resultset. 
 * While iterating through a resultset with this method, resultset items 
 * contained in the resultset will be freed (returned ones will not). 
 *
 * @param resultSet resultset whose next dataitem is to be returned
 * @param dataPointer pointer that will be set to point to next dataitem
 * @return errorcode for the execution, see error_handling.h. 
 */
int resultSetNext(DHT_ResultSet * resultSet, DHT_DataContainer ** dataPointer);

/**
 * Sets tablePointer to point to the next table that is in the tableset. 
 * While iterating through a tableset with this method, tableset items 
 * contained in the tableset will be freed (returned ones will not)
 *
 * @param tableSet tableset whose next table is to be returned
 * @param tablePointer pointer that will be set to point to next table
 * @return errorcode for the execution, see error_handling.h. 
 */
int tableSetNext(DHT_TableSet * tableSet, DHT_TableSetItem ** tablePointer);

#endif /* DHT_API_H */
