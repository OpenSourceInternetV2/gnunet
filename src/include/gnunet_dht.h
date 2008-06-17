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
 * @file include/gnunet_dht.h
 * @brief data structures exchanged between between DHT clients and the GNUnet DHT module
 * @author Tomi Tukiainen, Marko Räihä
 * @version client-server-api.h,v 1.7 2004/05/02 19:52:59 mjraiha Exp 
 */

#ifndef GNUNET_DHT_H
#define GNUNET_DHT_H 

#include "gnunet_util.h"



/* ************* DHT-operation's errorcodes *********** */

/* #define OK 1 */ /* this definition comes from gnunet_util.h */

#define DHT_ERRORCODE_BASE 1000
#define DHT_ERRORCODES__OP_REQUEST_REJECTED  (DHT_ERRORCODE_BASE+1)

/* ************* API specific errorcodes *********** */

#define API_ERRORCODE_BASE 50
#define DHT_ERRORCODES__API_ERROR_UNKNOWN                          (API_ERRORCODE_BASE+1)
#define DHT_ERRORCODES__API_CS_PROTO_RECEIVER_THREAD_CREATE_FAILED (API_ERRORCODE_BASE+2)
#define DHT_ERRORCODES__API_CS_PROTO_WRITE_TO_SOCKET_FAILED        (API_ERRORCODE_BASE+3)
#define DHT_ERRORCODES__API_MEMORY_ALLOCATION_FAILED               (API_ERRORCODE_BASE+4)
#define DHT_ERRORCODES__API_NO_SUCH_ELEMENT                        (API_ERRORCODE_BASE+5)

/* ************* DHT Client-Server protocol errorcodes *********** */

#define CS_ERRORCODE_BASE 100
#define DHT_ERRORCODES__CS_PROTO_UNEXPECTED_MESSAGE_RECEIVED (CS_ERRORCODE_BASE+1)
#define DHT_ERRORCODES__CS_PROTO_ACK_TIMEOUT                 (CS_ERRORCODE_BASE+2)
#define DHT_ERRORCODES__CS_PROTO_RESULTS_TIMEOUT             (CS_ERRORCODE_BASE+3)
#define DHT_ERRORCODES__CS_PROTO_INVALID_RESULTS             (CS_ERRORCODE_BASE+4)
#define DHT_ERRORCODES__CS_PROTO_PAYLOAD_EXCEEDED            (CS_ERRORCODE_BASE+5)

/**************** Datalayer specific error codes ****************/

#define DL_ERRORCODE_BASE 150
#define DHT_ERRORCODES__DATALAYER_STORAGE_FULL           (DL_ERRORCODE_BASE+1)
#define DHT_ERRORCODES__DATALAYER_KEYSTORAGE_FULL        (DL_ERRORCODE_BASE+2)
#define DHT_ERRORCODES__TABLE_NOT_FOUND                  (DL_ERRORCODE_BASE+3)
#define DHT_ERRORCODES__EMPTY_RESULT                     (DL_ERRORCODE_BASE+4)
#define DHT_ERRORCODES__DUPLICATE_DATA_UNIT              (DL_ERRORCODE_BASE+5)
#define DHT_ERRORCODES__DUPLICATE_TABLE_ID               (DL_ERRORCODE_BASE+6)



/* ************************* STRUCTS ******************************** */
/* these structs are exchanged in CS messages between gnunetd and the */
/* clients (APIs)                                                     */

typedef struct DHT_CS_MSG_HEADER_T {
  unsigned short apiId;              /* always in Network Byte Order */
  unsigned short requestId;          /* always in Network Byte Order */
} DHT_CS_MSG_HEADER;

typedef struct DHT_CSFetchResult_t {
  unsigned short valueCount;    /* number of values that are returned (Network Byte Order) */
  char data[0];                 /* Start of data. First there will be array of valueCount  */
                                /* shorts (telling length of each returned value)          */
                                /* and immediately after that actual data will follow      */
                                /* (catenated)                                             */
} DHT_CSFetchResult; 


/* ************************* CONSTANTS ******************************** */
/* these constants are exchanged between gnunetd and the clients (APIs) */

#define REQUEST_STATUS_ACCEPTED 0
#define REQUEST_STATUS_REJECTED 1

#define FAILURE_REASON_UNKNOWN      2
#define FAILURE_REASON_INTERNAL     3
#define FAILURE_REASON_P2P_PROTOCOL 4
#define FAILURE_REASON_MSG_LENGTH_MISMATCH 5

#define OPERATION_STATUS_UNKNOWN_OPERATION 6
#define OPERATION_STATUS_IN_PROGRESS       7
#define OPERATION_STATUS_WILL_SUCCEED      8
#define OPERATION_STATUS_SUCCEEDED         9
#define OPERATION_STATUS_FAILED            10

/* ************************* CS messages ***************************** */
/* these messages are exchanged between gnunetd and the clients (APIs) */

typedef HashCode160 DHT_TableId; 

/**
 * TCP communication: client to gnunetd: create apiId 
 **/
typedef struct DHT_CS_REQUEST_API_ID_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_API_ID_T), 
   *                         DHT_CS_PROTO_API_ID_REQUEST) 
   */
  CS_HEADER header;

  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

} DHT_CS_REQUEST_API_ID;

typedef struct DHT_TableConfig_t {
  unsigned int replicationCount;
  unsigned int parallelismCount;
  unsigned int maximumValuesPerKey;
  unsigned int expirationTimeSeconds;
  unsigned int flags;
  float cacheTimeMultiplier;
} DHT_TableConfig; 

/**
 * TCP communication: client to gnunetd: create new table 
 **/
typedef struct DHT_CS_REQUEST_CREATE_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_CREATE_T)+strlen(name)+1, 
   *                         DHT_CS_PROTO_CREATE_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Table settings (all fields in Network Byte Order)
   */
  DHT_TableConfig tableConfig;

  /**
   * Table name
   */
  char name[0]; 

} DHT_CS_REQUEST_CREATE;

/**
 * TCP communication: client to gnunetd: join table 
 **/
typedef struct DHT_CS_REQUEST_JOIN_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_JOIN_T), 
   *                         DHT_CS_PROTO_JOIN_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Address of the node that is the helper-when-joining node's address (Network Byte Order)
   */
  HostIdentity helperNodeAddress; 

  /**
   * Id of the to-be-joined table (Network Byte Order)
   */
  DHT_TableId joinedTableId;  

} DHT_CS_REQUEST_JOIN; 

/**
 * TCP communication: client to gnunetd: leave table 
 **/
typedef struct DHT_CS_REQUEST_LEAVE_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_LEAVE_T), 
   *                         DHT_CS_PROTO_LEAVE_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Id of the to-be-leaved table
   */
  DHT_TableId leavedTableId; 

} DHT_CS_REQUEST_LEAVE; 

/**
 * TCP communication: client to gnunetd: insert <key,value>-mapping to table 
 **/
typedef struct DHT_CS_REQUEST_INSERT_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_INSERT_T)+keyLength+valueLength, 
   *                         DHT_CS_PROTO_INSERT_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * The id of target table (a,b,c,d,e are all in NBO)
   * 
   */
  DHT_TableId targetTableId; 

  /**
   * Length of the key to be inserted (Network Byte Order)
   */
  unsigned short keyLength;
  
  /**
   * Length of the value to be inserted (Network Byte Order)
   */
  unsigned short valueLength;

  /**
   * Bytes that contain first key and then value (catenated).  
   */
  char keyAndValue[0];

} DHT_CS_REQUEST_INSERT;

/**
 * TCP communication: client to gnunetd: fetch <key,value>-mappings
 * for given key 
 **/
typedef struct DHT_CS_REQUEST_FETCH_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_FETCH_T), 
   *                         DHT_CS_PROTO_FETCH_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * The id of target table (a,b,c,d,e are all in NBO)
   * 
   */
  DHT_TableId targetTableId; 

  /**
   * Length of the key to be used for searching
   */
  int keyLength;
  
  /**
   * Bytes that contain the key.
   */
  char key[0];

} DHT_CS_REQUEST_FETCH;

/**
 * TCP communication: client to gnunetd: fetch info about joined tables 
 * from given dht node 
 **/
typedef struct DHT_CS_REQUEST_TABLES_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_TABLES_T), 
   *                         DHT_CS_PROTO_TABLES_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Address of the DHT node whose tables are to be fetched
   */
  HostIdentity nodeAddress; 

} DHT_CS_REQUEST_TABLES;

/**
 * TCP communication: client to gnunetd: fetch list of <key,value>-pairs that 
 * are inserted by DHT node at given DHT-Table
 **/
typedef struct DHT_CS_REQUEST_INSERTED_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_TABLES_T), 
   *                                DHT_CS_PROTO_TABLES_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Id of the table whose inserted <key,value>-pairs should be listed
   */
  DHT_TableId insertedTableId; 

} DHT_CS_REQUEST_INSERTED;

typedef struct {
  HashCode160 hashCode;
  cron_t insertionTime; 
} DHT_StoredDataReference; 

typedef struct {
  char *name; 
} DHT_TableMetaData; 

typedef struct {
  unsigned int dataLength;
  void *data;
} DHT_DataContainer;

typedef struct DHT_ResultSetItem_t {
  DHT_DataContainer * data;
  struct DHT_ResultSetItem_t *nextItem;
} DHT_ResultSetItem;

typedef struct {
  unsigned int errorCode;
  DHT_ResultSetItem *firstItem;
} DHT_ResultSet;


typedef struct DHT_TableSetItem_t {
  DHT_TableId tableId;
  DHT_TableMetaData tableMetaData;
  struct DHT_TableSetItem_t *nextItem;
} DHT_TableSetItem; 

typedef struct {
  unsigned int errorCode;
  DHT_TableSetItem *firstItem;
} DHT_TableSet;

typedef struct DHT_DataListItem_t {
  DHT_DataContainer *key;
  DHT_DataContainer *value;
  DHT_StoredDataReference uniqueReference;
  struct DHT_DataListItem_t *nextItem;
} DHT_DataListItem;

typedef struct {
  unsigned int errorCode;
  DHT_DataListItem *firstItem;
} DHT_DataList;



/**
 * TCP communication: client to gnunetd: stop republishing a <key,value>-pair 
 * that is inserted by DHT node at given DHT-Table
 **/
typedef struct DHT_CS_REQUEST_DROP_T {
  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_DROP_T), 
   *                                DHT_CS_PROTO_DROP_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Id of the table whose inserted <key,value>-pair should be dropped
   */
  DHT_TableId insertedTableId; 
  
  /**
   * Reference to the data that should be dropped
   */
  DHT_StoredDataReference droppedDataReference; 

} DHT_CS_REQUEST_DROP;

/**
 * TCP communication: client to gnunetd: query operation status
 **/
typedef struct DHT_CS_REQUEST_STATUS_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REQUEST_STATUS_T), 
   *                                DHT_CS_PROTO_STATUS_REQUEST) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header. Note that old requestId is used 
   * in this header to tell which operation is in question
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 
  
} DHT_CS_REQUEST_STATUS;

/**
 * TCP communication: gnunetd to client: ACK or DENIAL reply for a request.
 **/
typedef struct DHT_CS_REPLY_STANDARD_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REPLY_STANDARD_T), 
   *                                DHT_CS_PROTO_STANDARD_REPLY) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Status number for the request (Network Byte Order) - see CONSTANTS
   * in this file.
   */
  unsigned short requestStatusNumber;

} DHT_CS_REPLY_STANDARD;

/**
 * TCP communication: gnunetd to client: Failure notification for a request.
 **/
typedef struct DHT_CS_REPLY_FAILURE_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REPLY_FAILURE_T), 
   *                                DHT_CS_PROTO_FAILURE_REPLY) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Errornumber for the failure reason (Network Byte Order) - see CONSTANTS
   * in this file.
   */
  unsigned short failureReasonNumber;

} DHT_CS_REPLY_FAILURE;

/**
 * TCP communication: gnunetd to client: Results for a request.
 **/
typedef struct DHT_CS_REPLY_RESULTS_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REPLY_RESULTS_T)+length(data), 
   *                                DHT_CS_PROTO_RESULTS_REPLY) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Results data
   */
  char data[0]; 

} DHT_CS_REPLY_RESULTS;

/**
 * TCP communication: gnunetd to client: Operation status information.
 **/
typedef struct DHT_CS_REPLY_STATUS_T {

  /**
   * The TCP header (values: sizeof(DHT_CS_REPLY_STATUS_T), 
   *                                DHT_CS_PROTO_STATUS_REPLY) 
   */
  CS_HEADER header;
  
  /**
   * The DHT CS Message header
   */
  DHT_CS_MSG_HEADER dhtCSHeader; 

  /**
   * Operation status number - see CONSTANTS in this file
   */
  unsigned short operationStatusNumber; 

} DHT_CS_REPLY_STATUS;

#endif /* GNUNET_DHT_H */
