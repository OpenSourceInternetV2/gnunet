/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/ecrs_core.h
 * @brief support for ECRS encoding of files; also defines
 *        the structs for the various ECRS block types
 *        This file should NOT be installed, it is ONLY
 *        used internally!
 * @author Christian Grothoff
 */

#ifndef ECRS_CORE_H
#define ECRS_CORE_H

#include "gnunet_util.h"
#include "gnunet_datastore_service.h"

/**
 * @brief content hash key
 */
typedef struct
{
  HashCode512 key;
  HashCode512 query;
} CHK;

/**
 * @brief data block
 */
typedef struct
{

  /**
   * Type of the block, in network byte order.
   */
  unsigned int type;

  /* data follows here */

} DBlock;

typedef struct
{

  /**
   * Type of the block (IBLOCK), in network byte order.
   */
  DBlock iblock;

  CHK data[1];

} IBlock;

/**
 * @brief information required to download a file from GNUnet
 *
 * A FileIdentifier groups the information
 * required to download (and check) a file.
 */
typedef struct
{

  /**
   * Total size of the file in bytes. (network byte order (!))
   */
  unsigned long long file_length;

  /**
   * Query and key of the top IBlock.
   */
  CHK chk;

} FileIdentifier;

/**
 * @brief keyword block (advertising data under a keyword)
 */
typedef struct
{

  /**
   * Type of the block (KBLOCK), in network byte order.
   */
  unsigned int type;

  /**
   * Signature using RSA-key generated from search keyword.
   */
  Signature signature;

  /**
   * Key generated (!) from the H(keyword) as the seed!
   */
  PublicKey keyspace;

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here! */

} KBlock;

typedef struct
{

  /**
   * Type of the block (SBLOCK), in network byte order.
   */
  unsigned int type;

  /**
   * RSA signature (from pseudonym controlling the namespace)
   */
  Signature signature;

  /**
   * Public key of the pseudonym; S = H(subspace);
   */
  PublicKey subspace;

  /* from here on signed */

  /**
   * R = H(N-I)^S, used for routing!
   */
  HashCode512 identifier;
  /* from here on encrypted */

  /**
   * Time at which this SBlock was created;
   * in network byte order
   */
  TIME_T creationTime;

  /**
   * Interval (in seconds) how often the publisher intends to produce
   * an updated SBlock; ECRS_SBLOCK_UPDATE_NONE(0) is used for
   * non-updateable SBlocks, ECRS_SBLOCK_UPDATE_SPORADIC(-1) is used
   * for entries without a fixed update frequency; in network byte
   * order
   */
  TIME_T updateInterval;

  /**
   * N, the identifier that will be used for the
   * next revision of this SBlock.
   */
  HashCode512 nextIdentifier;

  /**
   * I, the increment between identifiers (used to enable
   * skipping of blocks by appying multiple increments.
   */
  HashCode512 identifierIncrement;

  /* 0-terminated URI follows here! */

  /* variable-size Meta-Data follows here! */
} SBlock;

typedef struct
{

  /**
   * Type of the block (NBLOCK), in network byte order.
   */
  unsigned int type;

  Signature signature;          /* 256 b */

  PublicKey subspace;           /* S = H(subspace); 264 b */

  /**
   * Must be all zeros
   */
  HashCode512 identifier;

  /* The REST (from here on) is encrypted! */

  /**
   * Identifier of the namespace
   */
  HashCode512 namespace;

  /**
   * Key of an (optional) root entry into the namespace
   * (use all-zeros for not given).
   */
  HashCode512 rootEntry;

  /* variable-size Meta-Data follows here! */
} NBlock;

/**
 * @brief keyword-NBlock (advertising namespace under a keyword)
 */
typedef struct
{

  /**
   * Type of the block (KNBLOCK), in network byte order.
   */
  unsigned int type;

  KBlock kblock;

  NBlock nblock;
} KNBlock;

/**
 * Perform on-demand content encoding.
 *
 * @param data the data to encode
 * @param len the length of the data
 * @param query the query that was used to query
 *  for the content (verified that it matches
 *  data)
 * @param value the encoded data (set);
 *        the anonymityLevel is to be set to 0
 *        (caller should have checked before calling
 *        this method).
 * @return OK on success, SYSERR if data does not
 *  match the query
 */
int fileBlockEncode (const DBlock * data,
                     unsigned int len,
                     const HashCode512 * query, Datastore_Value ** value);

/**
 * Get the query that will be used to query for
 * a certain block of data.
 */
void fileBlockGetQuery (const DBlock * data,
                        unsigned int len, HashCode512 * query);


/**
 * Get the key that will be used to decrypt
 * a certain block of data.
 */
void fileBlockGetKey (const DBlock * data,
                      unsigned int len, HashCode512 * key);

/**
 * What is the type of the given block of data?
 */
unsigned int getTypeOfBlock (unsigned int size, const DBlock * data);

/**
 * What is the main query (the one that is used in
 * routing and for the DB lookup) for the given
 * content and block type?
 *
 * @param type the type of the encoding
 * @param data the content (encoded)
 * @param verify should the data be verified?  Use NO if
 *         data integrity has been checked before (maybe much faster!)
 * @param query set to the query for the content
 * @return SYSERR if the content is invalid or
 *   the content type is not known
 */
int getQueryFor (unsigned int size,
                 const DBlock * data, int verify, HashCode512 * query);

/**
 * Verify that the given Datum is a valid response
 * to a given query.
 *
 * @param type the type of the queryo
 * @param size the size of the data
 * @param data the encoded data
 * @param knownDatumQuery result of getQueryFor
 * @param keyCount the number of keys in the query
 * @param keys the keys of the query
 * @return YES if this data matches the query, otherwise
 *         NO; SYSERR if the keyCount does not match the
 *         query type
 */
int isDatumApplicable (unsigned int type,
                       unsigned int size,
                       const DBlock * data,
                       const HashCode512 * knownDatumQuery,
                       unsigned int keyCount, const HashCode512 * keys);

#endif
