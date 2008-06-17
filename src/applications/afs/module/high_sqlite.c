/*
     This file is part of GNUnet.
     (C) 2001 - 2004 Christian Grothoff (and other contributing authors)

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
 * @author Nils Durner
 * @file applications/afs/module/high_sqlite.c
 * @brief SQLite based implementation of high database API
 *
 * Database: SQLite
 */

#include "high_backend.h"
#include "platform.h"
#include <sqlite3.h>

#define DEBUG_SQLITE NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(cmd, dbh) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbf)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(level, cmd, dbh) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbf)); } while(0);


/**
 * @brief SQLite wrapper
 */
typedef struct {
  sqlite3 *dbf; 
  unsigned int i;          /* database index */
  unsigned int n;          /* total number of databases */
  Mutex DATABASE_Lock_;
  char *fn;                /* filename of this bucket */
  double count;            /* number of rows in the db */
  double payload;          /* bytes used */
  
  /* Precompiled SQL */
  sqlite3_stmt *getContent, *writeContent, *updPrio, *getRndCont1,
    *getRndCont2, *exists, *updContent;
} sqliteHandle;


/**
 * @brief Encode a binary buffer "in" of size n bytes so that it contains
 *        no instances of characters '\'' or '\000'.  The output is
 *        null-terminated and can be used as a string value in an INSERT
 *        or UPDATE statement.
 * @param in input
 * @param n size of in
 * @param out output
 */
int sqlite_encode_binary(const unsigned char *in, int n, unsigned char *out){
  char c;
  unsigned char *start = out;
  
  n--;
  for (; n > -1; n--) {
    c = *in;
    in++;
    
    if (c == 0 || c == 1) {
      *out = 1;
      out++;
      *out = c + 1;
    } else {
      *out = c;
    }
    out++;
  }
  *out = 0;
  
  return (int) (out - start);
}

/**
 * @brief Decode the string "in" into binary data and write it into "out".
 * @param in input
 * @param out output
 * @return number of output bytes, -1 on error
 */
int sqlite_decode_binary(const unsigned char *in, unsigned char *out){
  char c;
  unsigned char *start = out;
  
  while((c = *in)) {
    if (c == 1) {
      in++;
      *out = *in - 1;
    }
    else
      *out = c;
    
    in++;
    out++;
  }
  
  return (int) (out - start);
}

/**
 * @param i index of the database
 * @param n total number of databases
 */
HighDBHandle initContentDatabase(unsigned int i,
         unsigned int n) {
  sqliteHandle * dbh;
  char *dummy, *dir, *afsdir;
  size_t nX;
  sqlite3_stmt *stmt;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: initializing database\n");
#endif 

  dbh = MALLOC(sizeof(sqliteHandle));
  
  dbh->n = n;
  dbh->i = i;
  dbh->count = 0;
  dbh->payload = 0;

  afsdir = getFileName("AFS",
           "AFSDIR",
           _("Configuration file must specify directory for "
             "storing AFS data in section '%s' under '%s'.\n"));
  dir = MALLOC(strlen(afsdir) + strlen(CONTENTDIR) + 2);
  strcpy(dir, afsdir);
  strcat(dir, "/");
  strcat(dir, CONTENTDIR);
  FREE(afsdir);
  mkdirp(dir);
  nX = strlen(dir) + 6 + 4 + 256;  /* 6 = "bucket", 4 = ".dat" */
  dbh->fn = MALLOC(strlen(dir) + 6 + 4 + 256);
  SNPRINTF(dbh->fn, nX, "%s/bucket.%u.%u.dat", dir, n, i);

  if (sqlite3_open(dbh->fn, &dbh->dbf) != SQLITE_OK) {
    LOG(LOG_ERROR, 
        _("Unable to initialize SQLite.\n"));
    FREE(dbh->fn);
    FREE(dbh);
    return NULL;
  }
  
  sqlite3_exec(dbh->dbf, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "PRAGMA count_changes=OFF", NULL, NULL, NULL);
  
  sqlite3_prepare(dbh->dbf, "Select 1 from sqlite_master where tbl_name"
    " = 'data'", 51, &stmt, (const char**) &dummy);
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    if (sqlite3_exec(dbh->dbf, "CREATE TABLE data ("
           "  hash blob default '' PRIMARY KEY,"
           "  priority integer default 0,"
           "  type integer default 0,"
           "  fileIndex integer default 0,"
           "  fileOffset integer default 0,"
           "  doubleHash blob default '',"
           "  content blob default '')", NULL, NULL,
           NULL) != SQLITE_OK) {
      LOG_SQLITE(LOG_ERROR, 
          "sqlite_query",
          dbh);
      FREE(dbh->fn);
      FREE(dbh);
      return NULL;
    }
  }
  sqlite3_finalize(stmt);
    
  sqlite3_exec(dbh->dbf,
                "CREATE INDEX idx_key ON data (priority)",
                NULL, NULL, NULL);
                   
  if (sqlite3_prepare(dbh->dbf, "SELECT content, type, priority, " \
         "doubleHash, fileOffset, fileIndex FROM data WHERE hash=?", 83,
         &dbh->getContent, (const char **) &dummy) != SQLITE_OK ||
         
      sqlite3_prepare(dbh->dbf, "UPDATE data SET priority = priority + ? WHERE" \
         " hash = ?", 54, &dbh->updPrio, (const char **) &dummy) != SQLITE_OK ||
         
      sqlite3_prepare(dbh->dbf, "REPLACE INTO data "
         "(content, priority, fileOffset, fileIndex, doubleHash, type, hash)"
         " VALUES (?, ?, ?, ?, ?, ?, ?)", 113, &dbh->writeContent,
         (const char **) &dummy) != SQLITE_OK ||
         
      sqlite3_prepare(dbh->dbf, "SELECT hash, type, priority, fileOffset, "
         "fileIndex, content FROM data WHERE hash >= ? "
         "AND (type = ? OR type = ?) LIMIT 1", 111,
         &dbh->getRndCont1, (const char **) &dummy) != SQLITE_OK ||
                  
      sqlite3_prepare(dbh->dbf, "SELECT hash, type, priority, fileOffset, "
         "fileIndex, content FROM data WHERE hash NOTNULL "
         "AND (type = ? OR type = ?) LIMIT 1", 114, &dbh->getRndCont2,
         (const char **) &dummy) != SQLITE_OK ||
     
      sqlite3_prepare(dbh->dbf, "SELECT length(hash), length(doubleHash), "
         "length(content) from data WHERE hash=?", 79,
         &dbh->exists, (const char **) &dummy) != SQLITE_OK ||
         
      sqlite3_prepare(dbh->dbf, "UPDATE data Set content = ?, priority = ?, "
         "fileOffset = ?, fileIndex = ?, doubleHash = ?, type = ? WHERE "
         "hash = ?", 113, &dbh->updContent,
         (const char **) &dummy) != SQLITE_OK) {
        
      LOG_SQLITE(LOG_ERROR, 
          "precompiling",
          dbh);
      FREE(dbh->fn);
      FREE(dbh);
      return NULL;
  }
  
  nX = sqlite3_prepare(dbh->dbf, 
    "Select fileOffset from data where hash = 'PAYLOAD'", 50, &stmt,
    (const char **) &dummy);
  if (nX == SQLITE_OK) {
    nX = sqlite3_step(stmt);
    
    if (nX == SQLITE_DONE) {
      dbh->payload = 0;
      nX = SQLITE_OK;
    }
    else if (nX == SQLITE_ROW) {
      dbh->payload = sqlite3_column_double(stmt, 0);
      nX = SQLITE_OK;
    }
  }
  sqlite3_finalize(stmt);
  
  if (nX != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, 
        "sqlite_query",
        dbh);
    FREE(dbh->fn);
    FREE(dbh);
    return NULL;
  }
  
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);  

  return dbh;
}

/**
 * Normal shutdown of the storage module
 *
 * @param handle the database
 */
void doneContentDatabase(HighDBHandle handle) {
  sqliteHandle *dbh = handle;
  sqlite3_stmt *stmt;
  char *dummy;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: closing database\n");
#endif 

  sqlite3_finalize(dbh->getContent);
  sqlite3_finalize(dbh->writeContent);
  sqlite3_finalize(dbh->updPrio);
  sqlite3_finalize(dbh->getRndCont1);
  sqlite3_finalize(dbh->getRndCont2);
  sqlite3_finalize(dbh->exists);
  sqlite3_finalize(dbh->updContent);

  sqlite3_prepare(dbh->dbf,
    "REPLACE into data(hash, fileOffset) values ('PAYLOAD', ?)", 58,
    &stmt, (const char **) &dummy);
  sqlite3_bind_double(stmt, 1, dbh->payload);
  if (sqlite3_step(stmt) != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
  }
  sqlite3_finalize(stmt);
  
  if (sqlite3_close(dbh->dbf) != SQLITE_OK)
    LOG_SQLITE(LOG_ERROR, "sqlite_close", dbh);

  MUTEX_DESTROY(&dbh->DATABASE_Lock_);

  FREE(dbh->fn);
  FREE(dbh);
}

/**
 * Call a method for each key in the database and
 * call the callback method on it. 
 *
 * @param handle the database
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
int forEachEntryInDatabase(HighDBHandle handle,
                EntryCallback callback,
                void * data) {
  sqliteHandle *dbh = handle;
  sqlite3_stmt *stmt;
  ContentIndex ce;
  void *result;
  int count = 0;
  int len;
  char *dummy, *escapedCol6, *col6;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: iterating through the database\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  if (sqlite3_prepare(dbh->dbf, "SELECT content, type, priority, doubleHash, "
           "fileOffset, fileIndex, hash FROM data", 80, &stmt,
           (const char **) &dummy) != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) { 
    char *escapedRes;
    
    escapedRes = (char *) sqlite3_column_blob(stmt, 0);
    if (strlen(escapedRes) > 0) {
      result = MALLOC(strlen(escapedRes) + 1);
      len = sqlite_decode_binary(escapedRes, result);
    } else {
      result = NULL;
      len = 0;
    }

    escapedCol6 = (char *) sqlite3_column_blob(stmt, 6);
    col6 = MALLOC(strlen(escapedCol6) + 1);
    sqlite_decode_binary(escapedCol6, col6);

    ce.type = htons(sqlite3_column_int(stmt, 1));
    ce.importance = htonl(sqlite3_column_int(stmt, 2));
    if (ntohs(ce.type)==LOOKUP_TYPE_3HASH) {
      char *escapedHash, *hash;
      
      escapedHash = (char *) sqlite3_column_blob(stmt, 3);
      hash = MALLOC(strlen(escapedHash) + 1);
      if (sqlite_decode_binary(escapedHash, hash) == sizeof(HashCode160))
        memcpy(&ce.hash, 
               hash,
               sizeof(HashCode160));
        FREE(hash);
      } else {
        memcpy(&ce.hash, col6, sizeof(HashCode160));
    }

    ce.fileOffset = htonl(sqlite3_column_int(stmt, 4));
    ce.fileNameIndex = htons(sqlite3_column_int(stmt, 5));       
    callback((HashCode160*) col6,
       &ce,
       result, /* freed by callback */
       len,
       data);
    FREE(col6);
    count++;
  }
    
  sqlite3_finalize(stmt);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: reached end of database\n");
#endif 
  
  return count;
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 * @return the number of entries
 */
int countContentEntries(HighDBHandle handle) {
  sqliteHandle *dbh = handle;
  sqlite3_stmt *stmt;
  char *dummy;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: count entries\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  if (! dbh->count) {
    if (sqlite3_prepare(dbh->dbf, "SELECT count(*) from data", 25, &stmt,
         (const char **) &dummy) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_ROW) {
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return(SYSERR);    
    }
  
    dbh->count = sqlite3_column_double(stmt, 0);
  
    sqlite3_finalize(stmt);
  }
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: count %.0f\n", dbh->count);
#endif 
     
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return dbh->count;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database
 * @param query the hashcode representing the entry
 * @param ce the meta-data of the entry (set)
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @param prio by how much should the priority of the content be changed
 *           (if it is found)
 * @return the number of bytes read on success, -1 on failure
 */ 
int readContent(HighDBHandle handle, const HashCode160 *query,
          ContentIndex *ce, void **result, int prio) {
  sqliteHandle *dbh = handle;
  char *escapedHash, *escapedRes;
  int len, ret;

#if DEBUG_SQLITE
  {
    char block[33];
    hash2enc(query, (EncName *) block);
    LOG(LOG_DEBUG, "SQLite: read content %s\n", block);
  }
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  escapedHash = MALLOC(sizeof(HashCode160)*2 + 2);
  len = sqlite_encode_binary((char *) query, sizeof(HashCode160), escapedHash);

  ret = sqlite3_bind_blob(dbh->getContent, 1, escapedHash, len,
    SQLITE_TRANSIENT);
  if (ret == SQLITE_OK) {
    if((ret = sqlite3_step(dbh->getContent)) == SQLITE_DONE) {
#if DEBUG_SQLITE
      LOG(LOG_DEBUG, "SQLite: not found\n");
#endif
      /* no error, just data not found */
      sqlite3_reset(dbh->getContent);
      FREE(escapedHash);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    } else if (ret == SQLITE_ROW)
        ret = SQLITE_OK;
  }
 
  if (ret != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    FREE(escapedHash);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  
  escapedRes = (char *) sqlite3_column_blob(dbh->getContent, 0);
  if (strlen(escapedRes) > 0) {
    *result = MALLOC(strlen(escapedRes) + 1);
    len = sqlite_decode_binary(escapedRes, *result);
  } else {
    *result = NULL;
    len = 0;
  }
  
  ce->type = htons(sqlite3_column_int(dbh->getContent, 1));
  ce->importance = htonl(sqlite3_column_int(dbh->getContent, 2));
  if (ntohs(ce->type)==LOOKUP_TYPE_3HASH) {
    char *doubleHashEsc, *doubleHash;
    
    doubleHashEsc = (char *) sqlite3_column_blob(dbh->getContent, 3);
    doubleHash = MALLOC(strlen(doubleHashEsc));
    
    if (sqlite_decode_binary(doubleHashEsc, doubleHash) == sizeof(HashCode160))
      memcpy(&ce->hash, doubleHash, sizeof(HashCode160));
    FREE(doubleHash);
  } else {
    memcpy(&ce->hash, query, sizeof(HashCode160));
  }

  ce->fileOffset = htonl(sqlite3_column_int(dbh->getContent, 4));
  ce->fileNameIndex = htons(sqlite3_column_int(dbh->getContent, 5));

  sqlite3_reset(dbh->getContent);

  if (prio != 0) {
    sqlite3_bind_int(dbh->updPrio, 1, prio);
    sqlite3_bind_blob(dbh->updPrio, 2, escapedHash, strlen(escapedHash),
                      SQLITE_TRANSIENT);
    if (sqlite3_step(dbh->updPrio) != SQLITE_DONE)
      LOG_SQLITE(LOG_ERROR, "updating priority", dbh);
    sqlite3_reset(dbh->updPrio);
  }

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  FREE(escapedHash);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done reading content\n");
#endif 
  
  return len;
}

/**
 * Write content to the db.  Overwrites existing data.
 * If ce->type is LOOKUP_TYPE_3HASH, ce->hash will contain
 * a double hash which must be converted to 3HASH, later to be 
 * retrievable by 3HASH, but the 2HASH must be stored so it can
 * be retrieved by readContent(). For indexed content,
 * ce->fileOffset and ce->fileNameIndex must be stored.
 * Note that block can be NULL for on-demand encoded content
 * (in this case, len must also be 0).
 *
 * @param handle the database
 * @param ce the meta-data for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int writeContent(HighDBHandle handle, const ContentIndex * ce,
     unsigned int len, const void * block) {
  sqliteHandle *dbh = handle;
  HashCode160 tripleHash;
  char *doubleHash;
  char *escapedBlock;
  char *escapedHash;
  int n, blockLen, hashLen, dhashLen;
  sqlite3_stmt *stmt;
  unsigned long rowLen;

#if DEBUG_SQLITE
  {
    char block[33];
    hash2enc(&ce->hash, (EncName *) block);
    LOG(LOG_DEBUG, "SQLite: write content %s\n", block);
  }
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  rowLen = 0;
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  
  if(ntohs(ce->type) == LOOKUP_TYPE_3HASH) {
    hash(&ce->hash, 
       sizeof(HashCode160),
   &tripleHash);
    sqlite_encode_binary((char *)&tripleHash, sizeof(HashCode160), escapedHash);
    doubleHash = MALLOC(2*sizeof(HashCode160)+1);
    sqlite_encode_binary((char *)&ce->hash, sizeof(HashCode160), doubleHash);
  } else {
    doubleHash = NULL;
    sqlite_encode_binary((char *)&ce->hash, sizeof(HashCode160), escapedHash);
  }

  escapedBlock = MALLOC(2 * len + 1);
  sqlite_encode_binary((char *)block, len, escapedBlock);
  
  /* Do we have this content already? */
  sqlite3_bind_blob(dbh->exists, 1, escapedHash, strlen(escapedHash),
                    SQLITE_TRANSIENT);
  n = sqlite3_step(dbh->exists);
  if (n == SQLITE_DONE)
    stmt = dbh->writeContent;
  else if (n == SQLITE_ROW) {
    rowLen -= sqlite3_column_int(dbh->exists, 1) - 
      sqlite3_column_int(dbh->exists, 2) - sqlite3_column_int(dbh->exists, 3) -
      4 * sizeof(int);
    if (dbh->payload > rowLen)
      dbh->payload -= rowLen;
    else
      dbh->payload = 0;
    stmt = dbh->updContent;
  }
  else {
    sqlite3_reset(dbh->exists);
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    FREE(escapedBlock);
    FREE(escapedHash);
    FREENONNULL(doubleHash);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  sqlite3_reset(dbh->exists);

  blockLen = strlen(escapedBlock);
  hashLen = strlen(escapedHash);
  dhashLen = doubleHash ? strlen(doubleHash) : 0;

  sqlite3_bind_blob(stmt, 1, escapedBlock, blockLen,
                    SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, ntohl(ce->importance));
  sqlite3_bind_int(stmt, 3, ntohl(ce->fileOffset));
  sqlite3_bind_int(stmt, 4, ntohs(ce->fileNameIndex));
  sqlite3_bind_blob(stmt, 5, doubleHash, dhashLen, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 6, ntohs(ce->type));
  sqlite3_bind_blob(stmt, 7, escapedHash, hashLen,
                    SQLITE_TRANSIENT);
  n = sqlite3_step(stmt);
  FREE(escapedBlock);
  FREE(escapedHash);
  FREENONNULL(doubleHash);
  sqlite3_reset(stmt);
  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  rowLen = hashLen + dhashLen + blockLen + sizeof(int) * 4;
  if (stmt == dbh->writeContent)
    dbh->count++;
  dbh->payload += rowLen;
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
 
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done writing content\n");
#endif 

  return OK;
}

/**
 * Free space in the database by removing one block
 *
 * @param handle the database
 * @param name hashcode for the block to be deleted
 */
int unlinkFromDB(HighDBHandle handle,
     const HashCode160 * name) {
  sqliteHandle * dbh = handle;
  char *escapedHash, *dummy;
  size_t n;
  sqlite3_stmt *stmt;
  unsigned long rowLen;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: delete block\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  escapedHash = MALLOC(2 * sizeof(HashCode160) + 1);
  sqlite_encode_binary((char *)name, sizeof(HashCode160), escapedHash);

  sqlite3_bind_blob(dbh->exists, 1, escapedHash, strlen(escapedHash),
                    SQLITE_TRANSIENT);
  n = sqlite3_step(dbh->exists);
  if (n == SQLITE_ROW) {
    rowLen = sqlite3_column_int(dbh->exists, 1) - 
      sqlite3_column_int(dbh->exists, 2) - sqlite3_column_int(dbh->exists, 3) -
      4 * sizeof(int);
    if (dbh->payload > rowLen)
      dbh->payload -= rowLen;
    else
      dbh->payload = 0;
  }
  sqlite3_reset(dbh->exists);

  n = sqlite3_prepare(dbh->dbf, "DELETE FROM data WHERE hash = ?", 31,
      &stmt, (const char **) &dummy);
  if (n == SQLITE_OK) {
    sqlite3_bind_blob(stmt, 1, escapedHash, strlen(escapedHash),
                      SQLITE_TRANSIENT);
    n = sqlite3_step(stmt);
  }
  
  FREE(escapedHash);
  sqlite3_finalize(stmt);

  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  dbh->count--;

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: block deleted\n");
#endif 
  
  return OK;
}

/**
 * Get a random content block from database. 
 * Tries to use indexes efficiently.
 *
 * Code supplied by H. Pagenhardt
 *
 * @param handle the database
 * @param ce the meta-data of the random content (set)
 * @return OK on success, SYSERR on error
 */
int getRandomContent(HighDBHandle handle,                   
                     ContentIndex * ce,
                     CONTENT_Block ** data) {
  sqliteHandle *dbh = handle;
  char *escapedHash;
  char *hash;
  int i;
  int found;
  sqlite3_stmt *stmt;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: get random content\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  hash = MALLOC(sizeof(HashCode160));
  escapedHash = MALLOC(2 * sizeof(HashCode160) + 1);

  found = NO;
  for (i=0; i < sizeof(HashCode160); i++)
    hash[i] = randomi(256);
  
  sqlite_encode_binary(hash, sizeof(HashCode160), escapedHash);

  stmt = dbh->getRndCont1;
  sqlite3_bind_blob(stmt, 1, escapedHash, strlen(escapedHash),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, LOOKUP_TYPE_CHK);
  sqlite3_bind_int(stmt, 3, LOOKUP_TYPE_CHKS);
    
  i = sqlite3_step(stmt);
  
  if(!(i == SQLITE_ROW || i == SQLITE_DONE)) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    sqlite3_reset(stmt);
    FREE(escapedHash);
    FREE(hash);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  
  if (i != SQLITE_ROW) {
    sqlite3_reset(stmt);
    
    stmt = dbh->getRndCont2;
    sqlite3_bind_int(stmt, 1, LOOKUP_TYPE_CHK);
    sqlite3_bind_int(stmt, 2, LOOKUP_TYPE_CHKS);
    
    i = sqlite3_step(stmt);

    if(!(i == SQLITE_DONE || i == SQLITE_ROW)) {
      LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
      sqlite3_reset(stmt);
      FREE(escapedHash);
      FREE(hash);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    }
  }
  
  if(sqlite3_data_count(stmt) > 0) {
    char *escapedHash, *hash;
    
    escapedHash = (char *) sqlite3_column_blob(stmt, 0);
    hash = MALLOC(sizeof(HashCode160));
    sqlite_decode_binary(escapedHash, hash);
    memcpy(&ce->hash,
           hash,
           sizeof(HashCode160));
    FREE(hash);
    
    ce->type = htons(sqlite3_column_int(stmt, 1));
    ce->importance = htonl(sqlite3_column_int(stmt, 2));
    ce->fileOffset = htonl(sqlite3_column_int(stmt, 3));
    ce->fileNameIndex = htons(sqlite3_column_int(stmt, 4));

    if (ntohs(ce->fileNameIndex) == 0) {
      *data = MALLOC(sizeof(CONTENT_Block));
      sqlite_decode_binary(sqlite3_column_blob(stmt, 5),
        (unsigned char *) *data);
    }

    found = YES;
  }

  sqlite3_reset(stmt);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  FREE(escapedHash);
  FREE(hash);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done getting random content\n");
#endif 

  if(found==YES) {
    return OK;
  } else {
    LOG(LOG_DEBUG,
        "'%s' did not find anything!\n",
        __FUNCTION__);
    return SYSERR;
  }
}

/**
 * Get the lowest priority value of all content in the store.
 *
 * @param handle the database
 * @return the lowest priority
 */
unsigned int getMinimumPriority(HighDBHandle handle) {
  sqliteHandle *dbh = handle;
  sqlite3_stmt *stmt;
  unsigned int minPrio = 0;
  int i;
  char *dummy;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: get minimum priority\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  i = sqlite3_prepare(dbh->dbf, "SELECT MIN(priority) FROM data",
                      30, &stmt, (const char **) &dummy);
  if (i == SQLITE_OK) {
    i = sqlite3_step(stmt);
  }

  if (!(i == SQLITE_ROW || i == SQLITE_DONE)) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return 0;
  }
  if (i != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return 0; /* no entries in DB */
  }
  
  minPrio = sqlite3_column_int(stmt, 0);
  
  sqlite3_finalize(stmt);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

  return minPrio;
}

/**
 * Deletes some least important content
 * 
 * @param handle the database
 * @param count the number of entries to delete
 * @param callback method to call on each deleted entry
 * @param closure extra argument to callback
 * @return OK on success, SYSERR on error
 */
int deleteContent(HighDBHandle handle,
      unsigned int count,
      EntryCallback callback,
      void *closure) {
  sqliteHandle *dbh = handle;
  sqlite3_stmt *stmt;
  HashCode160 *deleteThese;
  char *escapedHash, *dummy, *scratch;
  int i=0, len;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: delete least important content (%i rows)\n", count);
#endif
 
  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  /* Collect hashes to delete */
  scratch = MALLOC(72);
  len = SNPRINTF(scratch, 72, "SELECT hash FROM data "
     "ORDER BY priority ASC LIMIT %i", count);
  i = sqlite3_prepare(dbh->dbf, scratch, len, &stmt, (const char **) &dummy);
  FREE(scratch);
  if (i != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  deleteThese = MALLOC(count * sizeof(HashCode160));
  i=0;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    char *escapedHash;
    
    escapedHash = (char *) sqlite3_column_blob(stmt, 0);
    sqlite_decode_binary(escapedHash, (char *) &deleteThese[i++]);
  }
  sqlite3_finalize(stmt);
 
  /* Delete collected hashes */
  count=i;
  escapedHash = MALLOC(2 * sizeof(HashCode160) + 1);
  for(i=0; i < count; i++) {
    ContentIndex ce;
    void *data;
    int dlen;
    unsigned long rowLen;
    
    data = NULL;
    dlen = readContent(handle,
           &deleteThese[i],
           &ce,
           &data,
           0);
    if (dlen >= 0) {
      if (callback != NULL) {
        callback(&deleteThese[i], &ce, data, dlen, closure);
      } else {
        FREENONNULL(data);
      }
    }

    sqlite3_bind_blob(dbh->exists, 1, escapedHash, strlen(escapedHash),
                      SQLITE_TRANSIENT);
    i = sqlite3_step(dbh->exists);
    if (i == SQLITE_ROW) {
      rowLen = sqlite3_column_int(dbh->exists, 1) - 
        sqlite3_column_int(dbh->exists, 2) - sqlite3_column_int(dbh->exists, 3) -
        4 * sizeof(int);
      if (dbh->payload > rowLen)
        dbh->payload -= rowLen;
      else
        dbh->payload = 0;
    }
    sqlite3_reset(dbh->exists);

    sqlite_encode_binary((char *) &deleteThese[i], sizeof(HashCode160),
                         escapedHash);
    i = sqlite3_prepare(dbh->dbf, "DELETE FROM data WHERE hash = ?", 31,
                        &stmt, (const char **) &dummy);
    if (i == SQLITE_OK) {
      sqlite3_bind_blob(stmt, 1, escapedHash, strlen(escapedHash),
                        SQLITE_TRANSIENT);
      i = sqlite3_step(stmt);
    }
    
    if(i != SQLITE_DONE)
      LOG_SQLITE(LOG_ERROR, "sqlite_query", dbh);
    
    sqlite3_finalize(stmt);
  }
    
  FREE(escapedHash);
  FREE(deleteThese);
  
  dbh->count -= count;
  
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
  return OK;
}

/**
 * Estimate how many blocks can be stored in the DB
 * before the quota is reached.
 *
 * @param handle the database
 * @param quota the number of kb available for the DB
 * @return number of blocks left
 */ 
int estimateAvailableBlocks(HighDBHandle handle,
          unsigned int quota) {       
  sqliteHandle *dbh = handle;
  double ret;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  ret = dbh->payload / 1024 * 1.15;

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: kbytes used: %.0f, quota: %i\n",
    ret, quota);
#endif
  
  return quota - ret;
}

/**
 * Close and delete the database.
 *
 * @param handle the database
 */
void deleteDatabase(HighDBHandle handle) {
  sqliteHandle *dbh = handle;
  
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);

  sqlite3_finalize(dbh->getContent);
  sqlite3_finalize(dbh->writeContent);
  sqlite3_finalize(dbh->updPrio);
  sqlite3_finalize(dbh->getRndCont1);
  sqlite3_finalize(dbh->getRndCont2);
  sqlite3_finalize(dbh->exists);
  sqlite3_finalize(dbh->updContent);

  sqlite3_close(dbh->dbf);
  UNLINK(dbh->fn);

  FREE(dbh->fn);
  FREE(dbh);
}

/* end of high_sqlite.c */
