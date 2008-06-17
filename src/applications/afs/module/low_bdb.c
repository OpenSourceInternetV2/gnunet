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
 * @file applications/afs/module/low_bdb.c
 * @brief bdb based implementation of low database API
 * @author Nils Durner
 **/

#include "low_backend.h"
#include "platform.h"
#include <db.h>

/**
 * Extension for the Berkeley DB.
 **/
#define BDB_EXT ".bdb"

/**
 * Log DEBUG-Info?
 **/
#define BDB_DEBUG NO

/**
 * A bdb wrapper
 **/
typedef struct {

  /**
   * BDB handle.
   **/
  DB *dbf;
  
  /**
   * Database environment
   **/
  DB_ENV *dbenv;

  int deleteSize;

  /**
   * Name of the database file.
   **/
  char * filename;
  
  /**
   * The database environment's home directory
   **/
  char * home;
  
  /**
   * Synchronized access
   **/
  Mutex DATABASE_Lock_;

} bdbHandle;

/* declared in logging.c */
extern FILE *logfile;

void handleError(int err, bdbHandle *dbh);


/**
 * Close BDB environment and database
 * @param dbh the BDB handle
 **/
int bdbClose(bdbHandle *dbh)
{
  int ret;
  
  ret = dbh->dbf->close(dbh->dbf, 0);
  if (ret != 0)
    return ret;
  
  return dbh->dbenv->close(dbh->dbenv, 0);
}

/**
 * Open BDB environment and database
 * @param dbh the BDB handle
 **/
int bdbOpen(bdbHandle *dbh)
{
  int ret;
  
#if BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Initializing the database environment\n");
#endif

  ret = db_env_create(&dbh->dbenv, 0);
  if (ret != 0)
  {
    LOG(LOG_ERROR, 
        "ERROR: Unable to init the database environment: %s\n",
        db_strerror(ret));
    handleError(ret, dbh);
    return ret;
  }

  dbh->dbenv->set_errfile(dbh->dbenv, (FILE *) getLogfile());

  ret = dbh->dbenv->open(dbh->dbenv, dbh->home, DB_CREATE |
    DB_THREAD | DB_INIT_MPOOL, 0);
  if (ret != 0)
  {
    LOG(LOG_ERROR, 
        "ERROR: Unable to open the database environment: %s\n",
        db_strerror(ret));
    handleError(ret, dbh);
    return ret;
  }
  
#if BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Initializing the Berkeley DB\n");
#endif

  ret = db_create(&dbh->dbf, dbh->dbenv, 0);
  if (ret != 0) 
  {
    LOG(LOG_ERROR, 
        "ERROR: Unable to init the Berkeley DB: %s\n",
        db_strerror(ret));
    handleError(ret, dbh);
    return ret;
  }

  dbh->dbf->set_pagesize(dbh->dbf, 8192);

#if BDB_DEBUG
 LOG(LOG_DEBUG, 
     "BDB: Opening datafile %s\n", 
     dbh->filename);
#endif

#if DB_VERSION_MAJOR * 10 + DB_VERSION_MINOR >= 41
  ret = dbh->dbf->open(dbh->dbf, NULL, dbh->filename,
                      "data", DB_HASH, DB_CREATE | DB_THREAD,
                      S_IRUSR | S_IWUSR);
#else
  ret = dbh->dbf->open(dbh->dbf, dbh->filename,
                       "data", DB_HASH, DB_CREATE | DB_THREAD,
                       S_IRUSR | S_IWUSR);
#endif
  if (ret != 0) {
    LOG(LOG_ERROR, 
        "ERROR: Unable to open the Berkeley DB: %s\n",
        db_strerror(ret));
    handleError(ret, dbh);
    return ret;
  }

#if BDB_DEBUG
 LOG(LOG_DEBUG, 
     "BDB: Datafile opened\n");
#endif

  dbh->deleteSize = 0;

  return 0;
}

/**
 * Handle BDB errors
 * @param err the error code
 * @param dbh the BDB handle
 **/
void handleError(int err, bdbHandle *dbh)
{
  if (err == DB_NOSERVER || err == DB_RUNRECOVERY)
  {
    LOG(LOG_FATAL, "BDB panic, that's the end\n");
    FREE(dbh->filename);
    FREE(dbh->home);
    MUTEX_DESTROY(&dbh->DATABASE_Lock_);
    FREE(dbh);
    exit(1);
  }
}

/**
 * Open a bdb database (for content)
 * @param dir the directory where content is configured
 *         to be stored (e.g. data/content). A file 
 *         called ${dir}.bdb is used instead
 **/
static bdbHandle * getDatabase(char * dir)
{
  char *ff;
  bdbHandle * result;
  int len;

  result = MALLOC(sizeof(bdbHandle));
  ff = MALLOC(strlen(dir)+strlen(BDB_EXT)+1);
  strcpy(ff, dir);
  len = strlen(ff);
  if (ff[len - 1] == DIR_SEPARATOR)
    ff[len - 1] = 0; /* eat the '/' at the end */
  else 
    ff[len] = 0; /* no '/' to eat */
  strcat(ff, BDB_EXT); /* add the extention */
  result->filename = expandFileName(ff); /* expand ~/ if present */
  FREE(ff);
  
  /* Get database directory */
  len = strlen(result->filename);
  while(len >= 0 && (result->filename[len] != DIR_SEPARATOR))
    len--;
  result->home = (char *) MALLOC(len + 1);
  strncpy(result->home, result->filename, len);
  result->home[len] = 0;
  
  if (bdbOpen(result) != 0)
  {
    FREE(result->filename);
    FREE(result->home);
    FREE(result);
    return NULL;
  }

  return result;
}

void * lowInitContentDatabase(char * dir)
{  
  bdbHandle * dbh;
  
  dbh = getDatabase(dir);
  if (dbh == NULL) 
    errexit("FATAL: could not open database!\n");  
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);
  return dbh;
}

/**
 * Normal shutdown of the storage module.
 *
 * @param handle the database
 **/
void lowDoneContentDatabase(void * handle)
{
  bdbHandle * dbh = handle;

#if BDB_DEBUG
 LOG(LOG_DEBUG, 
     "BDB: Shutting down\n");
#endif
  
  bdbClose(dbh);
  
  FREE(dbh->filename);
  FREE(dbh->home);
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  FREE(dbh);
}

/**
 * Delete the BDB database.
 *
 * @param handle the database
 **/
void lowDeleteContentDatabase(void * handle)
{
  bdbHandle * dbh = handle;

#if BDB_DEBUG
 LOG(LOG_DEBUG, 
     "BDB: removing the database\n");
#endif
  
  bdbClose(dbh);

  if (REMOVE(dbh->filename) != 0)
  {
    LOG(LOG_ERROR,
        "ERROR: could not remove %s: %s\n",
        dbh->filename,
        db_strerror(errno));
  }
  FREE(dbh->filename);
  FREE(dbh->home);
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  FREE(dbh);
}

/**
 * Call a method for each entry in the database and
 * call the callback method on it. 
 *
 * @param handle the database
 * @param callback the function to call for each entry
 * @param data extra argument to callback
 * @return the number of items stored in the content database
 **/
int lowForEachEntryInDatabase(void * handle,
			      LowEntryCallback callback,
			      void * data)
{
  bdbHandle *dbh = handle;
  DBT key, dummy;
  HashCode160 doubleHash;
  int count = 0, ret;
  DBC *cursor;

  memset(&key, 0, sizeof(DBT));
  memset(&dummy, 0, sizeof(DBT));

  key.flags = DB_DBT_MALLOC;
  dummy.flags = DB_DBT_MALLOC;

#if BDB_DEBUG
  LOG(LOG_DEBUG,
      "BDB: Iterating through the database\n");
#endif
 
  /* scan database data/content.bdb and add entries to database 
     if not already present */
  ret = dbh->dbf->cursor(dbh->dbf, NULL, &cursor, 0);
  if (ret) {
    LOG(LOG_ERROR,
        "BDB: Can't create cursor: %d (%s)\n", 
        ret,
        db_strerror(ret));
    handleError(ret, dbh);
    return 0;
  }

  while((ret = cursor->c_get(cursor, &key, &dummy, DB_NEXT)) != DB_NOTFOUND)
  {
    if (ret != 0)
    {
      LOG(LOG_ERROR, 
	        "BDB: Unable to get next entry: %s\n",
          db_strerror(ret));
      handleError(ret, dbh);
      break;
    }

#if BDB_DEBUG
    LOG(LOG_DEBUG,
        "BDB: Got next entry\n");
#endif

    if (ret == ENOMEM)
      continue;
    if ((key.size - 1) == sizeof(HashCode160)*2)
    {	
      if (callback != NULL)
      {
        hex2hash((HexName*)key.data,
		             &doubleHash);
        callback(&doubleHash, 
		             data);
      }
      count++; /* one more file */
    }
    if(key.data)
      free(key.data);
    if(dummy.data)
      free(dummy.data);
  }

#if BDB_DEBUG
  LOG(LOG_DEBUG,
      "BDB: Reached end of DB\n");
#endif

  cursor->c_close(cursor);

  return count;
}

#define COUNTENTRY "COUNT"

/**
 * @param dbh the database
 * @param count the number to store
 **/
static void storeCount(bdbHandle * dbh,
		       int count)
{
  DBT key, buffer;
  int ret;

  memset(&key, 0, sizeof(DBT));
  memset(&buffer, 0, sizeof(DBT));
  key.data = COUNTENTRY;
  key.size = strlen(COUNTENTRY)+1;
  buffer.data = (char*)&count;
  buffer.size = sizeof(int);

#if BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Storing count %d\n",
      count);
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->dbf->put(dbh->dbf, NULL, &key, &buffer, 0);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if (ret != 0)
  {
    LOG(LOG_ERROR, 
	      "BDB: Unable to store the row counter: %s\n",
        db_strerror(ret));
    handleError(ret, dbh);
  }
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 **/
int lowCountContentEntries(void * handle)
{
  bdbHandle * dbh = handle;
  DBT key, buffer;
  int count;

  memset(&key, 0, sizeof(DBT));
  memset(&buffer, 0, sizeof(DBT));
  key.data = COUNTENTRY;
  key.size = strlen(COUNTENTRY)+1;
  buffer.flags = DB_DBT_MALLOC;
  buffer.data = 0;

  dbh->dbf->get(dbh->dbf, NULL, &key, &buffer, 0);

  if ( (!buffer.data) || 
       (buffer.size != sizeof(int)) ) {
    count = lowForEachEntryInDatabase(dbh, NULL, NULL);  
    storeCount(dbh, count);
  } else {
    count = *(int*) buffer.data;
  }

  if (buffer.data)
    free(buffer.data);

#if BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Retrieved count of entries: %d\n",
      count);
#endif
  
  return count;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database
 * @param name the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, SYSERR on failure
 **/ 
int lowReadContent(void * handle,
	     	   HashCode160 * name,
		   void ** result)
{
  bdbHandle * dbh = handle;
  HexName fn;
  DBT key, buffer;
  int ret;

  if ((name == NULL) || (result == NULL))
    return SYSERR;
  hash2hex(name, &fn);  
  
  memset(&key, 0, sizeof(DBT));
  memset(&buffer, 0, sizeof(DBT));
  key.data = fn.data;
  key.size = strlen(key.data) + 1;
  buffer.flags = DB_DBT_MALLOC;
  buffer.data = NULL;

#if BDB_DEBUG
 LOG(LOG_DEBUG,
     "BDB: Retrieving data for key %s\n",
     key.data);
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->dbf->get(dbh->dbf, NULL, &key, &buffer, 0);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
  if (ret != 0)
    handleError(ret, dbh);
  
  if (! buffer.data) 
    return SYSERR;
  *result = MALLOC(buffer.size);
  memcpy(*result,
	  buffer.data,
	  buffer.size);
  free(buffer.data);
  return buffer.size;  
}

/**
 * Write content to a file. Check for reduncancy and eventually
 * append.
 *
 * @param handle the database
 * @param name the key for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 **/
int lowWriteContent(void * handle,
		    HashCode160 * name, 
		    int len,
		    void * block)
{
  bdbHandle * dbh = handle;
  HexName fn;
  DBT buffer, key, old;
  int count, ret;

  hash2hex(name, &fn);
  
  memset(&key, 0, sizeof(DBT));
  memset(&buffer, 0, sizeof(DBT));
  key.data = fn.data;
  key.size = strlen(key.data) + 1;
  buffer.data = block;
  buffer.size = len;
  count = lowCountContentEntries(dbh);
#if BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Storing data with the key %s\n", 
      key.data);
#endif
  old.flags = DB_DBT_MALLOC;
  old.data = NULL;  
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->dbf->get(dbh->dbf, NULL, &key, &old, 0);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
  if (! (ret == 0 || ret == DB_NOTFOUND))
  {
    handleError(ret, dbh);
    return SYSERR;
  }
  
  if (old.data != NULL) {
    free(old.data);
    count--; /* substituting data, do not change cnt */
  }
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->dbf->put(dbh->dbf, NULL, &key, &buffer, 0);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

  if (ret != 0)
  {
    handleError(ret, dbh);
    return SYSERR;
  }

  dbh->deleteSize -= len;
  if (dbh->deleteSize < 0)
    dbh->deleteSize = 0;

  storeCount(dbh, count + 1);

  return OK;
}

/**
 * Free space in the database by removing one file
 *
 * @param handle the database
 * @param name hashcode representing the name of the file (without directory)
 * @return SYSERR on error, OK if ok.
 **/
int lowUnlinkFromDB(void * handle,
		    HashCode160 * name)
{
  bdbHandle *dbh = handle;
  DBT key, buffer;
  HexName fn;
  int cnt, ret;

  hash2hex(name, &fn);
  
  memset(&key, 0, sizeof(DBT));
  memset(&buffer, 0, sizeof(DBT));

  key.data = fn.data;
  key.size = strlen(key.data) + 1;

  buffer.flags = DB_DBT_MALLOC;
  buffer.data = 0;

#ifdef BDB_DEBUG
  LOG(LOG_DEBUG, 
      "BDB: Deleting key %s\n", 
      key.data);
#endif

  cnt = lowCountContentEntries(dbh);
  buffer.data = NULL;
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->dbf->get(dbh->dbf, NULL, &key, &buffer, 0);
  
  if (ret != 0)
    handleError(ret, dbh);
  
  if (buffer.data != NULL) {
    free(buffer.data);
    dbh->dbf->del(dbh->dbf, NULL, &key, 0);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    dbh->deleteSize += buffer.size;
    storeCount(dbh, cnt - 1);
  } else {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    LOG(LOG_WARNING,
	    "WARNING: bdb_delete failed for key %s (%s)\n",
	    &fn,
	    db_strerror(ret));
    return SYSERR;
  }

  return OK;
}

/**
 * Estimate the size of the database.
 *
 * @param handle the database
 * @return the number of kb that the DB is assumed to use at the moment.
 **/
int lowEstimateSize(LowDBHandle handle) {
  bdbHandle * dbh = handle;

  return 
    ( (getFileSize(dbh->filename) * 120 / 100) -
      (dbh->deleteSize) +
      (sizeof(HashCode160) * lowCountContentEntries(handle))  
    ) / 1024; /* in kb */
}
 

/* end of low_bdb.c */
