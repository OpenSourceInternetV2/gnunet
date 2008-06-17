/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/low_gdbm.c
 * @brief gdbm based implementation of low database API
 *
 * @author Christian Grothoff
 * @author Uli Luckas
 * @author Igor Wronsky
 **/

#include "low_backend.h"
#include "platform.h"
#include <gdbm.h>

#define GDBM_DEBUG NO

#define GIGA_BYTE (1024 * 1024 * 1024)

/**
 * If a block is about 512 bytes or 1 MB, 1024
 * blocks sounds like a reasonable lower bound.
 **/
#define MIN_BLOCKS_FREE 1024

/**
 * After how-many insert operations test
 * DB size?
 **/
#define TEST_FREQUENCY 1024

/**
 * Extention for the GDBM database.
 **/
#define GDB_EXT ".gdb"

/**
 * @brief gdbm wrapper
 **/
typedef struct {

  /**
   * GDBM handle.
   **/
  GDBM_FILE dbf;

  /**
   * Name of the database file (for size-tests).
   **/
  char * filename;

  /**
   * Number of insert operations since last
   * size-check?
   **/
  int insertCount;

  /**
   * Number of delete operations that were not
   * matched with an insert operation so far?
   **/
  int deleteSize;  

  /**
   * gdbm requires synchronized access.
   **/
  Mutex DATABASE_Lock_;

} gdbmHandle;


/**
 * Open a gdbm database (for content)
 * @param dir the directory where content is configured
 *         to be stored (e.g. data/content). A file 
 *         called ${dir}.gdb is used instead
 **/
static gdbmHandle * getDatabase(char * dir) {
  char * ff;
  gdbmHandle * result;
  int value;

  result = MALLOC(sizeof(gdbmHandle));
#if GDBM_DEBUG
  LOG(LOG_DEBUG, 
      "DEBUG: Database (GDBM): %s\n", 
      dir);
#endif
  ff = MALLOC(strlen(dir)+strlen(GDB_EXT)+1);
  strcpy(ff, dir);
  if (ff[strlen(ff)-1] == DIR_SEPARATOR)
    ff[strlen(ff) - 1] = 0; /* eat the '/' at the end */
  else 
    ff[strlen(ff)] = 0; /* no '/' to eat */
  strcat(ff, GDB_EXT); /* add the extention */
  result->filename = expandFileName(ff); /* expand ~/ if present */
  FREE(ff);
  result->dbf = gdbm_open(result->filename, 
			  0, 
			  GDBM_WRCREAT, 
			  S_IRUSR|S_IWUSR, 
			  0);  
  if (NULL == result->dbf) {
    errexit("FATAL: GDBM getDatabase: failed to open"\
	    " database file %s with error: %s\n",
	    (char*)result->filename,
	    gdbm_strerror(gdbm_errno));
  }
  value = 5;
  if (-1 == gdbm_setopt(result->dbf, 
			GDBM_CACHESIZE,
			&value,
			sizeof(int))) {
    LOG(LOG_WARNING,
	"WARNING: gdbm_setopt failed: %s\n",
	gdbm_strerror(errno));
  }
  if (YES == testConfigurationString("GDBM",
				     "EXPERIMENTAL",
				     "YES")) {
    value = 1;
    if (-1 == gdbm_setopt(result->dbf, 
			  GDBM_CENTFREE,
			  &value,
			  sizeof(int))) {
      LOG(LOG_WARNING,
	  "WARNING: gdbm_setopt failed: %s\n",
	  gdbm_strerror(errno));
    }
    value = 1;
    if (-1 == gdbm_setopt(result->dbf, 
			  GDBM_COALESCEBLKS,
			  &value,
			  sizeof(int))) {
      LOG(LOG_WARNING,
	  "WARNING: gdbm_setopt failed: %s\n",
	  gdbm_strerror(errno));
    }
  }

  if (NO == testConfigurationString("GDBM",
				    "REORGANIZE",
				    "NO")) {
    LOG(LOG_INFO,
	"INFO: reorganizing database %s.  This may take a while.\n",
	dir);
    /* We must call reorganize here since otherwise "deleteSize" is
       going to be wrong and we'd delete blocks needlessly.  Yes, this
       can take a while.  Should teach people not to use gdbm or not to
       restart gnunetd too often, both of which are probably good advice
       anyway. */
    if (0 != gdbm_reorganize(result->dbf))
      LOG(LOG_WARNING,
	  "WARNING: gdbm_reorganize failed: %s\n",
	  gdbm_strerror(gdbm_errno));
    LOG(LOG_INFO,
	"INFO: Done reorganizing database.\n");
  }

  result->insertCount = TEST_FREQUENCY;
  result->deleteSize = 0; 

  return result;
}

void * lowInitContentDatabase(char * dir) {  
  gdbmHandle * dbh;
  
  dbh = getDatabase(dir);
  if (dbh == NULL) 
    errexit("FATAL: could not open database!\n");  
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);
  return dbh;
}

/**
 * Delete the GDBM database.
 *
 * @param handle the database
 **/
void lowDeleteContentDatabase(void * handle) {
  gdbmHandle * dbh = handle;
  
  gdbm_sync(dbh->dbf);
  gdbm_close(dbh->dbf);
  if (0 != REMOVE(dbh->filename))
    LOG(LOG_ERROR,
	"ERROR: gdbm: could not remove %s: %s\n",
	dbh->filename,
	STRERROR(errno));
  FREE(dbh->filename);
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  FREE(dbh);
}

/**
 * Normal shutdown of the storage module.
 * @param handle the database
 **/
void lowDoneContentDatabase(void * handle) {
  gdbmHandle * dbh = handle;
  
  gdbm_sync(dbh->dbf);
  gdbm_close(dbh->dbf);
  FREE(dbh->filename);
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  FREE(dbh);
}

/**
 * Call a method for each entry in the database and
 * call the callback method on it. 
 * This method performs no locking, the caller is
 * responsible for avoiding concurrent modification!
 *
 * @param handle the database
 * @param callback method to call on each entry
 * @param data extra argument to callback
 * @return the number of items stored in the content database
 **/
int lowForEachEntryInDatabase(void * handle,
			      LowEntryCallback callback,
			      void * data) {
  gdbmHandle * dbh = handle;
  datum prevkey, key;
  HashCode160 doubleHash;
  int count;

  count = 0;
  /* scan database data/content.dbf and add entries to database 
     if not already present */
  key = gdbm_firstkey(dbh->dbf);
  while (key.dptr) {
    if (strlen(key.dptr) == sizeof(HashCode160)*2) {	
      if (callback != NULL) {
	hex2hash((HexName*)key.dptr,
		 &doubleHash);
	callback(&doubleHash, 
		 data);
      }
      count++; /* one more file */
    }
    prevkey = key;
    key = gdbm_nextkey(dbh->dbf, prevkey);
    free(prevkey.dptr); /* allocated by gdbm! */
  }
  return count;
}

#define COUNTENTRY "COUNT"

static void storeCount(gdbmHandle * dbh,
		       int count) {
  datum key;
  datum buffer;

  key.dptr = COUNTENTRY;
  key.dsize = strlen(COUNTENTRY)+1;
  buffer.dptr = (char*)&count;
  buffer.dsize = sizeof(int);
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  if (0 != gdbm_store(dbh->dbf, key, buffer, GDBM_REPLACE)) {
    LOG(LOG_WARNING,
	"WARNING: gdbm store of count failed: %s\n",
	gdbm_strerror(gdbm_errno));
  }
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 * @return the number of entries
 **/
int lowCountContentEntries(void * handle) {
  gdbmHandle * dbh = handle;
  datum key;
  datum buffer;
  int count;

  key.dptr = COUNTENTRY;
  key.dsize = strlen(COUNTENTRY)+1;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  buffer = gdbm_fetch(dbh->dbf, key);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if ( (!buffer.dptr) || 
       (buffer.dsize != sizeof(int)) ) {
    count = lowForEachEntryInDatabase(dbh, NULL, NULL);  
    storeCount(dbh, count);
  } else {
    count = *(int*) buffer.dptr;
    free(buffer.dptr); /* allocated by gdbm */
  }
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
		   void ** result) {
  gdbmHandle * dbh = handle;
  HexName fn;
  datum key, buffer;

  if ((name == NULL) || (result == NULL))
    return SYSERR;
  hash2hex(name, &fn);  
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  buffer = gdbm_fetch(dbh->dbf, key);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if (NULL == buffer.dptr) 
    return SYSERR;
  *result = MALLOC(buffer.dsize);
  memcpy(*result,
	 buffer.dptr,
	 buffer.dsize);
  free(buffer.dptr);
  return buffer.dsize;  
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
		    void * block) {
  gdbmHandle * dbh = handle;
  HexName fn;
  datum buffer, key, old;
  int ok;
  int cnt;

  if (getBlocksLeftOnDrive(dbh->filename) < MIN_BLOCKS_FREE) {
    LOG(LOG_WARNING,
	"WARNING: less than %d blocks free on drive, will not write to GDBM database.\n",
	MIN_BLOCKS_FREE);
    return SYSERR;
  }
  if (dbh->insertCount > 1024) {
    if (getFileSize(dbh->filename) > 
	(unsigned long long) 2 * GIGA_BYTE - 3 * TEST_FREQUENCY * len) {
      LOG(LOG_WARNING,
	  "WARNING: single gdbm database is limited to 2 GB, can not store more data.\n");
      return SYSERR; /* enforce GDBM size limit of 2 GB minus 3*TF_len slack */
    }
    dbh->insertCount = 0;
  } else {
    dbh->insertCount++;
  }

  hash2hex(name, &fn);
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;
  buffer.dptr = block;
  buffer.dsize = len;
  cnt = lowCountContentEntries(dbh);
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  old = gdbm_fetch(dbh->dbf,
		   key);
  if ( (old.dsize > 0) ||
       (old.dptr != NULL) ) {
    /* replace! */
    cnt--;
    free(old.dptr);
  }
  ok = gdbm_store(dbh->dbf,
		  key, 
		  buffer,
		  GDBM_REPLACE);
  if ( (ok == 0) && 
       (dbh->deleteSize > 0) ) {
    dbh->deleteSize -= len;
    if (dbh->deleteSize < 0)
      dbh->deleteSize = 0;
  }
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if (ok == 0) {
    storeCount(dbh, 
	       cnt + 1);
    return OK;
  } else {
    LOG(LOG_WARNING,
	"WARNING: gdbm store failed: %s\n",
	gdbm_strerror(gdbm_errno));
    return SYSERR;
  }
}

/**
 * Free space in the database by removing one file
 *
 * @param handle the database
 * @param name hashcode representing the name of the file (without directory)
 * @return SYSERR on error, OK if ok.
 **/
int lowUnlinkFromDB(void * handle,
		    HashCode160 * name) {
  gdbmHandle * dbh = handle;
  datum buffer;
  datum key;
  HexName fn;
  int ok;
  int cnt;

  if (getBlocksLeftOnDrive(dbh->filename) < MIN_BLOCKS_FREE/2) {
    LOG(LOG_WARNING,
	"WARNING: less tha %d blocks free on drive, will not even DELETE from GDBM database (may grow in size!)\n",
	MIN_BLOCKS_FREE/2);
    return SYSERR; /* for free, we set the limit a bit lower */
  }
  hash2hex(name, &fn);
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  buffer = gdbm_fetch(dbh->dbf, key);
  if (NULL == buffer.dptr) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    LOG(LOG_WARNING,
	"WARNING: gdbm_delete failed for key %s (%s)\n",
	&fn,
	gdbm_strerror(gdbm_errno));
    return SYSERR;
  }
  free(buffer.dptr);
  cnt = lowCountContentEntries(dbh);
  ok = gdbm_delete(dbh->dbf, key);  

  if (ok == 0) {
    dbh->deleteSize += buffer.dsize;
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    storeCount(dbh, 
	       cnt - 1);
    
    return OK;
  } else {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    LOG(LOG_WARNING,
	"WARNING: gdbm_delete failed for key %s (%s)\n",
	&fn,
	gdbm_strerror(gdbm_errno));
    return SYSERR;
  }
}

/**
 * Estimate the size of the database.  This implementation
 * takes into account that gdbm databases never shrink 
 * (since we can't call reorganize in practice).  Thus
 * the actual size of used space will be smaller than the
 * file size if some blocks have been deleted
 * recently.  lowEstimateSize subtracts the size of the deleted
 * blocks from the filesize, thus even after the database
 * hits the quota, a delete operation will cause lowEstimateSize
 * to again signal free space.  Of course, this assumes that
 * gdbm will actually be able to reclaim the holes from the
 * delete operation, which it may not always be able to do.
 * Thus an &quot;arbitrary&quot; factor of 20% is added to the
 * filesize to take gdbm fragmentation a bit into account.<p>
 *
 * Furthermore, in addition to the gdbm database we have
 * the pidx database.  We take that DB into account by
 * adding 20 bytes (sizeof(HashCode)) per entry in this
 * database to the total size used.
 *
 * @param handle the database
 * @return the number of kb that the DB is
 *  assumed to use at the moment.
 **/
int lowEstimateSize(LowDBHandle handle) {
  gdbmHandle * dbh = handle;

  return 
    ( (getFileSize(dbh->filename) * 120 / 100) -
      (dbh->deleteSize) +
      (sizeof(HashCode160) * lowCountContentEntries(handle))  
    ) / 1024; /* in kb */
}
/* end of low_gdbm.c */
