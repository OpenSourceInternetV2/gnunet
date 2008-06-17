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
 * @file util/state.c
 * @brief tiny, stateful database too keep track of internal state
 *
 * Directory based implementation of a tiny, stateful database
 * to keep track of GNUnet _internal_ configuration parameters
 * that users are not supposed to see (e.g. *previous* quota,
 * previous database type for AFS, etc.)
 *
 *
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"

#include <sys/stat.h>


#define STATE_DEBUG NO

#define DIR_EXT "state.sdb"

static char * handle = NULL;

/**
 * Initialize the Directory module, expand filename
 * @param dir the directory where content is configured to be stored (e.g. ~/.gnunet/data/content).
 **/
static char * getDirectory(char * dir) {
  char * result;
  char * tmp;

#if STATE_DEBUG
  LOG(LOG_INFO, 
      "Database (state): %s\n", 
      dir);
#endif
  tmp = MALLOC(strlen(dir) + strlen(DIR_EXT) + 5);
  sprintf(tmp, "%s/%s/", dir, DIR_EXT);
  result = expandFileName(tmp);
  FREE(tmp);
  return result;
}

void initState() {
  char * dbh;
  char * dir;
  char * base;

  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES"))
    base = "GNUNETD_HOME";
  else
    base = "GNUNET_HOME";
  dir = getFileName("",
		    base,
		    "Configuration file must specify a directory"
		    " for GNUnet to store per-peer data under %s%s\n");
  dbh = getDirectory(dir);  
  FREE(dir);
  if (dbh == NULL) 
    errexit("FATAL: could not open directory %s!\n",
	    (char*) dbh);
  mkdirp(dbh);
  handle = dbh;
}

/**
 * Clean shutdown of the storage module (not used at the moment)
 **/
void doneState() {
  FREE(handle);
  handle = NULL;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param name the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 **/ 
int stateReadContent(char * name,
		     void ** result) {
  /* open file, must exist, open read only */
  char * dbh = handle;
  int fd;
  int size;
  char * fil;
  size_t fsize;

  if (result == NULL)
    return -1;
  fil = MALLOC(strlen(dbh) + strlen(name) + 2);
  sprintf(fil, 
	  "%s/%s", 
	  dbh, 
	  name);
  fd = OPEN(fil, 
	    O_RDONLY,
	    S_IRUSR);
  if (fd == -1) {
    FREE(fil);
    return -1;
  }
  fsize = getFileSize(fil);
  FREE(fil);
  if (fsize == 0) { /* also invalid! */
    CLOSE(fd);
    return -1;
  }
    
  *result = MALLOC(fsize);
  size = READ(fd, 
	      *result, 
	      fsize);
  CLOSE(fd);
  if (size == -1) {
    FREE(*result);
    *result = NULL;
  }
  return size;
}


/**
 * Append content to file.
 *
 * @param name the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 **/
int stateAppendContent(char * name,
		       int len,
		       void * block) {
  char * dbh = handle;
  char * fil;
  int fd;

  fil = MALLOC(strlen(dbh) + strlen(name) + 2);
  sprintf(fil,
	  "%s/%s", 
	  dbh, 
	  name);
  fd = OPEN(fil,
	    O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR);
  if (fd == -1) {
    LOG(LOG_WARNING,
	"WARNING: Failed to open file %s\n", 
	fil);
    FREE(fil);
    return SYSERR; /* failed! */
  }
  FREE(fil);
  lseek(fd, 
	0, 
	SEEK_END);
  WRITE(fd, 
	block, 
	len);
  CLOSE(fd);
  return OK;
}

/**
 * Write content to a file. 
 *
 * @param name the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 **/
int stateWriteContent(char * name,
		      int len,
		      void * block) {
  char * dbh = handle;
  char * fil;
  int fd;

  fil = MALLOC(strlen(dbh) + strlen(name) + 2);
  sprintf(fil,
	  "%s/%s", 
	  dbh, 
	  name);
  fd = OPEN(fil,
	    O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR);
  if (fd == -1) {
    LOG(LOG_WARNING,
	"WARNING: Failed to open file %s: %s\n", 
	fil,
	STRERROR(errno));
    FREE(fil);
    return SYSERR; /* failed! */
  }
  WRITE(fd, 
	block, 
	len);
  if (0 != ftruncate(fd, len))
    LOG(LOG_WARNING,
	"WARNING: truncate of %s failed: %s\n",
	fil,
	STRERROR(errno));
  CLOSE(fd);
  FREE(fil);
  return OK;
}

/**
 * Free space in the database by removing one file
 * @param name the hashcode representing the name of the file 
 *        (without directory)
 **/
int stateUnlinkFromDB(char * name) {
  char * dbh = handle;
  char * fil;

  fil = MALLOC(strlen(dbh) + strlen(name) + 2);
  sprintf(fil, 
	  "%s/%s",
	  dbh, 
	  name);
  UNLINK(fil);
  FREE(fil);
  return OK;
}

/* end of state.c */
