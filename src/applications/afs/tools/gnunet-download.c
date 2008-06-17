/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/tools/gnunet-download.c 
 * @brief Main function to download files from GNUnet.
 * @author Christian Grothoff
 **/

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 **/
static void printhelp() {
  static Help help[] = {
    { 'a', "anonymity", "LEVEL",
      "set the desired LEVEL of receiver-anonymity" },
    HELP_CONFIG,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    { 'o', "output", "FILENAME",
      "write the file to FILENAME (required)" },
    { 'R', "recursive", NULL,
      "download a GNUnet directory recursively" },
    { 't', "threads", "NUMBER",
      "specifies the NUMBER of files that maybe downloaded in parallel for a recursive download"},
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-download [OPTIONS] GNUNET-URI",
	     "Download file from GNUnet.",
	     help);
}

/**
 * ParseOptions for gnunet-download.
 * @return SYSERR to abort afterwards, OK to continue
 **/
static int parseOptions(int argc,
			char ** argv) {
  int c;  

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity", 1, 0, 'a' }, 
      { "output",    1, 0, 'o' },
      { "recursive", 0, 0, 'R' },
      { "threads",   1, 0, 't' },
      { "verbose",   0, 0, 'V' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "a:vhdc:L:H:Vo:Rt:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a': {
      unsigned int receivePolicy;
      
      if (1 != sscanf(GNoptarg, "%ud", &receivePolicy)) {
        LOG(LOG_FAILURE,
	    "FAILURE: You must pass a number to the -a option.\n");
	return -1;
      }
      setConfigurationInt("AFS",
      			  "ANONYMITY-RECEIVE",
			  receivePolicy);
      break;
    }
    case 't': {
      unsigned int threads;
      
      if (1 != sscanf(GNoptarg, "%ud", &threads)) {
        LOG(LOG_FAILURE,
	    "FAILURE: You must pass a number to the -t option.\n");
	return -1;
      }
      if (threads == 0) {
	threads = 1; /* actual minimum value */
      }
      setConfigurationInt("GNUNET-DOWNLOAD",
      			  "PARALLELIZATION",
			  threads);
      break;
    }
    case 'R': 
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "RECURSIVE",
					 "YES"));
      break;
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "FILENAME",
					 GNoptarg));
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-download v%s\n",
	     VERSION,
	     AFS_VERSION);
      return SYSERR;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "VERBOSE",
					 "YES"));
      break;
    case 'h': 
      printhelp(); 
      return SYSERR;
    default: 
      LOG(LOG_FAILURE,
	  "Unknown option %c. Aborting.\n"\
	  "Use --help to get a list of options.\n",
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind != 1) {
    LOG(LOG_WARNING, 
	"Not enough arguments. "\
	"You must specify atleast a GNUnet AFS URI\n");
    printhelp();
    return SYSERR;
  }
  FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
				     "URI",
				     argv[GNoptind++]));
  return OK;
}

typedef struct {
  Semaphore * sem;
  char * filename;
  FileIdentifier * fid;
  cron_t startTime;
  size_t lastProgress;
  int result;
  PTHREAD_T thread;
} DownloadInfo;

/**
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 **/
static void progressModel(ProgressStats * stats,
			  DownloadInfo * data) {
  if (YES == testConfigurationString("GNUNET-DOWNLOAD",
				     "VERBOSE",
				     "YES")) {
    if (stats->progress != data->lastProgress)
      printf("Download at %8u out of %8u bytes (%8.3f kbps)\r",
  	     (unsigned int) stats->progress, 
	     (unsigned int) stats->filesize,
	     (stats->progress/1024.0) / 
	     (((double)(cronTime(NULL)-(data->startTime-1))) / (double)cronSECONDS) );
  }
  data->lastProgress = stats->progress;
  if (stats->progress == stats->filesize)
    SEMAPHORE_UP(data->sem);
}

static void scheduleDownload(FileIdentifier * fid,
			     char * filename);

static int downloadFileHelper(DownloadInfo * di) {
  RequestManager * rm;
  int ok;

  if (di->sem != NULL)
    errexit("FATAL: assertion failed!\n");
  cronTime(&di->startTime);
  di->lastProgress = 0;
  di->sem = SEMAPHORE_NEW(0);
  rm = downloadFile(di->fid,
		    di->filename, 
		    (ProgressModel) &progressModel,
		    di);
  if (rm == NULL) {
    printf("Download %s failed (error messages should have been provided).\n",
	   di->filename);
    return SYSERR;
  }
  SEMAPHORE_DOWN(di->sem);
  SEMAPHORE_FREE(di->sem);
  di->sem = NULL;
  destroyRequestManager(rm);
  printf("\nDownload %s %s.  Speed was %8.3f kilobyte per second.\n",
	 di->filename,
	 (ntohl(di->fid->file_length) == di->lastProgress) ?
	 "complete" : "incomplete",
	 (di->lastProgress/1024.0) / 
	 (((double)(cronTime(NULL)-di->startTime)) / (double)cronSECONDS) );
  if (ntohl(di->fid->file_length) == di->lastProgress)
    ok = OK;
  else
    ok = SYSERR;
  if ( (ok == OK) && 
       testConfigurationString("GNUNET-DOWNLOAD",
			       "RECURSIVE",
			       "YES")) {
    /* download files in directory! */
    char * exp;
    GNUnetDirectory * dir;
    unsigned int i;

    exp = expandFileName(di->filename);
    dir = readGNUnetDirectory(exp);
    FREE(exp);
    if (dir == NULL) 
      return ok; /* not a directory */    
    for (i=0;i<ntohl(dir->number_of_files);i++) {
      RootNode * rn;
      char * fn;
      char * rfn;

      rn = &((GNUnetDirectory_GENERIC*)dir)->contents[i];
      rfn = getFilenameFromNode(rn);
      fn = MALLOC(strlen(di->filename) + 
		  strlen(rfn) +
		  128);
      strcpy(fn, di->filename);
      /* remove '.gnd' or add ".dir" */
      if ( (strlen(fn) > 1+strlen(GNUNET_DIRECTORY_EXT)) &&
	   (0 == strcmp(GNUNET_DIRECTORY_EXT, 
			&fn[strlen(fn)-4])) ) {
	fn[strlen(fn)-4] = '\0';
      } else {
	strcat(fn, ".dir");
      }
      mkdirp(fn); /* create directory */
      strcat(fn, "/");
      strcat(fn, rfn);
      FREE(rfn);
      scheduleDownload(&rn->header.fileIdentifier,
		       fn);
      FREE(fn);
    }    
    FREE(dir);
  }
  return ok;
}			 

static DownloadInfo ** pending = NULL;
static unsigned int pendingCount = 0;
static Mutex lock;
/* just not SYSERR/OK */
#define PENDING 42
#define RUNNING 43
#define JOINED 44

static void scheduleDownload(FileIdentifier * fid,
			     char * filename) {
  MUTEX_LOCK(&lock);
  GROW(pending,
       pendingCount,
       pendingCount+1);
  pending[pendingCount-1] = MALLOC(sizeof(DownloadInfo));
  pending[pendingCount-1]->fid = MALLOC(sizeof(FileIdentifier));
  memcpy(pending[pendingCount-1]->fid,
	 fid,
	 sizeof(FileIdentifier));
  pending[pendingCount-1]->filename = STRDUP(filename);  
  pending[pendingCount-1]->result = PENDING;
  pending[pendingCount-1]->sem = NULL;
  MUTEX_UNLOCK(&lock);
}

static Semaphore * semSignal;

static void * process(DownloadInfo * di) {
  di->result = downloadFileHelper(di);
  SEMAPHORE_UP(semSignal);
  return NULL;
}

static int run(int threadLimit) {
  unsigned int i;
  unsigned int left;
  unsigned int running;
  int ret;    
  void * unused;

  if (threadLimit == 0) /* should never happen */
    threadLimit = 1; /* need at least 1! */

  ret = OK;
  semSignal = SEMAPHORE_NEW(threadLimit);
  left = pendingCount;
  running = 0;
  while ( (left > 0) || (running > 0) ) {
    if (left > 0) {
      SEMAPHORE_DOWN(semSignal);
      for (i=0;i<pendingCount;i++) {
	if (pending[i]->result == PENDING) {
	  pending[i]->result = RUNNING;
	  if (0 != PTHREAD_CREATE(&pending[i]->thread,
				  (PThreadMain) &process,
				  pending[i],
				  16*1024))
	    errexit("FATAL: could not create download thread: %s\n",
		    strerror(errno));
	  break;
	}
      }
    }
    left = 0;
    running = 0;
    for (i=0;i<pendingCount;i++) {
      if (pending[i]->result == PENDING) {
	left++;
	continue;
      }
      if (pending[i]->result == RUNNING) {
	running++;
	continue;
      }
      if (pending[i]->result == JOINED)
	continue;
      if (pending[i]->result == SYSERR)
	ret = SYSERR;
      PTHREAD_JOIN(&pending[i]->thread,
		   &unused);
      pending[i]->result = JOINED;
      FREE(pending[i]->fid);
      FREE(pending[i]->filename);
    }
    /* wait a bit */
    if ( (left == 0) && (running > 0) ) 
      gnunet_util_sleep(150 * cronMILLIS);        
  }  
  /* wait for all threads to terminate */
  for (i=0;i<threadLimit;i++)
    SEMAPHORE_DOWN(semSignal); 
  /* join on all */
  for (i=0;i<pendingCount;i++) {
    if (pending[i]->result == PENDING)		
      errexit("FATAL: assertion failed at %s:%d\n",
	      __FILE__, __LINE__);
    if (pending[i]->result == JOINED)
      continue;
    if (pending[i]->result == SYSERR)
      ret = SYSERR;    
    FREE(pending[i]->fid);
    FREE(pending[i]->filename);
    PTHREAD_JOIN(&pending[i]->thread,
		 &unused);
    pending[i]->result = JOINED;
  }
  for (i=0;i<pendingCount;i++) 
    FREE(pending[i]);  
  GROW(pending,
       pendingCount,
       0);
  SEMAPHORE_FREE(semSignal);
  return ret;
}

/**
 * Main function to download files from GNUnet.
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from download file: 0: ok, -1, 1: error
 **/   
int main(int argc, 
	 char ** argv) {
  char * fstring;
  FileIdentifier * fid;
  char * filename;
  int ok;
  int threadLimit;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  threadLimit = getConfigurationInt("GNUNET-DOWNLOAD",
				    "PARALLELIZATION");
  if (threadLimit == 0)
    threadLimit = 30; /* default */
  filename = getConfigurationString("GNUNET-DOWNLOAD",
				    "FILENAME");
  if (filename == NULL) {
    LOG(LOG_ERROR,
	"ERROR: You must specify a filename (option -o).\n");
    printhelp();
    return -1;
  }
  fstring = getConfigurationString("GNUNET-DOWNLOAD",
  				   "URI");
  fid = stringToFileIdentifier(fstring);
  FREE(fstring);
  if (fid == NULL) {
    LOG(LOG_ERROR,
        "ERROR: Can't proceed without valid URI.\n");
    FREE(filename);
    return -1;
  }

  MUTEX_CREATE_RECURSIVE(&lock);
  startAFSPriorityTracker();
  startCron();
  initAnonymityPolicy(NULL);
  scheduleDownload(fid,
		   filename);
  FREE(fid);
  FREE(filename);
  ok = run(threadLimit);
  doneAnonymityPolicy();
  MUTEX_DESTROY(&lock);
  stopCron();
  stopAFSPriorityTracker();
  doneUtil();
  
  if (ok == OK)
    return 0;
  else
    return 1;
}

/* end of gnunet-download.c */
