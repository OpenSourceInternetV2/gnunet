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
 * @file applications/afs/tools/gnunet-search.c 
 * @brief Main function to search for files on GNUnet.
 * @author Christian Grothoff
 *
 * Todo: namespace search should be more like the normal
 * search (add cron for repeated queries, allow multiple results).
 * But this requires some changes in esed2-lib first!
 *
 * OTOH, it would also probably be good if we had a convenience
 * method for printing RBlocks in esed2-lib like what we have
 * for SBlocks.
 **/

#include "gnunet_afs_esed2.h"
#include "platform.h"

typedef struct {
  unsigned int resultCount;
  unsigned int max;
} SearchClosure;

/**
 * Handle the search result.
 **/
static void handleNormalResult(RootNode * rootNode,
			       SearchClosure * sc) {
  char * fstring;
  char * fname;
  char * prefix;  

  /* write rblock to file? */
  prefix = getConfigurationString("GNUNET-SEARCH",
  				  "OUTPUT_PREFIX");
  if (prefix != NULL) {
    char * outfile;

    outfile = MALLOC(strlen(prefix)+16);
    sprintf(outfile, 
	    "%s.%03d", 
	    prefix, 
	    sc->resultCount++);
    writeFile(outfile,
    	      rootNode,
	      sizeof(RootNode),
	      "600");
    FREE(outfile);
    FREE(prefix);
  }

  sc->max--;  
  fstring = fileIdentifierToString(&rootNode->header.fileIdentifier);
 
  rootNode->header.description[MAX_DESC_LEN-1] = 0;
  rootNode->header.filename[MAX_FILENAME_LEN-1] = 0;
  rootNode->header.mimetype[MAX_MIMETYPE_LEN-1] = 0;
  
  if (0 == strcmp(rootNode->header.mimetype,
		  GNUNET_DIRECTORY_MIME)) {
    fname = expandDirectoryName(rootNode->header.filename);
  } else 
    fname = STRDUP(rootNode->header.filename);
  
  printf("gnunet-download -o \"%s\" %s\n",
	 fname,
	 fstring); 
  printf("=> %s <= (mimetype: %s)\n",
	 rootNode->header.description,
	 rootNode->header.mimetype);
  FREE(fstring);
  FREE(fname);
  if (0 == sc->max)
    run_shutdown(0);
}

typedef struct {
  HashCode160 * results;
  unsigned int resultCount;
  unsigned int max;
} NSSearchClosure;

/**
 * Handle namespace result.
 */   
static void handleNamespaceResult(SBlock * sb,
				  NSSearchClosure * sqc) {
  HashCode160 curK;
  int i;
  char * prefix;

  hash(sb, sizeof(SBlock), &curK);
  for (i=0;i<sqc->resultCount;i++)
    if (equalsHashCode160(&curK,
        &sqc->results[i])) {
      LOG(LOG_DEBUG, 
	  "DEBUG: SBlock already seen\n");
      return; /* displayed already */
    }
  GROW(sqc->results,
       sqc->resultCount,
       sqc->resultCount+1);
  memcpy(&sqc->results[sqc->resultCount-1],
         &curK,
         sizeof(HashCode160));
  printSBlock(stdout,
	      sb);
  sqc->max--;  
  /* write sblock to file */
  prefix = getConfigurationString("GNUNET-SEARCH",
  				  "OUTPUT_PREFIX");
  if (prefix != NULL) {
    char * outfile;

    outfile = MALLOC(strlen(prefix)+16);
    sprintf(outfile, 
	    "%s.%03d", 
	    prefix, 
	    sqc->resultCount-1);
    writeFile(outfile,
    	      sb,
	      sizeof(SBlock),
	      "600");
    FREE(outfile);
    FREE(prefix);
  }
  if (0 == sqc->max)
    run_shutdown(0);
}

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
    { 'm', "max", "LIMIT",
      "exit after receiving LIMIT results" },
    { 'n', "namespace", "HEX",
      "only search the namespace identified by HEX" },
    { 'o', "output", "PREFIX",
      "write encountered (decrypted) search results to the file PREFIX" },
    { 't', "timeout", "TIMEOUT",
      "wait TIMEOUT seconds for search results before aborting" },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-search [OPTIONS] KEYWORD [AND KEYWORD]",
	     "Search GNUnet for files.",
	     help);
}

/**
 * Parse the options, set the timeout.
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should exit, OK otherwise
 **/
static int parseOptions(int argc,
			char ** argv) {
  int c;  

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "output",    1, 0, 'o' },
      { "anonymity", 1, 0, 'a' }, 
      { "timeout",   1, 0, 't' },
      { "max",       1, 0, 'm' },
      { "namespace", 1, 0, 'n' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "a:vhdc:L:H:t:o:n:m:", 
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
    case 'v': 
      printf("GNUnet v%s, gnunet-search v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 's':
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
      					 "NAMESPACE",
					 GNoptarg));
      break;
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
      					 "OUTPUT_PREFIX",
					 GNoptarg));
      break;
    case 't': {
      unsigned int timeout;
      if (1 != sscanf(GNoptarg, "%ud", &timeout)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -t option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("AFS",
			    "SEARCHTIMEOUT",
			    timeout);
      }
      break;
    }
    case 'm': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -m option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("AFS",
			    "MAXRESULTS",
			    max);
	if (max == 0) 
	  return SYSERR; /* exit... */	
      }
      break;
    }
    default: 
      LOG(LOG_FAILURE,
	  "Unknown option %c. Aborting.\n"
	  "Use --help to get a list of options.\n",
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind <= 0) {
    LOG(LOG_FAILURE, 
	"FAILURE: Not enough arguments. "
	"You must specify a keyword or identifier.\n");
    printhelp();
    return SYSERR;
  }
  setConfigurationStringList(&argv[GNoptind],
			     argc-GNoptind);
  return OK;
}

/**
 * Perform a normal (non-namespace) search.
 */
static void * normalSearchMain(GNUNET_TCP_SOCKET * sock) {
  SearchClosure max;
  int i;
  int keywordCount;
  char ** keyStrings;

  max.max = getConfigurationInt("AFS",
				"MAXRESULTS");
  max.resultCount = 0;
  if (max.max == 0)
    max.max = (unsigned int)-1; /* infty */
  keywordCount = getConfigurationStringList(&keyStrings);
  searchRBlock(sock,
	       keyStrings,
	       keywordCount,
	       (SearchResultCallback)&handleNormalResult,
	       &max,
	       &testShutdown,
	       NULL);
  for (i=0;i<keywordCount;i++) 
    FREE(keyStrings[i]);  
  FREE(keyStrings);
  return NULL;
}

/**
 * Perform a namespace search.
 */
static int namespaceSearchMain(GNUNET_TCP_SOCKET * sock) {
  int ret;
  NSSearchClosure sqc;
  HashCode160 namespace;
  HashCode160 identifier;
  char * nsstring;
  char * idstring;
  char ** keyStrings;
  int kc;
  int i;
	  
  nsstring = getConfigurationString("GNUNET-SEARCH", 
				    "NAMESPACE"); 
  sqc.max = getConfigurationInt("AFS",
				"MAXRESULTS");
  if (sqc.max == 0)
    sqc.max = (unsigned int)-1; /* infty */
  hex2hash((HexName*)nsstring,
	   &namespace);
  FREE(nsstring);
  
  kc = getConfigurationStringList(&keyStrings);
  ret = 1; /* '\0' terminator */
  for (i=0;i<kc;i++)
    ret += strlen(keyStrings[i]);
  ret += kc; /* spaces! */
  idstring = MALLOC(ret);
  idstring[0] = '\0';
  for (i=0;i<kc;i++) {
    strcat(idstring, keyStrings[i]);
    FREE(keyStrings[i]);
  } 
  FREE(keyStrings);
  
  if (SYSERR == tryhex2hash(idstring,
  			    &identifier)) {
     LOG(LOG_DEBUG,
         "DEBUG: namespace ID entered is not in HEX format, using hash of ASCII text (%s).\n",
	 idstring);
     hash(idstring,
	  strlen(idstring), 
	  &identifier);
  }
  FREE(idstring);

  sqc.results = NULL;
  sqc.resultCount = 0;
  ret = searchSBlock(sock,
		     &namespace,
		     &identifier,
		     &testShutdown, 
		     NULL,
		     (NSSearchResultCallback)&handleNamespaceResult,
		     &sqc);
  if (ret == SYSERR) 
    printf("Sorry, nothing found.\n");
 
  FREENONNULL(sqc.results);
  return ret;
}

/**
 * The main function to search for files on GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunetsearch: 0: ok, -1: error
 **/   
int main(int argc,
	 char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T searchThread;
  void * unused;
  PThreadMain type;
  char * ns;
 
  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;
  sock = getClientSocket();
  if (sock == NULL)
    errexit("FATAL: could not connect to gnunetd.\n");
  initAnonymityPolicy(NULL);
  initializeShutdownHandlers();

  /* order of cron-jobs is important, thus '- cronMILLIS' */
  addCronJob((CronJob)&run_shutdown,
	     cronSECONDS * getConfigurationInt("AFS",
					       "SEARCHTIMEOUT") - cronMILLIS,
	     0, /* no need to repeat */
	     NULL);
  startAFSPriorityTracker();
  startCron();
  
  ns = getConfigurationString("GNUNET-SEARCH", 
			      "NAMESPACE");
  if (ns != NULL) {
    FREE(ns);
    type = (PThreadMain) &namespaceSearchMain;
  } else {
    type = (PThreadMain) &normalSearchMain;
  }

  if (0 != PTHREAD_CREATE(&searchThread, 
			  type,
			  sock,
			  8 * 1024)) 
    errexit("FATAL: failed to create search thread (%s).\n",
	    strerror(errno));
  wait_for_shutdown();
  closeSocketTemporarily(sock);
  stopCron();
  stopAFSPriorityTracker();
  delCronJob((CronJob)&run_shutdown,
	     0,
	     NULL);
  PTHREAD_JOIN(&searchThread, &unused);
  doneAnonymityPolicy();
  releaseClientSocket(sock);
  doneShutdownHandlers();
  doneUtil();
  return 0;
}

/* end of gnunet-search.c */
