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
 * @file dht-join.c
 * @brief join table and provide client store
 * @author Christian Grothoff
 *
 * Todo:
 * - test
 * - add options (verbose reporting of DHT operations, leave-timeout)
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht_datastore_memory.h"

static int verbose;

static void printHelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'm', "memory", "SIZE",
      gettext_noop("allow SIZE bytes of memory for the local table") },
    { 't', "table", "NAME",
      gettext_noop("join table called NAME") },
    { 'T', "timeout", "VALUE",
      gettext_noop("when leaving table, use VALUEs to migrate data") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("dht-join [OPTIONS]",
	     "Join a DHT table.",
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;  

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "memory", 1, 0, 'm' },
      { "table", 1, 0, 't' },      
      { "verbose", 0, 0, 'V' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "vhH:c:L:dt:m:T:V",
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'h': 
      printHelp(); 
      return SYSERR;
    case 'm': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE, 
	    _("You must pass a number to the '%s' option.\n"),
	    "-m");
	return SYSERR;
      } else {	
	setConfigurationInt("DHT-JOIN",
			    "MEMORY",
			    max);
      }
      break;
    }
    case 't':
      FREENONNULL(setConfigurationString("DHT-JOIN",
					 "TABLE",
					 GNoptarg));
      break;
    case 'T': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE, 
	    _("You must pass a number to the '%s' option.\n"),
	    "-T");
	return SYSERR;
      } else {	
	setConfigurationInt("DHT-JOIN",
			    "TIMEOUT",
			    max);
      }
      break;
    }
    case 'v': 
      printf("dht-join v0.0.0\n");
      return SYSERR;
    case 'V':
      verbose++;
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Unknown option %c. Aborting. "
	    "Use --help to get a list of options.\n"),
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind != 0) 
    LOG(LOG_WARNING, 
	_("Superflous arguments (ignored).\n"));
  return OK;
}

static void dump(const char * fmt,
		    ...) {
  va_list ap;
  if (verbose > 0) {
    va_start(ap, fmt);
    vfprintf(stdout,
	     fmt,
	     ap);
    va_end(ap);
  }
}

#define LOGRET(ret) dump(_("Call to '%s' returns %d.\n"), __FUNCTION__, ret)
#define LOGKEY(key) do { EncName kn; hash2enc(key, &kn); dump(_("Call to '%s' with key '%s'.\n"), __FUNCTION__, &kn); } while (0)
#define LOGVAL(val) dump(_("Call to '%s' with value '%*s' (%d bytes).\n"), __FUNCTION__, (val == NULL) ? 0 : val->dataLength, (val == NULL) ? NULL : val->data, (val == NULL) ? 0 : val->dataLength)

static int lookup(void * closure,
		 const HashCode160 * key,
		 unsigned int maxResults,
		 DHT_DataContainer * results,
		 int flags) {
  int ret;
  DHT_Datastore * cls = (DHT_Datastore*) closure;  
  LOGKEY(key);
  ret = cls->lookup(closure,
		    key,
		    maxResults,
		    results,
		    flags);
  LOGRET(ret);
  return ret;
}
  
static int store(void * closure,
		 const HashCode160 * key,
		 const DHT_DataContainer * value,
		 int flags) {
  int ret;
  DHT_Datastore * cls = (DHT_Datastore*) closure;
  LOGKEY(key);
  LOGVAL(value);
  ret = cls->store(closure,
		   key,
		   value,
		   flags);
  LOGRET(ret);
  return ret;
}

static int removeDS(void * closure,
		    const HashCode160 * key,
		    const DHT_DataContainer * value,
		    int flags) {
  int ret;
  DHT_Datastore * cls = (DHT_Datastore*) closure;
  LOGKEY(key);
  LOGVAL(value);
  ret = cls->remove(closure,
		    key,
		    value,
		    flags);
  LOGRET(ret);
  return ret;
}

static int iterate(void * closure,		 
		   int flags,
		   DHT_DataProcessor processor,
		   void * parg) {
  int ret;
  DHT_Datastore * cls = (DHT_Datastore*) closure;
  ret = cls->iterate(closure,
		     flags,
		     processor,
		     parg);
  LOGRET(ret);
  return ret;
}

int main(int argc, 
	 char **argv) {
  char * tableName;
  int flags;
  unsigned int mem;
  HashCode160 table;
  DHT_Datastore myStore;

  if (SYSERR == initUtil(argc, argv, &parseOptions)) 
    return 0;

  tableName = getConfigurationString("DHT-JOIN", 
				     "TABLE");
  if (tableName == NULL) {
    printf(_("No table name specified, using '%s'.\n"),
	   "test");
    tableName = STRDUP("test");
  }
  if (OK != enc2hash(tableName,
		     &table)) {
    hash(tableName,
	 strlen(tableName),
	 &table);
  }
  FREE(tableName);
  mem = getConfigurationInt("DHT-JOIN",
			    "MEMORY");
  if (mem == 0) mem = 65536; /* default: use 64k */
  myStore.closure = create_datastore_memory(mem);
  myStore.lookup = &lookup;
  myStore.store = &store;
  myStore.remove = &removeDS;
  myStore.iterate = &iterate;

  flags = 1; /* one replica */
  
  DHT_LIB_init();
  initializeShutdownHandlers();
  if (OK != DHT_LIB_join(&myStore,
			 &table,
			 0,
			 flags)) {
    LOG(LOG_WARNING,
	_("Error joining DHT.\n"));
    destroy_datastore_memory((DHT_Datastore*)&myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 1;
  }

  printf(_("Joined DHT.  Press CTRL-C to leave.\n"));
  /* wait for CTRL-C */
  wait_for_shutdown();
  
  /* shutdown */ 
  if (OK != DHT_LIB_leave(&table,
			  getConfigurationInt("DHT-JOIN",
					      "TIMEOUT") * cronSECONDS,
			  flags)) {
    LOG(LOG_WARNING,
	_("Error leaving DHT.\n"));
    destroy_datastore_memory((DHT_Datastore*)&myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 1;
  } else {
    destroy_datastore_memory((DHT_Datastore*)&myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 0;
  }
}

/* end of dht-join.c */
