/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file util/initialize.c
 * @brief functions to initializing libgnunetutil in the proper order.
 * @author Christian Grothoff
 **/

#include "platform.h"
#include "gnunet_util.h"

/* internal prototypes... */
void initXmalloc();

void doneXmalloc();

/**
 * Initialize Random number generator.
 **/
void initRAND(); 

/**
 * This method must be called first. Typically,
 * the command line is parsed after that and then
 * "readConfiguration" is invoked.
 **/
void initConfiguration();

/**
 * This method may be called at last to clean up.
 * Afterwards everything but initConfiguration will result
 * in errors...
 **/
void doneConfiguration();

void initState();

/**
 * Clean shutdown of the state module
 **/
void doneState();

/**
 * Initialize the statistics module.
 **/
void initStatistics();

/**
 * Shutdown the statistics module.
 **/
void doneStatistics();

/**
 * initialize logging module.
 **/
void initLogging();

/**
 * Shutdown the logging module.
 **/
void doneLogging();

/**
 * The following method is called in order to initialize the status
 * calls routines. After that it is safe to call each of the status
 * calls separately
 */
void initStatusCalls();

/**
 * Shutdown the module.
 **/
void doneStatusCalls();

/** 
 * Initialize identity module. Requries configuration.
 **/
int initAddress();

/** 
 * Shutdown identity module.
 **/
void doneAddress();

void gnunet_util_initIO();
void gnunet_util_doneIO();

#if ! USE_OPENSSL
void initLockingGcrypt();
void doneLockingGcrypt();
#endif


/**
 * Initialize the util library. Use argc, argv and the given parser
 * for processing command-line options <strong>after</strong> the
 * configuration module was initialized, but <strong>before</strong> logging
 * and other configuration-dependent features are started.
 **/
int initUtil(int argc,
	     char * argv[],
	     CommandLineParser parser) {
  gnunet_util_initIO();
  initRAND();
  initStatistics();
  initXmalloc();
#if ! USE_OPENSSL
  initLockingGcrypt();
#endif
#ifdef MINGW
  InitWinEnv();
#endif
  initConfiguration();
  if (argc > 0)
    setConfigurationString("MAIN",
			   "ARGV[0]",
			   argv[0]);
  initCron();
  if (parser != NULL)
    if (SYSERR == parser(argc, argv))
      return SYSERR;
  readConfiguration();
  initLogging();
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES")) {
    initStatusCalls(); 
    if (OK != initAddress())
      return SYSERR;
  }
  initState();
  return OK;
}

void doneUtil() {
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES")) {
    doneStatusCalls();
    doneAddress();
  }
  doneCron();
  doneState();
  doneStatistics();
  LOG(LOG_MESSAGE,
      "Shutdown complete.\n");
  doneLogging();  
  doneConfiguration();
#ifdef MINGW
  ShutdownWinEnv();
#endif
#if ! USE_OPENSSL 
  doneLockingGcrypt();
#endif
  doneXmalloc();
  gnunet_util_doneIO();
}

/* end of initialize.c */
