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
 * @file util/logging.c
 * @brief basic logging mechanism
 * @author Christian Grothoff
 *
 * This file contains basic logging mechanisms, with log-levels,
 * logging to file or stderr and with or without time-prefixing.
 **/

#include "gnunet_util.h"
#include "platform.h"

static FILE * logfile = NULL;
static int loglevel__ = LOG_WARNING;
static Mutex logMutex;
static int bInited = 0;
static TLogProc customLog = NULL;

/**
 * Return the current logging level
 **/
int getLogLevel() {
  return loglevel__;
}

/**
 * Return the logfile
 **/
void *getLogfile() {
  return logfile;
}
 
/**
 * Convert a textual description of a loglevel into an int.
 **/
static int getLoglevel(char * log) {
  if (log == NULL)
    errexit("LOGLEVEL specified is NULL, that's not ok.\n");
  if (0 == strcmp(log, "NOTHING"))
    return LOG_NOTHING;
  if (0 == strcmp(log, "FATAL"))
    return LOG_FATAL;
  if (0 == strcmp(log, "ERROR"))
    return LOG_ERROR;
  if (0 == strcmp(log, "FAILURE"))
    return LOG_FAILURE;
  if (0 == strcmp(log, "WARNING"))
    return LOG_WARNING;
  if (0 == strcmp(log, "MESSAGE"))
    return LOG_MESSAGE;
  if (0 == strcmp(log, "INFO"))
    return LOG_INFO;
  if (0 == strcmp(log, "DEBUG"))
    return LOG_DEBUG;
  if (0 == strcmp(log, "CRON"))
    return LOG_CRON;
  if (0 == strcmp(log, "EVERYTHING"))
    return LOG_EVERYTHING;
  errexit("invalid loglevel specified: %s (did you use all-caps?)\n",
	  log);
  return 42; /* can not happen */
}

/**
 * Re-read the loggig configuration.
 * Call on SIGHUP if the configuration file has changed.
 **/
static void resetLogging() {
  char * loglevelname;
  char * logfilename;
  char * base;
  int levelstatic = 0;

  MUTEX_LOCK(&logMutex);
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES")) {
    base = "GNUNETD";
    loglevelname
      = getConfigurationString("GNUNETD",
			       "LOGLEVEL");
  } else {
    base = "GNUNET";
    loglevelname
      = getConfigurationString("GNUNET",
			       "LOGLEVEL");
    if (loglevelname == NULL) {
      loglevelname = "WARNING";
      levelstatic = 1;
    }
  }

  
  loglevel__ 
    = getLoglevel(loglevelname); /* will errexit if loglevel == NULL */
  if (! levelstatic)
    FREE(loglevelname);

  logfilename
    = getConfigurationString(base,
			     "LOGFILE");
  if (logfilename != NULL) {
    char * fn;

    fn = expandFileName(logfilename);
    logfile = FOPEN(fn, "a+");
    FREE(fn);
    FREE(logfilename);
  } else
    logfile = stderr;
  MUTEX_UNLOCK(&logMutex);
}

/**
 * Initialize the logging module.
 **/
void initLogging() {
  MUTEX_CREATE_RECURSIVE(&logMutex);
 
  bInited = 1;
  registerConfigurationUpdateCallback(&resetLogging);
  resetLogging();
}

/**
 * Shutdown the logging module.
 **/
void doneLogging() {
  unregisterConfigurationUpdateCallback(&resetLogging);
  if ( (logfile != NULL) &&
       (logfile != stderr) )
    fclose(logfile);
  logfile = NULL;
  loglevel__ = 0;
  MUTEX_DESTROY(&logMutex);
  bInited = 0;
}


/**
 * Print the current time to logfile without linefeed
 **/
static void printTime() {
  if (logfile !=NULL) {
    char timebuf[64];
    time_t timetmp;
    struct tm * tmptr;
 
    time(&timetmp);
    tmptr = localtime(&timetmp);
    strftime(timebuf, 
	     64, 
	     "%b %e %H:%M:%S ", 
	     tmptr);
    fputs(timebuf, 
	  logfile);
  }
}

/**
 * Something went wrong, add opportunity to stop gdb at this
 * breakpoint and/or report in the logs that this happened.
 *
 * @param filename where in the code did the problem occur
 * @param linenumber where in the code did the problem occur
 **/ 
void breakpoint_(const char * filename,
                 const int linenumber) {
  if (logfile != NULL) {
    printTime();
    fprintf(logfile, "__BREAK__ at %s:%d\n",
    	    filename, 
	    linenumber);
    fflush(logfile);
  } else
    fprintf(stderr, "__BREAK__ at %s:%d\n",
    	    filename,
	    linenumber);
}

/**
 * Register an additional logging function which gets
 * called whenever GNUnet LOG()s something
 *
 * @param proc the function to register
 **/
void setCustomLogProc(TLogProc proc) {
  if (bInited)
    MUTEX_LOCK(&logMutex);

  customLog = proc;

  if (bInited)
    MUTEX_UNLOCK(&logMutex);
}

/**
 * Log a debug message
 *
 * @param minLogLevel minimum level at which this message should be logged
 * @param format the string describing the error message
 **/
void LOG(int minLogLevel,
	 const char *format, ...) {
  va_list	args;  
  int           len = 0;

  if (loglevel__ < minLogLevel)
    return;

  if (bInited)
    MUTEX_LOCK(&logMutex);
  va_start(args, format);
  if (logfile != NULL) {
    printTime();
    len = vfprintf(logfile, format, args);
    fflush(logfile);
  } else
    len = vfprintf(stderr, format, args);
  if (customLog) {
    char *txt = (char *) MALLOC(len > 0 ? len : 251);
    vsnprintf(txt, 250, format, args);
    txt[250] = 0;
    customLog(txt);
    FREE(txt);
  }
  va_end(args);
  
  if (bInited)
    MUTEX_UNLOCK(&logMutex);
}

/**
 * errexit - log an error message and exit.
 *
 * @param format the string describing the error message
 **/
void errexit(const char *format, ...) {
  va_list args;

  /* NO locking here, we're supposed to die,
     and we don't want to take chances on that... */
  va_start(args, format);
  if (logfile != NULL) {
    printTime();
    vfprintf(logfile, format, args);
    fflush(logfile);
  } else {
#ifdef MINGW
    AllocConsole();
#endif
    vfprintf(stderr, format, args);
  }
  va_end(args);
  BREAK();
  abort();
  exit(-1); /* just in case... */
}

/* end of logging.c */
