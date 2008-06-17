/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 */

#include "gnunet_util.h"
#include "platform.h"

static FILE * logfile = NULL;
static int loglevel__ = LOG_WARNING;
static Mutex logMutex;
static int bInited = 0;
static TLogProc customLog = NULL;
static int maxLogLevel = LOG_EVERYTHING;

static char * loglevels[] = {
  "NOTHING",
  "FATAL",
  "ERROR",
  "FAILURE",
  "WARNING",
  "MESSAGE",
  "INFO",
  "DEBUG",
  "CRON",
  "EVERYTHING",
  NULL,
};

/**
 * Return the current logging level
 */
int getLogLevel() {
  return loglevel__;
}

/**
 * Return the logfile
 */
void *getLogfile() {
  return logfile;
}
 
/**
 * Convert a textual description of a loglevel into an int.
 */
static int getLoglevel(char * log) {
  int i;
  char * caplog;

  if (log == NULL)
    errexit(_("LOGLEVEL not specified, that is not ok.\n"));
  caplog = strdup(log);
  for (i=strlen(caplog)-1;i>=0;i--)
    caplog[i] = toupper(caplog[i]);    
  i = 0;
  while ( (loglevels[i] != NULL) &&
	  (0 != strcmp(caplog, loglevels[i])) )
    i++;
  free(caplog);
  if (loglevels[i] == NULL)
    errexit(_("Invalid LOGLEVEL '%s' specified.\n"),
	    log);
  return i;
}

/**
 * Re-read the loggig configuration.
 * Call on SIGHUP if the configuration file has changed.
 */
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
   if (loglevelname == NULL) {
      loglevelname = "WARNING";
      levelstatic = 1;
    }
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
    if (logfile == NULL)
      logfile = stderr;
    FREE(fn);
    FREE(logfilename);
  } else
    logfile = stderr;
  MUTEX_UNLOCK(&logMutex);
}

/**
 * Initialize the logging module.
 */
void initLogging() {
  MUTEX_CREATE_RECURSIVE(&logMutex);
 
  bInited = 1;
  registerConfigurationUpdateCallback(&resetLogging);
  resetLogging();
}

/**
 * Shutdown the logging module.
 */
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
 */
static void printTime() {
  if (logfile !=NULL) {
    char timebuf[64];
    time_t timetmp;
    struct tm * tmptr;
 
    time(&timetmp);
    tmptr = localtime(&timetmp);
    strftime(timebuf, 
	     64, 
	     "%b %d %H:%M:%S ", 
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
 */ 
void breakpoint_(const char * filename,
                 const int linenumber) {
  if (logfile != NULL) {
    printTime();
    fprintf(logfile, 
	    _("Failure at %s:%d.\n"),
    	    filename, 
	    linenumber);
    fflush(logfile);
  } else
    fprintf(stderr, 
	    _("Failure at at %s:%d.\n"),
    	    filename,
	    linenumber);
}

/**
 * Register an additional logging function which gets
 * called whenever GNUnet LOG()s something
 *
 * @param proc the function to register
 */
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
 */
void LOG(int minLogLevel,
	 const char *format, ...) {
  va_list	args;  
  size_t len;

  if (loglevel__ < minLogLevel)
    return;
  if (minLogLevel > maxLogLevel)
    minLogLevel = maxLogLevel;

  if (bInited)
    MUTEX_LOCK(&logMutex);
  va_start(args, format);
  if (logfile != NULL) {
    printTime();
    if (format[0] == ' ')
      fprintf(logfile, "%s:", loglevels[minLogLevel]);
    else
      fprintf(logfile, "%s: ", loglevels[minLogLevel]);
    len = vfprintf(logfile, format, args);
    fflush(logfile);
  } else
    len = vfprintf(stderr, format, args);
  va_end(args);
  if (bInited)
    MUTEX_UNLOCK(&logMutex);
  va_start(args, format);
  if (customLog) {
    char * txt;
    
    txt = MALLOC(len + 1);
    GNUNET_ASSERT(len == vsnprintf(txt, len, format, args));
    customLog(txt);
    FREE(txt);
  }
  va_end(args);  
}

/**
 * errexit - log an error message and exit.
 *
 * @param format the string describing the error message
 */
void errexit(const char *format, ...) {
  va_list args;

  /* NO locking here, we're supposed to die,
     and we don't want to take chances on that... */
  if (logfile != NULL) {
    va_start(args, format);
    printTime();
    vfprintf(logfile, format, args);
    fflush(logfile);
    va_end(args); 
  }
  if (logfile != stderr) {
    va_start(args, format);
#ifdef MINGW
    AllocConsole();
#endif
    vfprintf(stderr, format, args);
    va_end(args);
  }
  BREAK();
  abort();
  exit(-1); /* just in case... */
}

int SNPRINTF(char * buf,
	     size_t size,
	     const char * format,
	     ...) {
  int ret;
  va_list args;

  va_start(args, format);
  ret = vsnprintf(buf,
		  size,
		  format,
		  args);
  va_end(args);
  GNUNET_ASSERT(ret <= size);
  return ret;
}



/* end of logging.c */
