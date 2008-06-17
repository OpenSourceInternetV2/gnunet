/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/gnunet-update.c
 * @brief tool to process changes due to version updates
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-update [OPTIONS]",
	     _("Updates GNUnet datastructures after version change."),
	     help);
}

static int be_verbose = NO;

/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  int c;

  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the user-tools).  Needed such that we use
     the right configuration file... */
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "verbose", 0, 0, 'V' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:VL:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;    
    switch(c) {
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
     break;
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'v': 
      printf("GNUnet v%s, gnunet-update 0.0.0\n",
	     VERSION);
      return SYSERR;
    case 'V':
      be_verbose = YES;
      break;
    default:
      printf(_("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    printf(_("Invalid arguments: "));
    while (GNoptind < argc)
      printf("%s ", argv[GNoptind++]);
    printf(_("\nExiting.\n"));
    return SYSERR;
  }
  return OK;
}

static void rename062bCallback(const char * filename,
			       const char * dirName,
			       void * unused) {
  char * oldName;
  char * newName;
  EncName enc;
  HashCode160 hc;
  char * backup;

  if (strlen(filename) < sizeof(HexName)-1)
    return;
  backup = STRDUP(&filename[sizeof(HexName)-1]);
  oldName = MALLOC(strlen(dirName) + strlen(filename) + 10);
  strcpy(oldName, dirName);
  strcat(oldName, "/");
  strcat(oldName, filename);

  if (strlen(filename) != sizeof(HexName)-1) {
    FREE(backup);
    FREE(oldName);
    return;
  }
  if (SYSERR == tryhex2hash(filename,
			    &hc)) {  
    FREE(backup);
    FREE(oldName);
    return;
  }
  hash2enc(&hc, &enc);

  newName = MALLOC(strlen(dirName) + strlen(filename) + strlen(backup) + 10);
  strcpy(newName, dirName);
  strcat(newName, "/");
  strcat(newName, (char*) &enc);
  strcat(newName, backup);
  FREE(backup);
  if (YES == be_verbose)
    printf(_("Renamnig file '%s' to '%s'\n"),
	     oldName, newName);
  if (0 != rename(oldName, newName))
    LOG(LOG_ERROR,
	_("Could not rename '%s' to '%s': %s\n"),
	oldName, newName, STRERROR(errno));
  FREE(oldName);
  FREE(newName);
}

#define TRUSTDIR "data/credit/"

/**
 * Update from version 0.6.2b and earlier to
 * 0.6.3 (and later).
 * go over trust/ and hosts/ directories and rename files
 */
static void update062b() {
  char * gnHome;
  char * trustDirectory; 
  
  gnHome = getFileName("",
		       "GNUNETD_HOME",
		       _("Configuration file must specify a "
			 "directory for GNUnet to store "
			 "per-peer data under %s%s\n"));
  trustDirectory = MALLOC(strlen(gnHome) + 
			  strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  FREE(gnHome);
  strcat(trustDirectory, "/");
  strcat(trustDirectory, TRUSTDIR);
  scanDirectory(trustDirectory,
		&rename062bCallback,
		NULL);
  FREE(trustDirectory);
  gnHome = getFileName("GNUNETD",
		       "HOSTS",
		       _("Configuration file must specify directory for "
			 "network identities in section %s under %s.\n"));
  scanDirectory(gnHome,
		&rename062bCallback,
		NULL);  
}

static int work() {
  int * sbit;
  int version;
  int val;
  
  sbit = NULL;
  if (sizeof(int) == stateReadContent("GNUNET-VERSION",
				      (void**)&sbit)) {
    version = *sbit;
    FREE(sbit);
    switch (ntohl(version)) {
    case 0x0630: 
      printf(_("State is current, no update required.\n"));
      break;
    default:
      printf(_("Unknown version, are you down-grading?\n"));
    }
  } else {
    printf(_("Updating from version pre 0.6.3 (or first run)\n"));
    printf(_("You may also want to run gnunet-check -u.\n"));
    update062b();
    FREENONNULL(sbit);
  }
  val = htonl(0x0630);  
  stateWriteContent("GNUNET-VERSION",
		    sizeof(int),
		    &val);
  return OK;
}



int main(int argc, char * argv[]) {
  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0;
  work();  
  doneUtil();
  return 0;
}

/* end of gnunet-update */
