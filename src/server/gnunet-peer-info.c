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
 * @file server/gnunet-peer-info.c
 * @brief Print information about other known peers.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"

#include "keyservice.h"
#include "knownhosts.h"

/**
 * Perform option parsing from the command line. 
 */
static int parser(int argc, 
		  char * argv[]) {
  int cont = OK;
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
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { "version", 0, 0, 'v' },
      { "help",    0, 0, 'h' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhc:L:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    
    switch(c) {
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    case 'v': 
      printf("gnunet-peer-info v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-peer-info [OPTIONS]",
		 _("Print information about GNUnet peers."),
		 help);
      cont = SYSERR;
      break;
    }
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    default:
      LOG(LOG_FAILURE, 
	  _("Use --help to get a list of options.\n"));
      cont = SYSERR;    
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    LOG(LOG_WARNING, 
	_("Invalid arguments: "));
    while (GNoptind < argc)
      LOG(LOG_WARNING, 
	  "%s ", argv[GNoptind++]);
    LOG(LOG_FATAL,
	_("Invalid arguments. Exiting.\n"));
    return SYSERR;
  }
  return cont;
}

/* make linker happy... */
static CoreAPIForTransport capi;
CoreAPIForTransport * getCoreAPIForTransport() {
  return &capi;
}

static char * trustDirectory ;

#define TRUSTDIR "data/credit/"

/**
 * Print information about the peer.
 * Currently prints the HostIdentity, trust and the IP. 
 * Could of course do more (e.g. resolve via DNS).
 */ 
static void printHostInfo(const HostIdentity * id,
			  const unsigned short proto,
			  void * data) {
  HELO_Message * helo;
  char * info;
  EncName enc;
  unsigned int trust;
  char * fn;

  hash2enc(&id->hashPubKey,
	   &enc);
  if (SYSERR == identity2Helo(id,
			      proto,
			      NO,
			      &helo)) {
    LOG(LOG_WARNING,
	_("Could not get address of peer '%s'.\n"),
	&enc);
    return;
  }  
  if (SYSERR == verifySig(&helo->senderIdentity,
			  HELO_Message_size(helo) - sizeof(Signature) - sizeof(PublicKey) - sizeof(p2p_HEADER),
			  &helo->signature,
			  &helo->publicKey)) {
    LOG(LOG_WARNING, 
	_("HELO message invalid (signature invalid).\n"));
  }
  info = heloToString(helo);
  FREE(helo);
  if (info == NULL) {
    LOG(LOG_WARNING,
	_("Could not get address of peer '%s'\n"),
	&enc);
    return;
  }
  
  fn = MALLOC(strlen((char*)trustDirectory)+sizeof(EncName)+1);
  buildFileName(trustDirectory, &enc, fn);
 
  if (sizeof(unsigned int) !=
      readFile(fn,
               sizeof(unsigned int),
               &trust))
    trust = 0;
  FREE(fn);
  
  printf(_("Peer '%s' with trust %8d and address '%s'\n"),
	 (char*)&enc,
	 trust,
	 info);
  FREE(info);
}

int main(int argc, char *argv[]) {
  char * gnHome;
  
  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;

  initKeyService("gnunet-peer-info");
  initTransports();
  initKnownhosts();

  gnHome = getFileName("",
                       "GNUNETD_HOME",
                       _("Configuration file must specify a directory for GNUnet to store per-peer data under %s%s\n"));
  trustDirectory = MALLOC(strlen(gnHome) + strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  FREE(gnHome);
  strcat(trustDirectory, "/");
  strcat(trustDirectory, TRUSTDIR);
  mkdirp(trustDirectory);

  forEachHost(&printHostInfo,
	      0,
	      NULL);

  FREE(trustDirectory);
  
  doneKnownhosts();
  doneTransports();
  doneKeyService();
  doneUtil();

  return 0;
}


/* end of gnunet-peer-info.c */
