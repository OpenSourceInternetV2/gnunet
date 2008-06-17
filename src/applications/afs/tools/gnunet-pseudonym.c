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
 * @file applications/afs/tools/gnunet-pseudonym.c
 * @brief create, list or delete pseudoynms
 * @author Christian Grothoff
 **/

#include "gnunet_afs_esed2.h"
#include "platform.h"

static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'C', "create", "NAME",
      "create a new pseudonym (with the given password if specified)" },
    { 'D', "delete", "NAME",
      "delete the given pseudonym" },
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'p', "password", "PASS",
      "use the given password for the new pseudonym or to decrypt pseudonyms from the pseudonym database" },
    { 'q', "quiet", NULL,
      "do not list the pseudonyms from the pseudonym database" },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-pseudonym [OPTIONS]",
	     "List existing, create or delete pseudonyms.",
	     help);
}

/**
 * Perform option parsing from the command line. 
 **/
static int parser(int argc, 
	   char * argv[]) {
  int c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "password", 1, 0, 'p' },
      { "create", 1, 0, 'C' },
      { "delete", 1, 0, 'D' },
      { "quiet", 0, 0, 'q' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhc:L:p:C:D:q", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v': 
      printf("gnunet-pseudoynm v%s\n",
	     VERSION);
      return SYSERR;
    case 'C':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "CREATE",
					 GNoptarg));
      break;
    case 'q':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "QUIET",
					 "YES"));
      break;
    case 'D':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "DELETE",
					 GNoptarg));
      break;

    case 'p':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "PASSWORD",
					 GNoptarg));
      break;
    case 'h': 
      printhelp();
      return SYSERR;
    default:
      LOG(LOG_FAILURE, 
	  "FAILURE: Unknown option %c. Aborting.\n"\
	  "Use --help to get a list of options.\n",
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    LOG(LOG_WARNING, 
	"WARNING: Invalid arguments: ");
    while (GNoptind < argc)
      LOG(LOG_WARNING, 
	  "%s ", argv[GNoptind++]);
    LOG(LOG_FATAL,
	"FATAL: Invalid arguments. Exiting.\n");
    return SYSERR;
  }
  return OK;
}


int main(int argc, char *argv[]) {
  char ** list;
  int i;
  int cnt;
  char * pass;
  char * pname;
  int success;
  Hostkey hk;
  
  success = 0; /* no errors */
  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;

  pname = getConfigurationString("PSEUDONYM",
				 "DELETE");
  if (pname != NULL) {
    if (OK != deletePseudonym(pname)) {
      printf("Pseudonym %s deleted.\n",
	     pname);
    } else {
      success += 2;
      printf("Error deleting pseudonym %s (does not exist?).\n",
	     pname);
    }
    FREE(pname);
  }

  pass = getConfigurationString("PSEUDONYM",
				"PASSWORD");
  pname = getConfigurationString("PSEUDONYM",
				 "CREATE");
  if (pname != NULL) {
    if(pass == NULL || pass[0]=='\n')
      LOG(LOG_WARNING, 
	  "WARNING: No password supplied\n");
    hk = createPseudonym(pname,
			 pass);
    if (hk == NULL) {
      printf("Could not create pseudonym %s (exists?).\n",
	     pname);
      success += 1;
    } else {
      printf("Pseudonym %s created.\n",
	     pname);
      freeHostkey(hk);
    }
    FREE(pname);
  }
  
  if (testConfigurationString("PSEUDONYM",
			      "QUIET",
			      "YES"))
    return success; /* do not print! */

  list = NULL;
  cnt = listPseudonyms(&list);
  if (cnt == -1) {
    printf("Could not access pseudonym directory.\n");
    return 127;
  }
  for (i=0;i<cnt;i++) {
    char * id;
    HexName hex;

    Hostkey p = readPseudonym(list[i],
			      pass);
    if (p != NULL) {
      PublicKey pk;
      HashCode160 hc;
      getPublicKey(p, &pk);
      hash(&pk, sizeof(PublicKey), &hc);
      hash2hex(&hc, &hex);
      id = (char*)&hex;
    } else
      id = "not decrypted";
    printf("%s %s\n",
	   list[i],
	   id);
    FREE(list[i]);
  }
  FREENONNULL(list);

  doneUtil();
  return success;
}

/* end of gnunet-pseudonym.c */
