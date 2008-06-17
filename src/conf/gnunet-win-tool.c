/*
     This file is part of GNUnet.
     (C) 2001 - 2004 Christian Grothoff (and other contributing authors)

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
 * @file conf/gnunet-win-tool.c 
 * @brief tool for Windows specific tasks
 * @author Nils Durner
 **/

#include "platform.h"

#define WINTOOL_VERSION "0.1.0"

static int bPrintAdapters, bInstall, bUninstall;

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 **/
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'n', "netadapters", NULL, "list all network adapters" },
    { 'i', "install", NULL, "install GNUnet as Windows service" },    
    { 'u', "uninstall", NULL, "uninstall GNUnet service" },    
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-win-tool [OPTIONS]",
	     "Tool for Windows specific tasks.",
	     help);
}

/**
 * Print all network adapters with their index number
 **/
void PrintAdapters()
{
  PMIB_IFTABLE pTable;
  DWORD dwSize, dwRet;

  if (GNGetIfTable)
  {
        dwSize = 0;
  	dwRet = 0;
  	
  	pTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, sizeof(MIB_IFTABLE));
  	
  	/* Get size of table */
  	if (GNGetIfTable(pTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
  	{
  	  GlobalFree(pTable);
  	  pTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, dwSize);
  	}
  	
  	if ((dwRet = GNGetIfTable(pTable, &dwSize, 0)) == NO_ERROR)
  	{
          DWORD dwIfIdx, dwSize = sizeof(MIB_IPADDRTABLE);
          PMIB_IPADDRTABLE pAddrTbl = (MIB_IPADDRTABLE *) 
            GlobalAlloc(GPTR, dwSize);
          
          /* Make an initial call to GetIpAddrTable to get the
             necessary size */
          if (GNGetIpAddrTable(pAddrTbl, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
          {
            GlobalFree(pAddrTbl);
            pAddrTbl = (MIB_IPADDRTABLE *) GlobalAlloc(GPTR, dwSize);
          }
          GNGetIpAddrTable(pAddrTbl, &dwSize, 0);
  	
  	  for(dwIfIdx=0; dwIfIdx <= pTable->dwNumEntries; dwIfIdx++)
  	  {
            printf("Index: %i\nAdapter name: %s\n",
              (int) pTable->table[dwIfIdx].dwIndex, pTable->table[dwIfIdx].bDescr);

  	    /* Get IP-Addresses */
            int i;
            for(i = 0; i < pAddrTbl->dwNumEntries; i++)
            {  
              if (pAddrTbl->table[i].dwIndex == dwIfIdx)
                printf("Address: %d.%d.%d.%d\n", 
                  PRIP(ntohl(pAddrTbl->table[i].dwAddr)));
            }
            
            printf("\n");
          }
          GlobalFree(pAddrTbl);
  	}
  	else
          printf("ERROR: Could not get list of network adapters.\n");

    GlobalFree(pTable);
  }
  else
    printf("Index: 0\nAdapter name: not available\n\n");
}

/**
 * Install GNUnet as Windows service
 **/
void Install()
{
  HANDLE hManager, hService;
  char szEXE[_MAX_PATH + 17] = "\"";
  
  if (! GNOpenSCManager)
  {
    printf("This version of Windows doesn't support services.\n");
    return;
  }
  
  conv_to_win_path("/bin/gnunetd.exe", szEXE + 1);
  strcat(szEXE, "\" --win-service");
  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (! hManager)
  {
    SetErrnoFromWinError(GetLastError());
    printf("Error: can't open Service Control Manager: %s\n", _win_strerror(errno));
    return;
  }
  
  hService = GNCreateService(hManager, "GNUnet", "GNUnet", 0,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, szEXE,
    NULL, NULL, NULL, NULL, NULL);

  if (! hService)
  {
    SetErrnoFromWinError(GetLastError());
    printf("Error: can't create service: %s\n", _win_strerror(errno));
    return;
  }
  
  GNCloseServiceHandle(hService);
  
  printf("GNUnet service installed successfully.\n");
}

/**
 * Uninstall the service
 **/
void Uninstall()
{
  HANDLE hManager, hService;

  if (! GNOpenSCManager)
  {
    printf("This version of Windows doesn't support services.\n");
    return;
  }
  
  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (! hManager)
  {
    SetErrnoFromWinError(GetLastError());
    printf("Error: can't open Service Control Manager: %s\n", _win_strerror(errno));
    return;
  }

  if (! (hService = GNOpenService(hManager, "GNUnet", DELETE)))
  {
    SetErrnoFromWinError(GetLastError());
    printf("Error: can't access service: %s\n", _win_strerror(errno));
    return;
  }
  
  if (! GNDeleteService(hService))
  {
    SetErrnoFromWinError(GetLastError());
    printf("Error: can't delete service: %s\n", _win_strerror(errno));
    return;
  }
  
  GNCloseServiceHandle(hService);
  
  printf("Service deleted.\n");
}

/**
 * Parse the options.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should abort, OK to continue
 **/
static int parseOptions(int argc, char ** argv) {
  int option_index;
  int c;
  BOOL bPrintHelp = TRUE;

  while (1) {
    static struct GNoption long_options[] = {
      { "netadapters",          0, 0, 'n' }, 
      { "install",              0, 0, 'i' }, 
      { "uninstall",            0, 0, 'u' }, 
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };    
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:niu", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    
    bPrintHelp = FALSE;
      
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
      case 'v': 
        printf("GNUnet v%s, gnunet-win-tool v%s\n",
  	      VERSION, WINTOOL_VERSION);
        return SYSERR;
      case 'h': 
        printhelp(); 
        return SYSERR;
      case 'n':
        bPrintAdapters = YES;
        break;
      case 'i':
        bInstall = YES;
        break;
      case 'u':
        bUninstall = YES;
        break;
      default: 
        LOG(LOG_FAILURE,
        	  "Unknown option %c. Aborting.\n"\
        	  "Use --help to get a list of options.\n",
  	  c);
        return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  
  if (bPrintHelp) {
    printhelp();
    
    return SYSERR;
  }
  
  return OK;
}

/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 **/   
int main(int argc, char ** argv) {
  int res;

  res = OK;
  bPrintAdapters = bInstall = bUninstall = NO;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  if (bPrintAdapters)
    PrintAdapters();
  if (bUninstall)
    Uninstall();
  else if (bInstall)
    Install();

  doneUtil();

  return (res == OK) ? 0 : 1;
}

/* end of gnunet-win-tool.c */
