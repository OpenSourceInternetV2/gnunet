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
 * @file server/gnunetd.c
 * @brief Daemon that must run on every GNUnet peer.
 * @author Christian Grothoff
 * @author Larry Waldo
 * @author Tzvetan Horozov
 * @author Nils Durner
 */

#include "gnunet_util.h"

#include "startup.h"
#include "handler.h"
#include "pingpong.h"
#include "heloexchange.h"
#include "knownhosts.h"
#include "tcpserver.h"
#include "core.h"
#include "traffic.h"
#include "httphelo.h"


/**
 * This flag is set if gnunetd is not (to be) detached from the
 * console.
 */
int debug_flag = NO;

/**
 * This flag is set if gnunetd was started as windows service
 */
int win_service = NO;

void gnunet_main();

#ifdef MINGW
/**
 * Windows service information
 */
SERVICE_STATUS theServiceStatus;
SERVICE_STATUS_HANDLE hService;

/**
 * This function is called from the Windows Service Control Manager
 * when a service has to shutdown
 */
void WINAPI ServiceCtrlHandler(DWORD dwOpcode) {
  if (dwOpcode == SERVICE_CONTROL_STOP)
    win_shutdown_gnunetd(SERVICE_CONTROL_STOP);
}

/**
 * Main method of the windows service
 */
void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  memset(&theServiceStatus, sizeof(theServiceStatus), 0);
  theServiceStatus.dwServiceType = SERVICE_WIN32;
  theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  theServiceStatus.dwCurrentState = SERVICE_RUNNING;
  
  hService = GNRegisterServiceCtrlHandler("GNUnet", ServiceCtrlHandler);
  if (! hService)
    return;
    
  GNSetServiceStatus(hService, &theServiceStatus);
  
  gnunet_main();
  
  theServiceStatus.dwCurrentState = SERVICE_STOPPED;
  GNSetServiceStatus(hService, &theServiceStatus);
}
#endif

/**
 * The main method of gnunetd. And here is how it works:
 * <ol>
 * <li>detach from tty, initialize all coresystems
 * <li>a) start core-services
 *     b) initialize application services and download hostlist
 * <li>wait for semaphore to signal shutdown
 * <li>shutdown all services (in roughly inverse order)
 * <li>exit
 * </ol>
 */
void gnunet_main() {
  int filedes[2]; /* pipe between client and parent */
  int * sbit;
  int version;
  int firstStart;

  /* version management for GNUnet core */
  sbit = NULL;
  if (sizeof(int) == stateReadContent("GNUNET-VERSION",
				      (void**)&sbit)) {
    version = *sbit;
    FREE(sbit);
    if (ntohl(version) != 0x0630)
      errexit(_("You need to first run '%s'!\n"),
	      "gnunet-update");
    firstStart = NO;
  } else {
    FREENONNULL(sbit);  
    /* first start (or garbled version number), just write version tag */
    version = htonl(0x0630);  
    stateWriteContent("GNUNET-VERSION",
		      sizeof(int),
		      &version);
    firstStart = YES;
  }


  
  /* init 2: become deamon, initialize core subsystems */
  if (NO == debug_flag) 
    detachFromTerminal(filedes);  
  LOG(LOG_MESSAGE,
      "gnunetd starting\n");
  initHandler(); 
  initTCPServer();
  initPolicy(); 
  initTraffic();
  initKnownhosts(); 
  initConnection();   
  initPingPong();
  initCore(); 
  initTransports();
  initKeyService("gnunetd");
  initHeloExchange();  
  initHttpHelo();

  /* init 3a: start core services */
  startTransports();
  startCron();

  /* initialize signal handler (CTRL-C / SIGTERM) */
  if (NO == debug_flag) 
    detachFromTerminalComplete(filedes);  
  writePIDFile();

  /* init 3b: load application services */
  loadApplicationModules();
  if (firstStart == YES)
    downloadHostlist(); /* right away! */

  /* init 4: wait for shutdown */
  /* wait for SIGTERM, SIGTERM will set
     doShutdown to YES and send this thread
     a SIGUSR1 which will wake us up from the
     sleep */
  initSignalHandlers();
  LOG(LOG_MESSAGE,
      _("'%s' startup complete.\n"),
      "gnunetd");

  waitForSignalHandler();
  LOG(LOG_MESSAGE,
      _("'%s' is shutting down.\n"),
      "gnunetd");

  /* init 5: shutdown in inverse order */   
  stopCron();
  stopTCPServer();
  doneCore();
  deletePIDFile();
  doneHeloExchange();  
  doneHttpHelo(); 
  donePingPong();
  doneConnection();
  doneTransports();
  doneKeyService();
  doneKnownhosts();
  doneTraffic();
  doneTCPServer();
  doneHandler();
  donePolicy();
  /* init 6: goodbye */
  doneSignalHandlers();
  doneUtil();
}

/**
 * Initialize util (parse command line, options) and
 * call the main routine.
 */
int main(int argc, char * argv[]) {
  checkCompiler();
  umask(0);
  /* init 1: get options and basic services up */
  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0; /* parse error, --help, etc. */

#ifdef MINGW
  if (win_service) {
    SERVICE_TABLE_ENTRY DispatchTable[] =
      {{"GNUnet", ServiceMain}, {NULL, NULL}};
    GNStartServiceCtrlDispatcher(DispatchTable);
    
    return 0;
  } else
#endif
    gnunet_main();

  return 0;
} 

/* You have reached the end of GNUnet. You can shutdown your
   computer and get a life now. */
