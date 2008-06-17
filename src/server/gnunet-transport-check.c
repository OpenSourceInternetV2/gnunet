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
 * @file server/gnunet-transport-check.c
 * @brief Test for the transports.  
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 **/

#include "gnunet_util.h"
#include "transport.h"
#include "httphelo.h"
#include "keyservice.h"
#include "knownhosts.h"

#define DEBUG_TRANSPORT_CHECK NO

#define TEST_CRC 25116123
#define DEFAULT_MSG "Hello World"

static char * testmsg;

static MessagePack * receit;
static CoreAPIForTransport capi;
static Semaphore * sem;
static int terminate;
static cron_t timeout = 15 * cronSECONDS;

static void receive(MessagePack * mp) {
  if ( (sem == NULL) || (receit != NULL) ) {
    FREE(mp->msg);
    FREE(mp);
    return; /* spurious receive or double-receive, happens */
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) 
    fprintf(stderr, ".");
  receit = mp;
  SEMAPHORE_UP(sem);
}

static void semUp(Semaphore * sem) {
  terminate = YES;
  SEMAPHORE_UP(sem);
}

/**
 * Test the given transport API.
 **/
static void testTAPI(TransportAPI * tapi,
		     int * res) {
  HELO_Message * helo;
  TSession * tsession;
  unsigned int repeat;
  cron_t start;
  cron_t end;

  if (tapi == NULL)
    errexit("Could not initialize transport!\n");

  helo = NULL;
  if (OK != tapi->startTransportServer()) {
    fprintf(stderr,
	    "ERROR: could not start transport server\n");
    *res = SYSERR;
    return;
  }
  if (OK != tapi->createHELO(&helo)) {
    fprintf(stderr,
	    "ERROR: could not create HELO\n");
    tapi->stopTransportServer();
    *res = SYSERR;
    return;
  }
  tsession = NULL;
  if (OK != tapi->connect(helo,
			  &tsession)) {
    fprintf(stderr,
	    "ERROR: could not connect\n");
    *res = SYSERR;
    tapi->stopTransportServer();
    FREE(helo);
    return;
  }
  repeat = getConfigurationInt("TRANSPORT-CHECK",
			       "REPEAT");
  if (repeat == 0) {
    repeat = 1;
    setConfigurationInt("TRANSPORT-CHECK",
			"REPEAT",
			1);
  }
  sem = SEMAPHORE_NEW(0);
  cronTime(&start);
  while (repeat > 0) {
    repeat--;
    receit = NULL;
    if (OK != tapi->send(tsession,
			 testmsg,
			 strlen(testmsg),
			 NO,
			 TEST_CRC)) {
      fprintf(stderr,
	      "ERROR: could not send\n");
      *res = SYSERR;
      tapi->disconnect(tsession);
      tapi->stopTransportServer();
      SEMAPHORE_FREE(sem);
      return;
    }
    addCronJob((CronJob)&semUp,
	       timeout,
	       0,
	       sem);
    SEMAPHORE_DOWN(sem);
    suspendCron();
    delCronJob((CronJob)&semUp,
	       0,
	       sem); 
    resumeCron();
    if (receit == NULL) {
      fprintf(stderr,
	      "ERROR: did not receive message within %llu ms.\n",
	      timeout);
      *res = SYSERR;
      tapi->disconnect(tsession);
      tapi->stopTransportServer();
      SEMAPHORE_FREE(sem);
      return;
    }
    if ( (receit->crc != TEST_CRC) ||
	 (receit->size != strlen(testmsg)) ||
	 (receit->isEncrypted != NO) ||
	 (0 != memcmp(capi.myIdentity,
		      &receit->sender,
		      sizeof(HostIdentity))) ||
	 (0 != memcmp(receit->msg,
		      testmsg,
		      strlen(testmsg))) ) {
      fprintf(stderr,
	      "ERROR: message received was invalid\n");
      *res = SYSERR;
      tapi->disconnect(tsession);
      tapi->stopTransportServer();
      SEMAPHORE_FREE(sem);
      return;
    }
    FREE(receit->msg);
    FREE(receit);
  }
  cronTime(&end);
  if (OK != tapi->disconnect(tsession)) {
    fprintf(stderr,
	    "ERROR: could not disconnect\n");
    *res = SYSERR;
    tapi->stopTransportServer();
    SEMAPHORE_FREE(sem);
    return;
  }
  if (OK != tapi->stopTransportServer()) {
    fprintf(stderr,
	    "ERROR: could not stop server\n");
    *res = SYSERR;
    SEMAPHORE_FREE(sem);
    return;
  }

  SEMAPHORE_FREE(sem);
  printf("Transport OK, %ums for %d messages of size %d bytes.\n",
	 (unsigned int) ((end - start)/cronMILLIS),  
	 getConfigurationInt("TRANSPORT-CHECK",
			     "REPEAT"),
	 strlen(testmsg));
}


static void testPING(HELO_Message * xhelo,
		     int * stats) {  
  TSession * tsession;
  PINGPONG_Message pmsg;
  HELO_Message * helo;
  HELO_Message * myHelo;
  char * msg;
  int len;
  int again;
  int reply;
  
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) {
    char * str;
    str = heloToString(xhelo);
    fprintf(stderr, 
	    "\nContacting %s.",
	    str);
    FREE(str);
  } else
    fprintf(stderr, ".");
  helo = MALLOC(ntohs(xhelo->header.size));
  memcpy(helo, xhelo, ntohs(xhelo->header.size));

  stats[0]++; /* one more seen */
  if (NO == isTransportAvailable(ntohs(helo->protocol))) {
    fprintf(stderr, 
	    " Transport %d not available\n",
	    ntohs(helo->protocol));
    FREE(helo);
    return;
  }
  myHelo = NULL;
  if (OK != transportCreateHELO(ntohs(xhelo->protocol),
				&myHelo)) {
    FREE(helo);
    return;
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) 
    fprintf(stderr, ".");

  stats[1]++; /* one more with transport 'available' */

  pmsg.header.size = htons(sizeof(PINGPONG_Message));
  pmsg.header.requestType = htons(p2p_PROTO_PING);
  memcpy(&pmsg.receiver,
	 &helo->senderIdentity,
	 sizeof(HostIdentity));
  pmsg.challenge = rand();
 
  
  tsession = NULL;
  if (OK != transportConnect(helo, 
			     &tsession)) {
    FREE(helo);
    fprintf(stderr, 
	    " Connection failed\n");
    return;
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) 
    fprintf(stderr, ".");
  
  sem = SEMAPHORE_NEW(0);
  len = sizeof(PINGPONG_Message) + ntohs(myHelo->header.size);
  msg = MALLOC(len);
  memcpy(msg,
	 myHelo,
	 ntohs(myHelo->header.size));
  memcpy(&msg[ntohs(myHelo->header.size)],
	 &pmsg,
	 sizeof(PINGPONG_Message));
  FREE(myHelo);
  /* send ping */
  if (OK != transportSend(tsession,
			  msg,
			  len,
			  NO,
			  crc32N(msg, len))) {
    fprintf(stderr, 
	    " Send failed.\n");
    FREE(msg);
    transportDisconnect(tsession);
    return;
  }
  FREE(msg);
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) 
    fprintf(stderr, ".");
  /* check: received pong? */
  terminate = NO;
  addCronJob((CronJob)&semUp,
	     timeout,
	     5 * cronSECONDS,
	     sem);
  reply = 0;
  again = 1;
  while (again && (terminate == NO)) {
    again = 0;
    SEMAPHORE_DOWN(sem);
    if (receit != NULL) {
      p2p_HEADER * part;
      PINGPONG_Message * pong;      
      unsigned int pos;
      unsigned short plen;
      
      again = 1;
      if (0 != memcmp(&receit->sender,
		      &xhelo->senderIdentity,
		      sizeof(HostIdentity))) {
#if DEBUG_TRANSPORT_CHECK
	HexName hex1, hex2;
	hash2hex(&xhelo->senderIdentity.hashPubKey,
		 &hex1);
	hash2hex(&receit->sender.hashPubKey,
		 &hex2);
	fprintf(stderr, 
		"%s!=%s",
		(char*)&hex1, 
		(char*)&hex2);
#endif
	FREE(receit->msg);
	FREE(receit);
	receit = NULL;
	continue; /* different peer, ignore */
      }
      
      reply = 1;
      pos = 0;
      while (pos < receit->size) {
	part = (p2p_HEADER*) &((char*)receit->msg)[pos];
	plen = ntohs(part->size);
#if DEBUG_TRANSPORT_CHECK 
	fprintf(stderr, "PRT<%d,%d>:%d@%d",
		plen,
		ntohs(part->requestType),
		pos,
		receit->size);
#endif
	pos += plen;
	if ( (pos > receit->size) || (plen < sizeof(p2p_HEADER)) ) {
	  fprintf(stderr,
		  "!F");
	  break; /* malformed */
	}

	if ( (plen == sizeof(PINGPONG_Message)) &&
	     (part->requestType == htons(p2p_PROTO_PONG)) ) {	  
	  pong = (PINGPONG_Message*) part;
	  pong->header.requestType = htons(p2p_PROTO_PING);
	  if (0 == memcmp(&pmsg,
			  pong,
			  sizeof(PINGPONG_Message))) {
	    if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
					"VERBOSE",
				      "YES")) 
	      fprintf(stderr, "OK!");
	    stats[2]++;
	    reply = 2;
	    again = 0;
	    break;
	  } else {
	    if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
					"VERBOSE",
				      "YES")) 
	      fprintf(stderr,
		      "!"); /* invalid pong */
	  }
	} 
      }
      FREE(receit->msg);
      FREE(receit);
      receit = NULL;    
    }
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) {
    if (reply == 1)
      fprintf(stderr, " No PONG.");
    else if (reply == 0)
      fprintf(stderr, 
	      " No reply (within %llu ms).",
	      timeout);
  }
  suspendCron();
  delCronJob((CronJob)&semUp,
	     5 * cronSECONDS,
	     sem); 
  resumeCron();
  SEMAPHORE_FREE(sem);
  sem = NULL;
  if (receit != NULL) {
    FREE(receit->msg);
    FREE(receit);
    receit = NULL;        
  }
  transportDisconnect(tsession);  
}

/* dead code to make linker happy without
   dragging in heloexchange.c */
int receivedHELO(p2p_HEADER * message) {
  return OK;
}

/**
 * Perform option parsing from the command line. 
 **/
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
      { "transport", 1, 0, 't' },
      { "repeat",  1, 0, 'r' },
      { "size",    1, 0, 's'},
      { "Xrepeat", 1, 0, 'x' },
      { "timeout", 1, 0, 'T' },
      { "ping",    0, 0, 'p' },
      { "Xport",   1, 0, 'P' },
      { "verbose", 0, 0, 'V' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhc:L:t:r:s:X:P:pVT:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    
    switch(c) {
    case 'p': 
      FREENONNULL(setConfigurationString("TRANSPORT-CHECK",
					 "PING",
					 "YES"));
      break;
    case 'P':{
      unsigned int port;
      if (1 != sscanf(GNoptarg, "%ud", &port)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -P option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("TCP", "PORT", port);
	setConfigurationInt("UDP", "PORT", port);
	setConfigurationInt("TCP6", "PORT", port);
	setConfigurationInt("UDP6", "PORT", port);
	setConfigurationInt("HTTP", "PORT", port);
      }
      break;
    }
    case 's':{
      unsigned int size;
      if (1 != sscanf(GNoptarg, "%ud", &size)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -s option.\n");
	return SYSERR;
      } else {
	if (size == 0)
	  size = 2;
	else
	  size++;
	testmsg = MALLOC(size);
	testmsg[--size] = '\0';
	while (size > 0)
	  testmsg[--size] = 'A';
      }
      break;
    }
    case 'r':{
      unsigned int repeat;
      if (1 != sscanf(GNoptarg, "%ud", &repeat)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -r option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("TRANSPORT-CHECK",
			    "REPEAT",
			    repeat);
      }
      break;
    }
    case 'X':{
      unsigned int repeat;
      if (1 != sscanf(GNoptarg, "%ud", &repeat)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -X option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("TRANSPORT-CHECK",
			    "X-REPEAT",
			    repeat);
      }
      break;
    }
    case 'T':{
      if (1 != sscanf(GNoptarg, "%llu", &timeout)) {
	LOG(LOG_FAILURE, 
	    "You must pass a number to the -T option.\n");
	return SYSERR;
      }
      break;
    }
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    case 't':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "TRANSPORTS",
					 GNoptarg));
      break;
    case 'v': 
      printf("gnunet-transport-check v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-TRANSPORT-CHECK",
					 "VERBOSE",
					 "YES"));
      break;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,
	{ 'p', "ping", NULL,
	  "ping peers from HOSTLISTURL that match transports" },
	{ 'r', "repeat", "COUNT",
	  "send COUNT messages" },
	{ 's', "size", "SIZE",
	  "send messages with SIZE bytes payload" },
	{ 't', "transport", "TRANSPORT",
	  "specifies which TRANSPORT should be tested" },
	{ 'T', "timeout", "MS",
	  "specifies after how many MS to time-out" },
	HELP_VERSION,
        HELP_VERBOSE,
	HELP_END,
      };
      formatHelp("gnunet-transport-check [OPTIONS]",
		 "Test if GNUnet transport services are operational.",
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
	  "FAILURE: Unknown option %c. Aborting.\n"\
	  "Use --help to get a list of options.\n",
	  c);
      cont = SYSERR;    
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
  return cont;
}

CoreAPIForTransport * getCoreAPIForTransport() {
  return &capi;
}

int main(int argc, char *argv[]) {
  int res;
  int Xrepeat;
  char * trans;
  int ping;
  char * url;
  int i;
  int stats[3];

  if (OK != initUtil(argc, argv, &parser)) {
    return SYSERR;
  }
  if (testmsg == NULL)
    testmsg = STRDUP(DEFAULT_MSG);

  trans = getConfigurationString("GNUNETD",
				 "TRANSPORTS");
  if (trans == NULL)
    errexit("You must specify a non-empty set of transports to test!\n");
  ping = testConfigurationString("TRANSPORT-CHECK",
				 "PING",
				 "YES");
  if (! ping)
    printf("Testing transport(s) %s\n",
	   trans);
  else
    printf("Available transport(s): %s\n",
	   trans);
  FREE(trans);
  if (! ping) {
    /* disable blacklists (loopback is often blacklisted)... */
    FREENONNULL(setConfigurationString("TCP",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("UDP",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("TCP6",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("UDP6",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("HTTP",
				       "BLACKLIST",
				       NULL));
  }
  initKnownhosts();
  initTransports();
  if (ping) {
    initKeyService("gnunet-transport-check");
  } 
  startCron();

  capi.version = 0;
  capi.receive = &receive;
  capi.myIdentity = &myIdentity;
  Xrepeat = getConfigurationInt("TRANSPORT-CHECK",
				"X-REPEAT");
  if (Xrepeat == 0)
    Xrepeat = 1;
  res = OK;
  if (ping) {
    initHttpHelo();
    startTransports();

    stats[0] = 0;
    stats[1] = 0;
    stats[2] = 0;
    url = getConfigurationString("GNUNETD",
				 "HOSTLISTURL");
    if (url != NULL) {
      i = strlen(url);
      while (i > 0) {
	i--;
	if (url[i] == ' ') {
#if DEBUG_TRANSPORT_CHECK
	  fprintf(stderr,
		  "URL: %s\n", 
		  &url[i+1]);
#endif
	  downloadHostlistHelper(&url[i+1],
				 (HELO_Callback)&testPING,
				 &stats[0]);
	  url[i] = '\0';
	}
      } 
#if DEBUG_TRANSPORT_CHECK
      fprintf(stderr,
	      "URL: %s\n",
	      &url[0]);
#endif
      downloadHostlistHelper(&url[0],
			     (HELO_Callback)&testPING,
			     &stats[0]);
      FREE(url);
      fprintf(stderr, "\n");
    } else {
      printf("WARNING: no HOSTLISTURL specified in configuration!\n");
    }
    printf("%d out of %d peers contacted successfully (%d times transport unavailable).\n",
	   stats[2],
	   stats[1],
	   stats[0] - stats[1]);
    doneHttpHelo();
    stopTransports();
  } else {
    while (Xrepeat-- > 0) 
      forEachTransport((TransportCallback)&testTAPI,
		       &res);  
  }
  stopCron();
  doneTransports();
  if (ping) 
    doneKeyService();
  doneKnownhosts();
  FREE(testmsg);
  doneUtil();
  if (res == OK)
    return 0;
  else
    return -1;
}


/* end of gnunet-transport-check */
