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
 * @file applications/tracekit/gnunet-tracekit.c 
 * @brief tool that sends a trace request and prints the received network topology
 * @author Christian Grothoff
 */

#include "tracekit.h"
#include "platform.h"

#define TRACEKIT_VERSION "0.0.1"

static Semaphore * doneSem;

/**
 * Parse the options, set the timeout.
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return OK on error, SYSERR if we should exit 
 */
static int parseOptions(int argc,
			char ** argv) {
  int option_index;
  int c;  

  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "wait", 1, 0, 'W' },
      { "depth", 1, 0, 'D' },
      { "format", 1, 0, 'F' },
      { "priority", 1, 0, 'P' },
      { 0,0,0,0 }
    };    
    option_index=0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:W:D:F:P:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'D': {
      int depth;

      if(!sscanf(GNoptarg,"%d",&depth)) 
	errexit("-D argument not a number\n");
      setConfigurationInt("GNUNET-TRACEKIT",
			  "HOPS",
			  depth);
      break;
    }
    case 'F': {
      int format;

      if(!sscanf(GNoptarg,"%d",&format)) 
	errexit("-F argument not a number\n");
      setConfigurationInt("GNUNET-TRACEKIT",
			  "FORMAT",
			  format);
      break;
    }
    case 'P': {
      int prio;

      if(!sscanf(GNoptarg,"%d",&prio)) 
	errexit("-P argument not a number\n");
      setConfigurationInt("GNUNET-TRACEKIT",
			  "PRIORITY",
			  prio);
      break;
    }
    case 'W': {
      int wait;

      if(!sscanf(GNoptarg,"%d",&wait)) 
	errexit("-W argument not a number\n");
      setConfigurationInt("GNUNET-TRACEKIT",
			  "WAIT",
			  wait);
      break;
    }
    case 'v': 
      printf("GNUnet v%s, gnunet-tracekit v%s\n",
	     VERSION,
	     TRACEKIT_VERSION);
      return SYSERR;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	{ 'D', "depth", "DEPTH",
	  "probe network to the given DEPTH" },
	{ 'F', "format", "FORMAT",
	  "0 for human readable output, 1 for dot" },
	HELP_HELP,
	HELP_LOGLEVEL,
	{ 'P', "priority", "PRIO",
	  "use PRIO for the priority of the trace request" },
	HELP_VERSION,
	{ 'W', "wait", "DELAY",
	  "wait DELAY seconds for replies" },
	HELP_END,
      };
      formatHelp("gnunet-tracekit [OPTIONS]",
		 "Trace GNUnet network topology.",
		 help);
      return SYSERR;
    }
    default: 
      LOG(LOG_FAILURE,
	  " Unknown option %c. Aborting.\n"\
	  "Use --help to get a list of options.\n",
	  c);
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

static void * receiveThread(GNUNET_TCP_SOCKET * sock) {
  TRACEKIT_CS_REPLY * buffer;
  int format;
  HostIdentity * peersSeen;
  int psCount;
  int psSize;
  HostIdentity * peersResponding;
  int prCount;
  int prSize;
  int i;
  int j;
  int match;

  psCount = 0;
  psSize = 1;
  peersSeen = MALLOC(psSize * sizeof(HostIdentity));
  prCount = 0;
  prSize = 1;
  peersResponding = MALLOC(prSize * sizeof(HostIdentity));
  buffer = MALLOC(MAX_BUFFER_SIZE);
  format = getConfigurationInt("GNUNET-TRACEKIT", 
			       "FORMAT");
  if (format == 1)
    printf("digraph G {\n");
  while (OK == readFromSocket(sock, 
			      (CS_HEADER**)&buffer)) {
    int count;
    EncName enc;

    count = ntohs(buffer->header.size) - sizeof(TRACEKIT_CS_REPLY);
    if (count < 0) {
      LOG(LOG_ERROR,
	  " invalid reply from gnunetd\n");
      break; /* faulty reply */
    }
    hash2enc(&buffer->responderId.hashPubKey,
	     &enc);
    match = NO;
    for (j=0;j<prCount;j++)
      if (equalsHashCode160(&buffer->responderId.hashPubKey,
			    &peersResponding[j].hashPubKey))
	match = YES;
    if (match == NO) {
      if (prCount == prSize) 
	GROW(peersResponding,
	     prSize,
	     prSize*2);
      memcpy(&peersResponding[prCount++],
	     &buffer->responderId.hashPubKey,
	     sizeof(HostIdentity));
    }
    count = count / sizeof(HostIdentity);
    if (ntohs(buffer->header.size) !=
	sizeof(TRACEKIT_CS_REPLY) +
	count * sizeof(HostIdentity)) {
      LOG(LOG_ERROR,
	  " invalid reply from gnunetd\n");
      break;
    }
    if (count == 0) {
      switch (format) {
      case 0:
	printf("%s is not connected to any peer.\n",
	       (char*)&enc);
	break;
      case 1:
	printf("  %.*s;\n",
	       4, (char*)&enc);
	break;
      default:
	printf("Format specification invalid. "
	       "Use 0 for user-readable, 1 for dot\n");
	break;
      }
    } else {
      EncName other;

      for (i=0;i<count;i++) {
	match = NO;
	for (j=0;j<psCount;j++)
	  if (equalsHashCode160(&((TRACEKIT_CS_REPLY_GENERIC*)buffer)->peerList[i].hashPubKey,
				&peersSeen[j].hashPubKey))
	    match = YES;
	if (match == NO) {
	  if (psCount == psSize)
	    GROW(peersSeen,
		 psSize,
		 psSize * 2);
	  memcpy(&peersSeen[psCount++],
		 &((TRACEKIT_CS_REPLY_GENERIC*)buffer)->peerList[i].hashPubKey,
		 sizeof(HostIdentity));
	}

	hash2enc(&((TRACEKIT_CS_REPLY_GENERIC*)buffer)->peerList[i].hashPubKey,
		 &other);
	switch (format) {
	case 0:
	  printf("%s connected to %s.\n",
		 (char*)&enc,
		 (char*)&other);
	  break;
	case 1: /* DOT */
	  printf("  \"%.*s\" -> \"%.*s\";\n",
		 4, (char*)&enc,
		 4, (char*)&other);
	  break;
	default: /* undef */
	  printf("Format specification invalid. "
		 "Use 0 for user-readable, 1 for dot\n");
	  break;
	}
      }
    }
  }
  FREE(buffer);
  for (i=0;i<psCount;i++) {
    EncName enc;

    match = NO;
    for (j=0;j<prCount;j++)
      if (equalsHashCode160(&peersResponding[j].hashPubKey,
			    &peersSeen[i].hashPubKey))
	match = YES;
    if (match == NO) {
      hash2enc(&peersSeen[i].hashPubKey,
	       &enc);
      switch (format) {
      case 0:
	printf("Peer %s did not report back.\n",
	       (char*)&enc);
	break;
      case 1:
	printf("  \"%.*s\" [style=filled,color=\".7 .3 1.0\"];\n",
	       4, (char*)&enc);
	break;
      default:
	break;
      }
    }
  }
  if (format == 1)
    printf("}\n");
  SEMAPHORE_UP(doneSem);
  FREE(peersResponding);
  FREE(peersSeen);  
  return NULL;
}

/**
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-tracekit: 0: ok, -1: error
 */   
int main(int argc, char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T messageReceiveThread;
  void * unused;
  TRACEKIT_CS_PROBE probe;
  int sleepTime;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */ 
  sock = getClientSocket();
  if (sock == NULL)
    errexit(" could not connect to gnunetd.\n");

  doneSem = SEMAPHORE_NEW(0);
  PTHREAD_CREATE(&messageReceiveThread, 
		 (PThreadMain) &receiveThread, 
		 sock,
		 128 * 1024);

  probe.header.size 
    = htons(sizeof(TRACEKIT_CS_PROBE));
  probe.header.tcpType
    = htons(TRACEKIT_CS_PROTO_PROBE);
  probe.hops 
    = htonl(getConfigurationInt("GNUNET-TRACEKIT",
				"HOPS"));
  probe.priority
    = htonl(getConfigurationInt("GNUNET-TRACEKIT",
				"PRIORITY"));  
  if (SYSERR == writeToSocket(sock,
                              &probe.header)) {
    LOG(LOG_ERROR,
	" could not send request to gnunetd\n");
    return -1;
  }
  startCron();
  initializeShutdownHandlers();
  sleepTime = getConfigurationInt("GNUNET-TRACEKIT",
                                  "WAIT");
  if (sleepTime == 0)
    sleepTime = 5;
  addCronJob((CronJob)&run_shutdown,
	     cronSECONDS * 
	     sleepTime,
	     0,
	     NULL);
  wait_for_shutdown();
  closeSocketTemporarily(sock);
  SEMAPHORE_DOWN(doneSem);
  SEMAPHORE_FREE(doneSem);
  PTHREAD_JOIN(&messageReceiveThread, &unused);
  doneShutdownHandlers();
  releaseClientSocket(sock);
  stopCron();
  doneUtil();
  return 0;
}

/* end of gnunet-tracekit.c */
