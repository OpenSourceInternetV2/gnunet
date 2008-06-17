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
 * @file applications/tbench/gnunet-tbench.c 
 * @brief Transport mechanism benchmarking tool
 * @author Paul Ruth
 */

#include "tbench.h"
#include "platform.h"

#define TBENCH_VERSION "0.0.3"

#define DEFAULT_MESSAGE_SIZE	10
#define DEFAULT_TIMEOUT		2
#define DEFAULT_SPACING		0

#define OF_HUMAN_READABLE 0
#define OF_GNUPLOT_INPUT 1

static int  messageSize = DEFAULT_MESSAGE_SIZE;
static int  messageCnt  = 1;
static char * messageReceiver;
static int  messageIterations = 1;
static int  messageTrainSize = 1;
static int  messageTimeOut = DEFAULT_TIMEOUT;
static int  messageSpacing = DEFAULT_SPACING;
static int outputFormat = OF_HUMAN_READABLE;

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
      { "gnuplot", 0, 0, 'g' },
      { "rec", 1, 0, 'r'},
      { "msg", 1, 0, 'n'},
      { "iterations", 1, 0, 'i'},
      { "timeout", 1, 0, 't' },
      { "space", 1, 0, 'S' },
      { "xspace", 1, 0, 'X' },
      { 0,0,0,0 }
    };    
    option_index=0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:n:s:r:i:t:S:X:g", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process*/
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v': 
      printf("GNUnet v%s, gnunet-tbench v%s\n",
	     VERSION,
	     TBENCH_VERSION);
      return SYSERR;

    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	{ 'g', "gnuplot", NULL,
	  "output in gnuplot format" },
	{ 'i', "iterations", "ITER",
	  "number of iterations" }, 
	HELP_LOGLEVEL,	
	{ 'n', "msg", "MESSAGES",
	  "number of messages to use per iteration"},
	{ 'r', "rec", "RECEIVER",
	  "receiver host identifier (ENC file name)" },
	{ 's', "size", "SIZE",
	  "message size" },
	{ 'S', "space", "SPACE",
	  "inter-train message spacing" },
	{ 't', "timeout", "TIMEOUT",
	  "time to wait for the arrival of a response" },
	HELP_VERSION,
	{ 'X', "xspace", "COUNT",
	  "sleep for SPACE ms after COUNT messages"},
	HELP_END,
      };
      formatHelp("gnunet-chat [OPTIONS]",
		 "Start GNUnet chat client.",
		 help);
      return SYSERR;
    }
    case 's': 
      if(!sscanf(GNoptarg,"%d",&messageSize)){
	printf("-s argument not a number\n");
	exit(1);
      }
      break;
    case 'g': 
      outputFormat = OF_GNUPLOT_INPUT;
      break;
    case 'X':
      if(!sscanf(GNoptarg,"%d",&messageTrainSize)){
	printf("-X argument not a number\n");
	exit(1);
      }
      break;
    case 'n': 
      if(!sscanf(GNoptarg,"%d",&messageCnt)){
	printf("-n argument not a number\n");
	exit(1);
      }
      break;

    case 'r': 
      messageReceiver = STRDUP(GNoptarg);
      break;

    case 'i': 
      if(!sscanf(GNoptarg,"%d",&messageIterations)){
	printf("-i argument not a number\n");
	exit(1);
      }
      break;

    case 't':
      if(!sscanf(GNoptarg,"%d",&messageTimeOut)){
	printf("-t argument not a number\n");
	exit(1);
      }
      break;

    case 'S':
      if(!sscanf(GNoptarg,"%d",&messageSpacing)){
	printf("-S argument not a number\n");
	exit(1);
      }
      break;

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

/**
 * Tool to benchmark the performance of the P2P transports.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunetsearch: 0: ok, -1: error
 */   
int main(int argc, char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  TBENCH_CS_MESSAGE msg;
  TBENCH_CS_REPLY * buffer;
  float messagesPercentLoss;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */ 
  sock = getClientSocket();
  if (sock == NULL)
    errexit(" could not connect to gnunetd.\n");

  memset(&msg,
	 0,
	 sizeof(TBENCH_CS_MESSAGE));
  msg.msgSize     =htons(messageSize);
  msg.msgCnt      =htons(messageCnt);
  msg.iterations  =htons(messageIterations);
  msg.intPktSpace =htons(messageSpacing);
  msg.trainSize   =htons(messageTrainSize);
  msg.timeOut     =htonl(messageTimeOut);
  if (messageReceiver == NULL)
    errexit("You must specify a receiver!\n");
  if (OK != enc2hash(messageReceiver,
		     &msg.receiverId.hashPubKey))		     
    errexit("Invalid receiver peer ID specified (%s is not valid enc name)\n",
	    messageReceiver);
  FREE(messageReceiver);

  msg.header.size = htons(sizeof(TBENCH_CS_MESSAGE));
  msg.header.tcpType = htons(TBENCH_CS_PROTO_REQUEST);

  if (SYSERR == writeToSocket(sock,
			      &msg.header))
    return -1;
  
  buffer = MALLOC(MAX_BUFFER_SIZE);
  LOG(LOG_DEBUG,
      " reading from readFromSocket\n");
  if (OK == readFromSocket(sock, (CS_HEADER**)&buffer)) {
    if((float)buffer->mean_loss <= 0){
      messagesPercentLoss = 0.0;
    } else {
      messagesPercentLoss = (buffer->mean_loss/((float)htons(msg.msgCnt)));
    }
    switch (outputFormat) {
    case OF_HUMAN_READABLE:
      printf("Time:\n");
      printf("\tmax      %d\n",
	     htons(buffer->max_time));
      printf("\tmin      %d\n",
	     htons(buffer->min_time));
      printf("\tmean     %f\n",
	     buffer->mean_time);
      printf("\tvariance %f\n",
	     buffer->variance_time);
      
      printf("Loss:\n");
      printf("\tmax      %d\n",
	     htons(buffer->max_loss));
      printf("\tmin      %d\n",
	     htons(buffer->min_loss));
      printf("\tmean     %f\n",
	     buffer->mean_loss);
      printf("\tvariance %f\n",
	     buffer->variance_loss); 
      break;
    case OF_GNUPLOT_INPUT:
      printf("%f %f\n",
	     buffer->mean_time,
	     1.0-messagesPercentLoss);
      break;
    default:
      printf(" output format not known, this should not happen.\n");
    }
  } else 
    printf("\nDid not receive the message from gnunetd. Is gnunetd running?\n");  
  FREE(buffer);

  releaseClientSocket(sock);
  doneUtil();
  return 0;
}
/* end of gnunet-tbench.c */ 
