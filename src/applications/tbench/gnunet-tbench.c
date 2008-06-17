/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @author Paul Ruth, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "tbench.h"

#define DEFAULT_MESSAGE_SIZE  10
#define DEFAULT_TIMEOUT  	(2 * GNUNET_CRON_SECONDS)
#define DEFAULT_SPACING  	0

#define OF_HUMAN_READABLE 0
#define OF_GNUPLOT_INPUT 1

static unsigned long long messageSize = DEFAULT_MESSAGE_SIZE;

static unsigned long long messageCnt = 1;

static char *messageReceiver;

static unsigned long long messageIterations = 1;

static unsigned long long messageTrainSize = 1;

static GNUNET_CronTime messageTimeOut = DEFAULT_TIMEOUT;

static GNUNET_CronTime messageSpacing = DEFAULT_SPACING;

static int outputFormat = OF_HUMAN_READABLE;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

/**
 * All gnunet-tbench command line options
 */
static struct GNUNET_CommandLineOption gnunettbenchOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Start GNUnet transport benchmarking tool.")), /* -h */
  {'g', "gnuplot", NULL,
   gettext_noop ("output in gnuplot format"), 0,
   &GNUNET_getopt_configure_set_one, &outputFormat},
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  {'i', "iterations", "ITER",
   gettext_noop ("number of iterations"), 1,
   &GNUNET_getopt_configure_set_ulong, &messageIterations},
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'n', "msg", "MESSAGES",
   gettext_noop ("number of messages to use per iteration"), 1,
   &GNUNET_getopt_configure_set_ulong, &messageCnt},
  {'r', "rec", "RECEIVER",
   gettext_noop ("receiver host identifier (ENC file name)"), 1,
   &GNUNET_getopt_configure_set_string, &messageReceiver},
  {'s', "size", "SIZE",
   gettext_noop ("message size"), 1,
   &GNUNET_getopt_configure_set_ulong, &messageSize},
  {'S', "space", "SPACE",
   gettext_noop ("sleep for SPACE ms after each a message block"), 1,
   &GNUNET_getopt_configure_set_ulong, &messageSpacing},
  {'t', "timeout", "TIMEOUT",
   gettext_noop ("time to wait for the completion of an iteration (in ms)"),
   1,
   &GNUNET_getopt_configure_set_ulong, &messageTimeOut},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'X', "xspace", "COUNT",
   gettext_noop ("number of messages in a message block"), 1,
   &GNUNET_getopt_configure_set_ulong, &messageTrainSize},
  GNUNET_COMMAND_LINE_OPTION_END,
};


/**
 * Tool to benchmark the performance of the P2P transports.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunetsearch: 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_ClientServerConnection *sock;
  CS_tbench_request_MESSAGE msg;
  CS_tbench_reply_MESSAGE *buffer;
  float messagesPercentLoss;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  int res;

  res = GNUNET_init (argc,
                     argv,
                     "gnunet-tbench",
                     &cfgFilename, gnunettbenchOptions, &ectx, &cfg);
  if (res == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }

  msg.header.size = htons (sizeof (CS_tbench_request_MESSAGE));
  msg.header.type = htons (GNUNET_CS_PROTO_TBENCH_REQUEST);
  msg.msgSize = htonl (messageSize);
  msg.msgCnt = htonl (messageCnt);
  msg.iterations = htonl (messageIterations);
  msg.intPktSpace = GNUNET_htonll (messageSpacing);
  msg.trainSize = htonl (messageTrainSize);
  msg.timeOut = GNUNET_htonll (messageTimeOut);
  msg.priority = htonl (5);
  if (messageReceiver == NULL)
    {
      fprintf (stderr, _("You must specify a receiver!\n"));
      GNUNET_client_connection_destroy (sock);
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  if (GNUNET_OK !=
      GNUNET_enc_to_hash (messageReceiver, &msg.receiverId.hashPubKey))
    {
      fprintf (stderr,
               _
               ("Invalid receiver peer ID specified (`%s' is not valid name).\n"),
               messageReceiver);
      GNUNET_free (messageReceiver);
      GNUNET_client_connection_destroy (sock);
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  GNUNET_free (messageReceiver);

  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &msg.header))
    {
      GNUNET_client_connection_destroy (sock);
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  buffer = NULL;
  if (GNUNET_OK ==
      GNUNET_client_connection_read (sock,
                                     (GNUNET_MessageHeader **) & buffer))
    {
      GNUNET_GE_ASSERT (ectx,
                        ntohs (buffer->header.size) ==
                        sizeof (CS_tbench_reply_MESSAGE));
      if ((float) buffer->mean_loss < 0)
        {
          GNUNET_GE_BREAK (ectx, 0);
          messagesPercentLoss = 0.0;
        }
      else
        {
          messagesPercentLoss =
            (buffer->mean_loss / ((float) htons (msg.msgCnt)));
        }
      switch (outputFormat)
        {
        case OF_HUMAN_READABLE:
          printf (_("Time:\n"));
          PRINTF (_("\tmax      %llums\n"), GNUNET_ntohll (buffer->max_time));
          PRINTF (_("\tmin      %llums\n"), GNUNET_ntohll (buffer->min_time));
          printf (_("\tmean     %8.4fms\n"), buffer->mean_time);
          printf (_("\tvariance %8.4fms\n"), buffer->variance_time);

          printf (_("Loss:\n"));
          printf (_("\tmax      %u\n"), ntohl (buffer->max_loss));
          printf (_("\tmin      %u\n"), ntohl (buffer->min_loss));
          printf (_("\tmean     %8.4f\n"), buffer->mean_loss);
          printf (_("\tvariance %8.4f\n"), buffer->variance_loss);
          break;
        case OF_GNUPLOT_INPUT:
          printf ("%f %f\n", buffer->mean_time, 1.0 - messagesPercentLoss);
          break;
        default:
          printf (_("Output format not known, this should not happen.\n"));
        }
      GNUNET_free (buffer);
    }
  else
    printf (_
            ("\nDid not receive the message from gnunetd. Is gnunetd running?\n"));

  GNUNET_client_connection_destroy (sock);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-tbench.c */
