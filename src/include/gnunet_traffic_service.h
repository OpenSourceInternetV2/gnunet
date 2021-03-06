/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_traffic_service.h
 * @author Christian Grothoff
 *
 * @brief Module to keep track of recent amounts of p2p traffic
 * on the local GNUnet node.
 */
#ifndef GNUNET_TRAFFIC_SERVICE_H
#define GNUNET_TRAFFIC_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * This type is for messages that we send.
 */
#define GNUNET_TRAFFIC_TYPE_SENT      0x8000

/**
 * This type is for messages that we receive.
 */
#define GNUNET_TRAFFIC_TYPE_RECEIVED  0x4000

#define GNUNET_TRAFFIC_TYPE_MASK (GNUNET_TRAFFIC_TYPE_RECEIVED|GNUNET_TRAFFIC_TYPE_SENT)

/**
 * From/To how many different peers did we receive/send
 * messages of this type? (bitmask)
 */
#define GNUNET_TRAFFIC_DIVERSITY_MASK 0xFFF

/**
 * What is the unit of time (in GNUNET_CronTime) for the traffic module? This
 * constant essentially specifies the resolution of the distribution
 * function that is applied for sampling traffic. Default is 1s.
 */
#define GNUNET_TRAFFIC_TIME_UNIT GNUNET_CRON_SECONDS

/**
 * @brief API to the traffic service.
 *
 * The traffic service records how much traffic of which
 * type has recently been transmitted or received by this
 * peer.
 */
typedef struct
{

  /**
   * Get statistics over the number of messages that
   * were received or send of a given type.
   *
   * @param timeframe what time interval should be considered
   * @param type what type of message do we care about?
   * @param direction GNUNET_TRAFFIC_TYPE_RECEIVED of TC_SEND?
   * @param msgCount set to number of messages
   * @param avg_size set to average size
   * @param peerCount set to number of peers involved
   * @param time set to the time distribution
   *        bit-vector giving times of interactions,
   *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*get) (unsigned int timeframe,
              unsigned short type,
              unsigned short direction,
              unsigned int *msgCount,
              unsigned int *peerCount,
              unsigned int *avg_size, unsigned int *time);

} GNUNET_Traffic_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* end of gnunet_traffic_service.h */
