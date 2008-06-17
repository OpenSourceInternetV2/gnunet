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
 * @file server/traffic.h
 * @author Christian Grothoff
 * 
 * @brief Module to keep track of recent amounts of p2p traffic
 * on the local GNUnet node.
 */
#ifndef TRAFFIC_H
#define TRAFFIC_H

#include "gnunet_core.h"


void updateTrafficSendCounter(unsigned short ptyp,
			      unsigned short plen);

void updateTrafficReceiveCounter(unsigned short ptyp,
				 unsigned short plen);

/**
 * Initialize the traffic module.
 */
void initTraffic();

/**
 * Shutdown the traffic module.
 */
void doneTraffic();

/**
 * A message was received. Update traffic stats.
 * @param header the header of the message
 * @param sender the identity of the sender 
 */
void trafficReceive(const p2p_HEADER * header,
		    const HostIdentity * sender);

/**
 * A message is send. Update traffic stats.
 * @param header the header of the message
 */
void trafficSend(const p2p_HEADER * header,
		 const HostIdentity * receiver);

/**
 * How many time-units back do we keep the history of?  (must really
 * be <=32 since we use the 32 bit in an unsigned int). The memory
 * impact of this value n is 4 * 3 * MAX_MESSAGE_ID * n, which is for
 * the default of n=32 with the current MAX_MESSAGE_ID being roughly a
 * dozen less than 2k.
 */
#define HISTORY_SIZE 32

/**
 * Get statistics over the number of messages that
 * were received or send of a given type.
 *
 * @param messageType the type of the message
 * @param sendReceive TC_SEND for sending, TC_RECEIVE for receiving
 * @param timePeriod how many TRAFFIC_TIME_UNITs to take
 *        into consideration (limited by HISTORY_SIZE)
 * @param avgMessageSize average size of the messages (set)
 * @param messageCount number of messages (set)
 * @param peerCount number of peers engaged (set)
 * @param timeDistribution bit-vector giving times of interactions,
 *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
 * @return OK on success, SYSERR on error
 */
int getTrafficStats(const unsigned short messageType,
		    const int sendReceive,
		    const unsigned int timePeriod,
		    unsigned short * avgMessageSize,
		    unsigned short * messageCount,
		    unsigned int * peerCount,
		    unsigned int * timeDistribution);


#endif
/* end of traffic.h */
