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

#ifndef PINGPONG_H
#define PINGPONG_H

/**
 * @file server/pingpong.h
 * @brief Pings a host and triggers an action if a reply is received.
 * @author Christian Grothoff
 */

/**
 * Initialize the pingpong module.
 */
void initPingPong();

/**
 * Shutdown the pingpong module.
 */
void donePingPong();

/**
 * We received a PING message, send the PONG reply and notify the
 * connection module that the session is still life.
 */	
int plaintextPingReceived(const HostIdentity * sender,
			  TSession * tsession,
			  const p2p_HEADER * msg);

/**
 * Handler for a pong.
 */ 	
int plaintextPongReceived(const HostIdentity * sender,
			  TSession * tsession,
			  const p2p_HEADER * msg);

/**
 * Ping a host an call a method if a reply comes back.
 * @param receiverIdentity the identity to fill into the ping
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @param pmsg the ping-message, pingAction just fills it in,
 *        the caller is responsbile for sending it!
 * @returns OK on success, SYSERR on error
 */
int pingAction(const HostIdentity * receiver,
	       CronJob method,
	       void * data,
	       PINGPONG_Message * pmsg);

#endif
