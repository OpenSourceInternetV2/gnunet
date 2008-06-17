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
 * @file applications/tracekit/tracekit.h
 * @author Christian Grothoff
 */

#ifndef TRACEKIT_H
#define TRACEKIT_H

#include "gnunet_core.h"

typedef struct {
  P2P_MESSAGE_HEADER header;

  /**
   * When was this probe started? (NBO)
   */
  TIME_T timestamp;

  /**
   * How many more hops should this probe go (NBO)
   */
  unsigned int hopsToGo;

  /**
   * How important is the probe for the sender? (NBO)
   */
  unsigned int priority;

  /**
   * Internal client id of the sender.
   */
  unsigned int clientId;

  /**
   * Which peer is the ultimate receiver of this
   * information?
   */
  PeerIdentity initiatorId;

} P2P_tracekit_probe_MESSAGE;

typedef struct {
  P2P_MESSAGE_HEADER header;

  /**
   * Which peer is the ultimate receiver of this
   * information?
   */
  PeerIdentity initiatorId;

  /**
   * Which peer is the ultimate responder responsible
   * for sending this reply?
   */
  PeerIdentity responderId;

  /**
   * At what time was the initator sending the
   * request?
   */
  TIME_T initiatorTimestamp;

  /**
   * Internal client Id of the sender.
   */
  unsigned int clientId;

} P2P_tracekit_reply_MESSAGE;

typedef struct {
  P2P_tracekit_reply_MESSAGE p2p_reply;

  /**
   * List of peers that the responder is
   * currently connected to.
   */
  PeerIdentity peerList[1];
} P2P_tracekit_reply_MESSAGE_GENERIC;


typedef struct {
  CS_MESSAGE_HEADER header;

  /**
   * How many more hops should this probe go (NBO)
   */
  unsigned int hops;

  /**
   * How important is the probe for the sender? (NBO)
   */
  unsigned int priority;
} CS_tracekit_probe_MESSAGE;

typedef struct {
  CS_MESSAGE_HEADER header;

  /**
   * Which peer is the ultimate responder responsible
   * for sending this reply?
   */
  PeerIdentity responderId;

} CS_tracekit_reply_MESSAGE;

typedef struct {
  CS_tracekit_reply_MESSAGE cs_reply;

  /**
   * List of peers that the responder is
   * currently connected to.
   */
  PeerIdentity peerList[1];
} CS_tracekit_reply_MESSAGE_GENERIC;

#endif
