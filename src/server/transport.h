/*
     This file is part of GNUnet

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
 * The APIs for GNUnet transport layer implementations.
 * @file server/transport.h
 * @author Christian Grothoff
 **/

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "gnunet_transport.h"
#include "platform.h"

/**
 * Initialize the transport layer.
 **/
void initTransports();

/**
 * Actually start the transport services and begin
 * receiving messages.
 **/
void startTransports();

/**
 * Stop the transport services, stop receiving messages.
 **/
void stopTransports();

/**
 * Shutdown the transport layer.
 **/
void doneTransports();

/**
 * Convert HELO to string.
 **/
char * heloToString(HELO_Message * helo);

void setPercentRandomOutboundDrop(int value);

/**
 * Is this transport mechanism available (for sending)?
 * @return YES or NO
 **/
int isTransportAvailable(unsigned short ttype);

/**
 * Add an implementation of a transport protocol.
 **/
int addTransport(TransportAPI * tapi);

/**
 * Type of the per-transport callback method.
 **/ 
typedef void (*TransportCallback)(TransportAPI * tapi, 
				  void * data);

/**
 * Iterate over all available transport mechanisms.
 * @param callback the method to call on each transport API implementation
 * @param data second argument to callback
 **/
void forEachTransport(TransportCallback callback,
		      void * data);

/**
 * Connect to a remote host using the advertised
 * transport layer. This may fail if the appropriate
 * transport mechanism is not available.
 *
 * @param helo the HELO of the target node. The
 *        callee is responsible for freeing the HELO (!)
 * @param tsession the transport session to create
 * @return OK on success, SYSERR on error
 **/
int transportConnect(HELO_Message * helo,
		     TSession ** tsession);


/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case, use disconnect afterwards.
 * 
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 **/
int transportAssociate(TSession * tsession);

/**
 * Get the cost of a message in for the given transport mechanism.
 **/
unsigned int transportGetCost(int ttype);

/**
 * Create signed HELO for this transport and put it into
 * the cache tapi->helo.
 **/
void createSignedHELO(TransportAPI * tapi);

/**
 * Send a message.  Drop if the operation would block.
 *
 * @param session the session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC of the (plaintext) message
 * @return OK on success, SYSERR on error
 **/
int transportSend(TSession * session,
		  void * msg,
		  const unsigned int size,
		  int isEncrypted,
		  const int crc);

/**
 * Send a message.  
 * Try to be more reliable than the usual transportSend.
 *
 * @param session the session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC of the (plaintext) message
 * @return OK on success, SYSERR on error
 **/
int transportSendReliable(TSession * session,
			  void * msg,
			  const unsigned int size,
			  int isEncrypted,
			  const int crc);

/**
 * Close the session with the remote node. May only be called on
 * either connected or associated sessions.
 *
 * @return OK on success, SYSERR on error
 **/ 
int transportDisconnect(TSession * session);

/**
 * Verify that a HELO is ok. Call a method
 * if the verification was successful.
 * @return OK if the attempt to verify is on the way,
 *        SYSERR if the transport mechanism is not supported
 **/
int transportVerifyHelo(HELO_Message * helo);

/**
 * Get the MTU for a given transport type.
 **/
int transportGetMTU(unsigned short ttype);

/**
 * Create a HELO advertisement for the given
 * transport type for this node.
 **/
int transportCreateHELO(unsigned short ttype,
			HELO_Message ** helo);

/**
 * Get a message consisting of (if possible) all addresses that this
 * node is currently advertising.  This method is used to send out
 * possible ways to contact this node when sending a (plaintext) PING
 * during node discovery. Note that if we have many transport
 * implementations, it may not be possible to advertise all of our
 * addresses in one message, thus the caller can bound the size of the
 * advertisements.
 *
 * @param maxLen the maximum size of the HELO message collection in bytes
 * @param buff where to write the HELO messages
 * @return the number of bytes written to buff, -1 on error
 **/
int getAdvertisedHELOs(int maxLen,
		       char * buff);
		       

/* end of transport.h */
#endif
