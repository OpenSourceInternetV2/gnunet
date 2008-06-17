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
 * @file server/handler.h
 * @brief Main handler for incoming packets.
 * @author Christian Grothoff
 **/

#ifndef HANDLER_H
#define HANDLER_H

#include "gnunet_util.h"
#include "connection.h"

/**
 * Initialize message handling module.
 **/
void initHandler();

/**
 * Shutdown message handling module.
 **/
void doneHandler();

/**
 * The actual main method of GNUnet: message dispatch/handling.
 * @param msg the message that was received. Caller frees it on return
 **/
void handleMessage(TSession * session,
		   HostIdentity * sender,
		   void * msg,
		   const unsigned int size,
		   int isEncrypted,
		   const int crc);

void setPercentRandomInboundDrop(int value);
 
/**
 * Register a method as a handler for specific message
 * types. 
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is already a
 *         handler for that type
 **/
int registerp2pHandler(const unsigned short type,
		       MessagePartHandler callback); 
/**
 * Return wheter or not there is a method handler 
 * registered for a specific p2p message type.
 * @param the message type
 * @return YES if there is a handler for the type,
 * 	NO if there isn't
 **/
int isp2pHandlerRegistered(const unsigned short type);

/**
 * Unregister a method as a handler for specific message
 * types. Only for encrypted messages!
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *         handler for that type
 **/
int unregisterp2pHandler(const unsigned short type,
			 MessagePartHandler callback);

/**
 * Handle a request to see if a particular p2p message 
 * is supported.
 **/
int handlep2pMessageSupported(ClientHandle sock,
			      CS_HEADER * message);


#endif
/* end of handler.h */
