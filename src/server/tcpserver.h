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
 * @file server/tcpserver.h
 * @brief TCP server (gnunetd-client communication).
 * @author Christian Grothoff
 **/

#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "gnunet_util.h"
#include "keyservice.h"


/**
 * Initialize the TCP port and listen for incoming client connections.
 * @return OK on success, SYSERR on error
 **/
int initTCPServer();

/**
 * Stop the server (but do not yet destroy the data structures)
 **/
int stopTCPServer();

/**
 * Shutdown the module.
 * @return OK on success, SYSERR on error
 **/ 
int doneTCPServer();

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
int registerCSHandler(const unsigned short type,
		      CSHandler callback);

/**
 * Return wheter or not there is a method handler 
 * registered for a specific Client-Server message type.
 * @param the message type
 * @return YES if there is a handler for the type,
 * 	NO if there isn't
 **/
int isCSHandlerRegistered(const unsigned short type);
  
/**
 * Unregister a method as a handler for specific message
 * types. 
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is no or another
 *         handler for that type
 **/
int unregisterCSHandler(const unsigned short type,
			CSHandler callback);

int registerClientExitHandler(ClientExitHandler callback);

int unregisterClientExitHandler(ClientExitHandler callback);

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return SYSERR if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
int sendToClient(ClientHandle handle,
		 CS_HEADER * message);


/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 **/
int sendTCPResultToClient(ClientHandle sock,
			  int ret);

#endif
/* end of tcpserver.h */
