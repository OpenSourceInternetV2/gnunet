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
 * @file include/gnunet_core.h
 * @brief The APIs to the GNUnet core. See also core.c.
 * @author Christian Grothoff
 */

#ifndef COREAPI_H
#define COREAPI_H

#include "gnunet_util.h"


/**
 * Just the version number of GNUnet-core API.
 * Encoded as 
 * 0.6.1d  => 0x00060100
 * 4.5.2   => 0x04050200
 * 
 * Note that this version number is only changed if 
 * something changes in the core API.  It follows
 * roughly the main GNUnet version scheme, but is
 * more a compatibility ID.
 */
#define GNUNET_CORE_VERSION 0x00060105


/**
 * Priority for special administrative messages that
 * for example overrules drop-rules.
 */
#define EXTREME_PRIORITY 0xFFFFFF

/**
 * Opaque handle for a session representation on the transport
 * layer side 
 */
typedef struct {
  unsigned short ttype;
  void * internal;
} TSession;

/**
 * A session is a token provided by the transport
 * API to refer to a connection of the transport
 * layer.
 */
typedef struct {
  /**
   * To whom are we connected with this session?
   */
  HostIdentity sender;
  
  /**
   * The transport type for this session.
   */
  unsigned short ttype;

  /**
   * The MTU for this session.
   */
  unsigned short mtu;

  /**
   * Is this session encrypted (send only)?
   */
  int isEncrypted;

  /** 
   * The session handle specific for the transport service.
   */
  TSession * tsession;

} Session;

/**
 * HELO.
 * A HELO body contains the current HostAddress,
 * the host identity (hash), the time how long the
 * HostAddress is valid, a signature signing the
 * information above and the public key of the host.
 * The hash of the public key must match the host
 * identity.<p>
 * The signature goes over the message starting at
 * the HostIdentity and includes the senderAddress.
 * Since the senderAddress may be long, what is 
 * actually signed is the hash of these bytes.
 */
typedef struct {
  p2p_HEADER header;

  /**
   * The signature 
   */
  Signature signature;

  /**
   * The public key 
   */
  PublicKey publicKey; 

  /**
   * Whose identity follows? No, this is NOT a duplicate
   * as a node may send us the identity of ANOTHER node! 
   */
  HostIdentity senderIdentity; 

  /**
   * time this address expires  (network byte order) 
   */ 
  TIME_T expirationTime;

  /**
   * size of the sender address 
   */
  unsigned short senderAddressSize;

  /**
   * protocol supported by the node (only one protocol
   * can be advertised by the same HELO) 
   * Examples are UDP, TCP, etc. This field is
   * in network byte order 
   */
  unsigned short protocol;

  /**
   * advertised MTU for sending (replies can have a different
   * MTU!) 
   */
  unsigned int MTU;

} HELO_Message;

typedef struct {
  HELO_Message helo_message;

  /**
   * address of the node in a protocol specific format 
   */ 
  char senderAddress[1]; 
  
} HELO_Message_GENERIC;  

#define HELO_Message_size(helo) ((sizeof(HELO_Message) + ntohs((helo)->senderAddressSize)))

/**
 * Type of a handler for messages from clients.
 */
typedef int (*CSHandler)(ClientHandle client,
			 const CS_HEADER * message);

/**
 * Type of a struct passed to receive.
 */
typedef struct {
  /**
   * The session associated with the message
   * on the transport layer side. Maybe passed to "associate"
   * in order to send replies on a bi-directional pipe (if
   * possible).
   */
  TSession * tsession;

  /**
   * The identity of the sender node
   */
  HostIdentity sender;

  /**
   * The message itself. The GNUnet core will call 'xfree' once
   * processing of msg is complete. Note that msg can point to
   * multiple p2p_headers.
   */
  p2p_HEADER * msg;

  /**
   * The size of the message
   */
  unsigned int size;
  
  /**
   * YES if the message was encrypted, NO otherwise
   * (LOOPBACK is a special value for messages that are
   * to be treated as encrypted except that they are in plaintext)
   */
  int isEncrypted;

  /**
   * The checksum of the message (over size bytes from msg)
   */
  int crc;
} MessagePack;

#define LOOPBACK 3

/**
 * This header file contains a draft for the gnunetd
 * core API. This API is used by the transport layer
 * for communication with the GNUnet core.
 * 
 * A pointer to an instance of this struct is passed
 * to the init method of each Transport API.
 */
typedef struct {

  /**
   * The version of the CORE API. For now, always "0".
   */
  unsigned int version;

  /**
   * The identity of the local node.
   */
  HostIdentity * myIdentity;

  /**
   * Data was received (potentially encrypted), make
   * the core process it.
   *
   * @param mp the message, freed by the callee once processed!
   */
  void (*receive)(MessagePack * mp);

} CoreAPIForTransport;

typedef void (*ClientExitHandler)(ClientHandle client);

/**
 * Type of a handler for some message type.
 */
typedef int (*MessagePartHandler)(const HostIdentity * sender,
				  const p2p_HEADER * message);

/**
 * Type of a handler for some message type.
 * @param identity the id of the node
 */
typedef void (*PerNodeCallback)(const HostIdentity * identity,
				void * data);

/**
 * Type of a send callback to fill up buffers.
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
typedef int (*BufferFillCallback)(const HostIdentity * receiver,
				  void * position,
				  int padding);

/**
 * Callback that is used to fill in a message into the send buffer.
 * Note that the size of the message was specified when the callback
 * was installed.
 *
 * @param buf pointer to the buffer where to copy the msg to
 * @param closure context argument that was given when the callback was installed
 * @param len the expected number of bytes to write to buf 
 * @return OK on success, SYSERR on error
 */
typedef int (*BuildMessageCallback)(void * buf,
				    void * closure,
				    unsigned short len);

/**
 * Ping message (test if address actually corresponds to
 * the advertised GNUnet host. The receiver responds with
 * exactly the same message, except that it is now a pong.
 * This message can be send in plaintext and without padding
 * and typically does make little sense (except keepalive)
 * for an encrypted (authenticated) tunnel. 
 * <br>
 * There is also no proof that the other side actually
 * has the acclaimed identity, the only thing that is
 * proved is that the other side can be reached via
 * the underlying protocol and that it is a GNUnet node.
 * <br>
 * The challenge prevents an inept adversary from sending
 * us a HELO and then an arbitrary PONG reply (adversary
 * must at least be able to sniff our outbound traffic).
 */
typedef struct {
  p2p_HEADER header;

  /**
   * Which peer is the target of the ping? This is important since for
   * plaintext-pings, we need to catch faulty advertisements that
   * advertise a correct address but with the wrong public key.
   */
  HostIdentity receiver;

  /**
   * The challenge is a (pseudo) random number that an adversary that
   * wants to fake a pong message would have to guess. Since even if
   * the number is guessed, the security impact is at most some wasted
   * resources, 32 bit are more than enough.
   */
  int challenge;
} PINGPONG_Message;

/**
 * GNUnet CORE API for applications and services that are implemented
 * on top of the GNUnet core.
 */
typedef struct {

  /**
   * The version of the CORE API. For now, always "0".
   */
  unsigned int version;

  /**
   * The identity of the local node.
   */
  HostIdentity * myIdentity;


  /**
   * Ping a host an call a method if a reply comes back.
   * @param receiverIdentity the identity to fill into the ping
   * @param method the method to call if a PONG comes back
   * @param data an argument to pass to the method.
   * @param pmsg the ping-message, pingAction just fills it in,
   *        the caller is responsbile for sending it!
   * @returns OK on success, SYSERR on error
   */
  int (*pingAction)(const HostIdentity * receiver,
		    CronJob method,
		    void * data,
		    PINGPONG_Message * pmsg);

  /**
   * Sign a message with the key of the local node.
   * @param message the message to sign
   * @param size the size of the message
   * @param sig where to store the signature
   * @return OK on success, SYSERR on error 
   *  (typically size negative or to large)
   */
  int (*sign)(void * message,
	      unsigned short size,
	      Signature * sig);

  /**
   * @param signer the identity of the host that presumably signed the message
   * @param message the signed message
   * @param size the size of the message
   * @param sig the signature
   * @return OK on success, SYSERR on error (verification failed)
   */
  int (*verifySig)(const HostIdentity * signer,
		   void * message,
		   int size,
		   Signature * sig);

  /**
   * Increase the preference for traffic from some other peer.
   * @param node the identity of the other peer
   * @param preference how much should the traffic preference be increased?
   */
  void (*preferTrafficFrom)(const HostIdentity * node,
			    double preference);

  /**
   * Query how much bandwidth is availabe FROM the given node to
   * this node in bpm (at the moment).
   */
  unsigned int (*queryBPMfromPeer)(const HostIdentity * node);
  
  /**
   * Change our trust in some other node.
   * @param node the identity of the node
   * @param delta by how much to change the trust
   * @return the actual change in trust (trust can not go negative,
   *  so if the existing trust was 6 and delta was -10, then
   *  changeTrust will return -6.
   */
  unsigned int (*changeTrust)(const HostIdentity * node,
			      int delta);

  /**
   * Get the amount of trust that we have in a node.
   */
  unsigned int (*getTrust)(const HostIdentity * node);

  /**
   * Send an encrypted message to another node.
   * @param receiver the target node
   * @param msg the message to send
   * @param importance how important is the message?
   * @param maxdelay how long can the message be delayed?
   */
  void (*sendToNode)(const HostIdentity * receiver,
		     const p2p_HEADER * msg,
		     unsigned int importance,
		     unsigned int maxdelay);
  
  /**
   * Send a message to the client identified by the handle.  Note that
   * the core will typically buffer these messages as much as possible
   * and only return SYSERR if it runs out of buffers.  Returning OK
   * on the other hand does NOT confirm delivery since the actual
   * transfer happens asynchronously.
   */
  SendToClientCallback sendToClient;

  /**
   * Send a message to the client identified by the handle.  Note that
   * the core will typically buffer these messages as much as possible
   * and only return SYSERR if it runs out of buffers.  Returning OK
   * on the other hand does NOT confirm delivery since the actual
   * transfer happens asynchronously.
   */
  int (*sendTCPResultToClient)(ClientHandle handle,
			       int value);

  /**
   * Send an encrypted, on-demand build message to another node.
   * @param receiver the target node
   * @param callback the callback to build the message
   * @param closure the second argument to callback
   * @param len how long is the message going to be?
   * @param importance how important is the message?
   * @param maxdelay how long can the message wait?
   */
  void (*unicast)(const HostIdentity * receiver,
		  BuildMessageCallback callback,
		  void * closure,
		  unsigned short len,
		  unsigned int importance,
		  unsigned int maxdelay);

  /**
   * Perform an operation for all connected hosts.
   * The BufferEntry structure is passed to the method.
   * No synchronization or other checks are performed.
   *
   * @param method the method to invoke (NULL for counting only)
   * @param arg the second argument to the method
   * @return the number of connected hosts
   */ 
  int (*forAllConnectedNodes)(PerNodeCallback method,
			      void * arg);

  /**
   * Send a message to all connected nodes. Note that this is
   * not a network-wide broadcast!
   * @param msg the message to send
   * @param importance how important is the message?
   * @param maxdelay how long can we wait (max), in seconds
   */
  void (*broadcastToConnected)(const p2p_HEADER * msg,
			       unsigned int importance,
			       unsigned int maxdelay);

  /**
   * Register a callback method that should be invoked whenever a message
   * is about to be send that has more than minimumPadding bytes left
   * before maxing out the MTU. 
   * The callback method can then be used to add additional content
   * to the message (instead of the random noise that is added by
   * otherwise). Note that if the MTU is 0 (for streams), the
   * callback method will always be called with padding set to the
   * maximum number of bytes left in the buffer allocated for the
   * send.
   * @param minimumPadding how large must the padding be in order
   *   to call this method?
   * @param callback the method to invoke. The receiver is the
   *   receiver of the message, position is the reference to the
   *   first unused position in the buffer where GNUnet is building
   *   the message, padding is the number of bytes left in that buffer.
   *   The callback method must return the number of bytes written to
   *   that buffer (must be a positive number).
   * @return OK if the handler was registered, SYSERR on error
   */
  int (*registerSendCallback)(const unsigned int minimumPadding,
			      BufferFillCallback callback);
  
  /**
   * Unregister a handler that was registered with registerSendCallback.
   * @return OK if the handler was removed, SYSERR on error
   */
  int (*unregisterSendCallback)(const unsigned int minimumPadding,
				BufferFillCallback callback);

  /**
   * Register a method as a handler for specific message
   * types.
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is already a
   *         handler for that type
   */
  int (*registerClientHandler)(const unsigned short type,
			       CSHandler callback);

  /**
   * Return wheter or not there is a method handler 
   * registered for a specific Client-Server message type.
   * @param the message type
   * @return YES if there is a handler for the type,
   * 	NO if there isn't
   */
  int (*isClientHandlerRegistered)(const unsigned short type);

  /**
   * Remove a method as a handler for specific message
   * types.
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is a different
   *         handler for that type
   */
  int (*unregisterClientHandler)(const unsigned short type,
				 CSHandler callback);

  /**
   * Register a handler to call if any client exits.
   * @param callback a method to call with the socket
   *   of every client that disconnected.
   * @return OK on success, SYSERR on error
   */
  int (*registerClientExitHandler)(ClientExitHandler callback);
  
  /**
   * Unregister a handler to call if any client exits.
   * @param callback a method to call with the socket
   *   of every client that disconnected.
   * @return OK on success, SYSERR on error
   */
  int (*unregisterClientExitHandler)(ClientExitHandler callback);
  
  /**
   * Register a method as a handler for specific message
   * types. Only for encrypted messages!
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is already a
   *         handler for that type
   */
  int (*registerHandler)(const unsigned short type,
			 MessagePartHandler callback);
  

  /**
   * Return wheter or not there is a method handler 
   * registered for a specific message type.
   * @param the message type
   * @return YES if there is a handler for the type,
   * 	NO if there isn't
   */
  int (*isHandlerRegistered)(const unsigned short type);

  /**
   * Unregister a method as a handler for specific message
   * types. Only for encrypted messages!
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is a different
   *         handler for that type
   */
  int (*unregisterHandler)(const unsigned short type,
			   MessagePartHandler callback);
  
  /**
   * Return the estimated size of the network in
   * the number of nodes running at the moment.
   */
  int (*estimateNetworkSize)();

  /**
   * Compute the index (small, positive, pseudo-unique identification
   * number) of a hostId.
   */
  unsigned int (*computeIndex)(const HostIdentity * hostId);

  /**
   * The the lock of the connection module. A module that registers
   * callbacks may need this.
   */
  Mutex * (*getConnectionModuleLock)();

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
  int (*getTrafficStats)(const unsigned short messageType,
			 const int sendReceive,
			 const unsigned int timePeriod,
			 unsigned short * avgMessageSize,
			 unsigned short * messageCount,
			 unsigned int * peerCount,
			 unsigned int * timeDistribution);

  /**
   * Obtain the public key and address of a known host. If no specific
   * protocol is specified (ANY_PROTOCOL_NUMBER), HELOs for cheaper
   * protocols are returned with preference (randomness!).
   *
   * @param hostId the host id
   * @param protocol the protocol that we need,
   *        ANY_PROTOCOL_NUMBER if we do not care which protocol
   * @param tryTemporaryList is it ok to check the unverified HELOs?
   * @param result where to store the result
   * @returns SYSERR on failure, OK on success
   */
  int (*identity2Helo)(const HostIdentity *  hostId,
		       const unsigned short protocol,
		       int tryTemporaryList,
		       HELO_Message ** result);
 
  /**
   * Bind a host addres (helo) to a hostId.
   * @param msg the verified (!) HELO message
   */
  void (*bindAddress)(HELO_Message * msg);

  /**
   * Disconnect a particular peer. Send a HANGUP message to the other side
   * and mark the sessionkey as dead.
   *
   * @param peer  the peer to disconnect
   */
  void (*disconnectFromPeer)(const HostIdentity *peer);

  /**
   * Disconnect all current connected peers. Send HANGUP messages to the other peers
   * and mark the sessionkeys as dead.
   *
   */
  void (*disconnectPeers)();

  /**
   * Load an application module.  This function must be called
   * while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules
   * are loaded or unloaded inside the module initialization or
   * shutdown code.
   *
   * @return OK on success, SYSERR on error
   */
  int (*loadApplicationModule)(const char * name);

  /**
   * Unload an application module.  This function must be called
   * while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules
   * are loaded or unloaded inside the module initialization or
   * shutdown code.
   *
   * @return OK on success, SYSERR on error
   */
  int (*unloadApplicationModule)(const char * name);

  /**
   * Which percentage of inbound messages should gnunetd drop at
   * random (to simulate network unreliability or congestion).
   */
  void (*setPercentRandomInboundDrop)(int value);

  /**
   * Which percentage of outbound messages should gnunetd drop at
   * random (to simulate network unreliability or congestion).
   */
  void (*setPercentRandomOutboundDrop)(int value);

  /**
   * Load a service module of the given name. This function must be
   * called while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules are
   * loaded or unloaded inside the module initialization or shutdown
   * code.
   */
  void * (*requestService)(const char * name);

  /**
   * Notification that the given service is no longer required. This
   * function must be called while cron is suspended.  Note that the
   * initialization and shutdown function of modules are always run
   * while cron is disabled, so suspending cron is not necesary if
   * modules are loaded or unloaded inside the module initialization
   * or shutdown code.
   *
   * @return OK if service was successfully released, SYSERR on error
   */
  int (*releaseService)(void * service);

  /**
   * Terminate the connection with the given client (asynchronous
   * detection of a protocol violation).
   */
  void (*terminateClientConnection)(ClientHandle handle);

} CoreAPIForApplication;

/**
 * Type of the initialization method implemented by GNUnet protocol
 * plugins.
 *
 * @param capi the core API 
 */
typedef int (*ApplicationInitMethod) (CoreAPIForApplication * capi);

/**
 * Type of the shutdown method implemented by GNUnet protocol
 * plugins.
 */
typedef void (*ApplicationDoneMethod)();

/**
 * Type of the initialization method implemented by GNUnet service
 * plugins.
 *
 * @param capi the core API 
 */
typedef void * (*ServiceInitMethod)(CoreAPIForApplication * capi);

/**
 * Type of the shutdown method implemented by GNUnet service
 * plugins.
 */
typedef void (*ServiceDoneMethod)();

#endif
