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
 * @file server/connection.h
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 */ 

#ifndef CONNECTION_H
#define CONNECTION_H

#include "policy.h"

/* ********************* some message types ************** */

/**
 * The body of a sessionkey-message.
 */
typedef struct {
  /**
   * time when this key was created  (network byte order) 
   */ 
  TIME_T creationTime; 

  /**
   * the encrypted session key 
   */ 
  RSAEncryptedData key; 

  /**
   * Signature of the stuff above 
   */
  Signature signature;

} SKEY_Body;

/**
 * Session key exchange.  The header is followed by an inlined SKS.
 */
typedef struct {
  p2p_HEADER header; 
  SKEY_Body body;
} SKEY_Message;

/**
 * Format of a timestamp-message.  The rest of the body is only valid
 * if the timestamp is greater than the current time (in seconds after
 * 1970...).  Used against replay attacks!
 */
typedef struct {
  p2p_HEADER header;
  /* timestamp  (network byte order)*/
  TIME_T timeStamp;
} TIMESTAMP_Message;

/**
 * Sequence number.  If the sequence number is lower than a previous
 * number, the rest of the packet should be ignored (replay).  This
 * will of course break if UDP packets arrive out-of-order, but this
 * is rare and we're best-effort.  This is used to defend against
 * replay-attacks.
 */
typedef struct {
  p2p_HEADER header;
  /* sequence number, in network byte order */
  unsigned int sequenceNumber;
} SEQUENCE_Message;

/**
 * The other side has decided to terminate the connection.  This
 * message MAY be send if the other node decides to be nice.  It is
 * not required.  Mind that the message contains for which host the
 * termination is, such that we don't hang up the wrong connection...
 * A node can also choose to ignore the HANGUP message, though this is
 * probably not going to help that node.  This message is used to
 * prevent sending data to connections that were closed on the other
 * side (can happen anyway, so this is just an optimization between
 * well-behaved, non-malicious nodes that like each other).
 */
typedef struct {
  p2p_HEADER header;
  HostIdentity sender;
} HANGUP_Message;

/**
 * Capability specification.
 */
typedef struct {
  unsigned int capabilityType;
  unsigned int value;
} Capability;

/**
 * Limit number of bytes send to this peer per minute to "value".
 */
#define CAP_BANDWIDTH_RECV 0

/**
 * This message is used to advertise node capabilities.  Each
 * capability has a capability type and a value.  The primary
 * motivation for the introducation of capabilities is
 * CAP_BANDWIDTH_RECV which can be used by a peer to specify a maximum
 * amount of data that it is currently (!) willing to receive and
 * process from another peer.  After receiving a capability message
 * the other peer is expected to only send requests to the sender that
 * match the capabilities.<p>
 *
 * If a peer does not understand a given capability type, the message
 * is to be ignored.  Future capabilities that are currently planned
 * include an advertisment that specifies the set of application
 * services that are (not) supported. 
 */ 
typedef struct {
  p2p_HEADER header;
  Capability cap;
} CAPABILITY_Message;


/* ********************* Methods called from "node" ********************** */

/**
 * Initialize this module.
 */
void initConnection();

/**
 * Shutdown the connection module.
 */
void doneConnection();

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
void cronScanDirectoryDataHosts(void * unused);

/**
 * For debugging.
 */
void printConnectionBuffer();

/**
 * Accept a session-key that has been sent by another host.  The other
 * host must be known (public key).
 *
 * @param hostId the identity of the sender host
 * @param sessionkeySigned the session key that was "negotiated"
 */
int acceptSessionKey(const HostIdentity * sender,
		     TSession * tsession,
		     const p2p_HEADER * msg);

/**
 * Are we connected to this host?
 */
int isConnected(const HostIdentity * hi);

/**
 * Shutdown all connections (send HANGUPs, too).
 */
void closeAllConnections();

/**
 * How important is it at the moment to establish more connections?
 */
int getConnectPriority();
 
/**
 * Increase the host credit by a value - synchronized
 * @param hostId is the identity of the host
 * @param value is the int value by which the host credit is to be increased
 * @returns the new credit
 */
unsigned int changeHostCredit(const HostIdentity * hostId, 
			      int value);

/**
 * Call method for every connected node.
 */
int forEachConnectedNode(PerNodeCallback method,
			 void * arg);

/**
 * Obtain the credit record of the host.
 */
unsigned int getHostCredit(const HostIdentity * hostId);


/* ********************** Send-interface ****************************** */

/**
 * Compute the hashtable index of a host id.
 */
unsigned int computeIndex(const HostIdentity * hostId);


/**
 * Consider switching the transport mechanism used for contacting the
 * given node.  This function is called when the handler handles an
 * encrypted connection.  For example, if we are sending SMTP messages
 * to a node behind a NAT box, but that node has established a TCP
 * connection to us, it might just be better to send replies on that
 * TCP connection instead of keeping SMTP going.
 *
 * @param tsession the transport session that is for grabs
 * @param sender the identity of the other node
 */
void considerTakeover(TSession * tsession,
		      const HostIdentity * sender);

/**
 * Register a callback method that should be invoked whenever a
 * message is about to be send that has more than minimumPadding bytes
 * left before maxing out the MTU. The callback method can then be
 * used to add additional content to the message (instead of the
 * random noise that is added by otherwise).  Note that if the MTU is
 * 0 (for streams), the callback method will always be called with
 * padding set to the maximum number of bytes left in the buffer
 * allocated for the send.
 *
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
int registerSendCallback(const unsigned int minimumPadding,
			 BufferFillCallback callback);

/**
 * Unregister a handler that was registered with registerSendCallback.
 * @return OK if the handler was removed, SYSERR on error
 */
int unregisterSendCallback(const unsigned int minimumPadding,
			   BufferFillCallback callback);

/**
 * Send a message to all directly connected nodes.
 *
 * @param message the message to send
 * @param priority how important is the message? The higher, the more important
 * @param maxdelay how long can we wait (max), in CRON-time (ms)
 */
void broadcast(const p2p_HEADER * message,
	       unsigned int priority,
	       unsigned int maxdelay);

/**
 * Send a message to a specific host (reply, enqueue).  This method
 * may only be called by a thread that either holds no locks at all or
 * at most the lock returned by <tt>getConnectionModuleLock</tt>.
 *
 * @param message the message to send (unencrypted!)
 * @param hostId the identity of the receiver
 * @param priority how important is the message?
 * @param maxdelay how long can we wait (max), in CRON-time (ms)
 */
void sendToNode(const HostIdentity * hostId,
		const p2p_HEADER * message,
		unsigned int priority,
		unsigned int maxdelay);

/**
 * Send an encrypted, on-demand build message to another node.
 * @param receiver the target node
 * @param callback the callback to build the message
 * @param closure the second argument to callback
 * @param len how long is the message going to be?
 * @param importance how important is the message?
 * @param maxdelay how long can the message wait?
 */
void unicast(const HostIdentity * hostId,
	     BuildMessageCallback callback,
	     void * closure,
	     unsigned short len,
	     unsigned int importance,
	     unsigned int maxdelay);

/**
 * Return a pointer to the lock of the connection module.
 */ 
Mutex * getConnectionModuleLock();

/**
 * Shutdown all connections with other peers.
 */
void shutdownConnections();

/* ************************* encryption service ********************** */

/**
 * Decipher data comming in from a foreign host.
 * @param data the data to decrypt
 * @param size how big is data?
 * @param hostId the sender host that encrypted the data 
 * @param result where to store the decrypted data
 * @returns the size of the decrypted data, SYSERR on error
 */
int decryptFromHost(const void * data,
		    const unsigned short size,
		    const HostIdentity * hostId,
		    void * result);  

/* **************** ping pong notification (keepalive) *************** */

/**
 * We received a sign of life from this host.
 */
void notifyPING(const HostIdentity * hostId);

/**
 * We received a sign of life from this host.
 */
void notifyPONG(const HostIdentity * hostId);


/* ******************** traffic management ********** */

/**
 * How many bpm did we assign this peer (how much traffic
 * may the given peer send to us per minute?)
 */
unsigned int getBandwidthAssignedTo(const HostIdentity * hostId);

/**
 * Notification for per-connection bandwidth tracking:
 * we received size bytes from hostId.  Note that only
 * encrypted messages are counted as "real" traffic.
 *
 * @param hostId the peer that send the message
 * @param size the size of the message
 */
void trafficReceivedFrom(const HostIdentity * hostId,
			 const unsigned int size);

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void updateTrafficPreference(const HostIdentity * node,
			     double preference);


/**
 * Disconnect a particular peer. Send a HANGUP message to the other side
 * and mark the sessionkey as dead.
 *
 * @param peer  the peer to disconnect
 */
void disconnectFromPeer(const HostIdentity *node);


/**
 * Disconnect all current connected peers. Send HANGUP messages to 
 * the other peers and mark the sessionkeys as dead.
 */
void disconnectPeers();


#endif
/* end of connection.h */
