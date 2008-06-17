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
 * @file include/gnunet_transport.h
 * @brief The APIs for GNUnet transport layer implementations.
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRANSPORT_H
#define GNUNET_TRANSPORT_H

#include "gnunet_core.h"


/**
 * Just the version number of GNUnet-transport implementation.
 * Encoded as 
 * 0.6.1d  => 0x00060100
 * 4.5.2   => 0x04050200
 * 
 * Note that this version number is only changed if 
 * something changes in the transport API.  It follows
 * roughly the main GNUnet version scheme, but is
 * more a compatibility ID.
 */
#define GNUNET_TRANSPORT_VERSION 0x00060105


/**
 * This header file contains a list of the methods that every
 * transport layer implementation must provide. The basic idea is that
 * gnunetd calls "inittransport_XXX" on every transport-api, passing a
 * struct with gnunetd core services to the transport api, and getting
 * a struct with services provided by the transport api back (or null
 * on error). The return value of init is of type TransportAPI.
 *
 * Example:
 *
 * TransportAPI * inittransport_XXX(CoreTransportAPI * api) {
 *   if (api->version != 0)
 *     return NULL;
 *   // ...
 *   return myApi;
 * }
 *
 * The type of inittransport_XXX is TransportMainMethod.
 */
typedef struct {

  /**
   * This field is used by the core internally;
   * the transport should never do ANYTHING
   * with it.
   */
  void * libHandle;

  /**
   * The name of the transport, set by the
   * core. Read only for the service itself!
   */ 
  char * transName;

  /**
   * This field holds a cached HELO for this
   * transport. HELOs must be signed with RSA,
   * so caching the result for a while is a good
   * idea.  The field is updated by a cron job
   * periodically.
   */
  HELO_Message * helo;

  /**
   * The number of the protocol that is supported by this transport
   * API (i.e. 6 tcp, 17 udp, 80 http, 25 smtp, etc.)
   */
  unsigned short protocolNumber;

  /**
   * The MTU for the protocol (e.g. 1472 for UDP).
   * Can be up to 65535 for stream-oriented transport
   * protocols)
   */
  unsigned short mtu;

  /**
   * How costly is this transport protocol (compared to the other
   * transports, UDP and TCP are scaled to be both 100). The cost is
   * used by GNUnet to select the most preferable mode of
   * transportation.
   */
  unsigned int cost;

  /**
   * Verify that a HELO-Message is correct (a node
   * is potentially reachable at that address). Core
   * will only play ping pong after this verification passed.
   * @param helo the HELO message to verify
   *        (the signature/crc have been verified before)
   * @return OK if the helo is well-formed
   */
  int (*verifyHelo)(const HELO_Message * helo);
  
  /**
   * Create a HELO-Message for the current node. The HELO is
   * created without signature, timestamp, senderIdentity
   * or publicKey. The GNUnet core will sign the message 
   * and add these other fields. The callee is only
   * responsible for filling in the protocol number, 
   * senderAddressSize and the senderAddress itself.
   *
   * @param helo address where to store the pointer to the HELO
   *        message
   * @return OK on success, SYSERR on error (e.g. send-only
   *  transports return SYSERR here)
   */
  int (*createHELO)(HELO_Message ** helo);

  /**
   * Establish a connection to a remote node.
   *
   * @param helo the HELO-Message for the target node
   * @param tsession the session handle that is to be set
   * @return OK on success, SYSERR if the operation failed
   */
  int (*connect)(HELO_Message * helo,
		 TSession ** tsession);

  /**
   * Send a message to the specified remote node.
   * @param tsession an opaque session handle (e.g. a socket
   *        or the HELO_message from connect)
   * @param msg the message
   * @param size the size of the message, <= mtu
   * @return SYSERR on error, OK on success; after any error,
   *         the caller must call "disconnect" and not continue
   *         using the session afterwards (useful if the other
   *         side closed the connection).
   */
  int (*send)(TSession * tsession,
	      const void * msg,
	      const unsigned int size,
	      int isEncrypted,
	      const int crc);

  /**
   * Send a message to the specified remote node with 
   * increased reliablility (whatever that means is
   * up to the transport).
   *
   * @param tsession an opaque session handle (e.g. a socket
   *        or the HELO_message from connect)
   * @param msg the message
   * @param size the size of the message, <= mtu
   * @return SYSERR on error, OK on success; after any error,
   *         the caller must call "disconnect" and not continue
   *         using the session afterwards (useful if the other
   *         side closed the connection).
   */
  int (*sendReliable)(TSession * tsession,
		      const void * msg,
		      const unsigned int size,
		      int isEncrypted,
		      const int crc);

  /**
   * A (core) Session is to be associated with a transport session. The
   * transport service may want to know in order to call back on the
   * core if the connection is being closed. Associate can also be
   * called to test if it would be possible to associate the session
   * later, in this case, call disconnect afterwards. This can be used
   * to test if the connection must be closed by the core or if the core
   * can assume that it is going to be self-managed (if associate
   * returns OK and session was NULL, the transport layer is responsible
   * for eventually freeing resources associated with the tesession). If
   * session is not NULL, the core takes responsbility for eventually
   * calling disconnect.
   * 
   * @param tsession the session handle passed along
   *   from the call to receive that was made by the transport
   *   layer
   * @return OK if the session could be associated,
   *         SYSERR if not.
   */
  int (*associate)(TSession * tsession);

  /**
   * Disconnect from a remote node. A session can be closed
   * by either the transport layer calling "closeSession" on
   * the core API or by the core API calling "disconnect"
   * on the transport API. Neither closeSession nor
   * disconnect should call the other method. Due to 
   * potentially concurrent actions (both sides close the
   * connection simultaneously), either API must tolerate
   * being called from the other side.
   *
   * @param tsession the session that is to be closed
   * @return OK on success, SYSERR if the operation failed
   */
  int (*disconnect)(TSession * tsession);  

  /**
   * Start the server process to receive inbound traffic.
   * @return OK on success, SYSERR if the operation failed
   */
  int (*startTransportServer)(void);

  /**
   * Shutdown the server process (stop receiving inbound
   * traffic). Maybe restarted later!
   */
  int (*stopTransportServer)(void);

  /**
   * Reload the configuration. Should never fail (keep old
   * configuration on error, syslog errors!)
   */
  void (*reloadConfiguration)(void);

  /**
   * Convert transport address to human readable string.
   */
  char * (*addressToString)(const HELO_Message * helo);

} TransportAPI;

/**
 * This header file contains a draft of the methods that every
 * transport layer implementation should implement. The basic idea is
 * that gnunetd calls "inittransport_XXX" on every transport-api, passing a struct
 * with gnunetd core services to the transport api, and getting a
 * struct with services provided by the transport api back (or null
 * on error). The return value of init is of type TransportAPI.
 *q
 * Example:
 *
 * TransportAPI * inittransport_XXX(CoreTransportAPI * api) {
 *   if (api->version != 0)
 *     return NULL;
 *   // ...
 *   return myApi;
 * }
 *
 * The type of inittransport_XXX is TransportMainMethod.
 */
typedef TransportAPI * (*TransportMainMethod)(CoreAPIForTransport *);


/* end of transport.h */
#endif
