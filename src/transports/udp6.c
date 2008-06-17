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
 * @file transports/udp6.c
 * @brief Implementation of the UDP transport service over IPv6
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_transport.h"
#include "platform.h"

#define DEBUG_UDP6 NO

/**
 * Host-Address in a UDP6 network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order 
   */  
  IP6addr senderIP;

  /**
   * claimed port of the sender, network byte order 
   */
  unsigned short senderPort; 

  /**
   * reserved (set to 0 for signature verification) 
   */
  unsigned short reserved; 

} Host6Address;

/**
 * Message-Packet header. 
 */
typedef struct {
  /**
   * this struct is *preceded* by MESSAGE_PARTs - until
   * size-sizeof(UDP6Message)!
   */ 

  /** 
   * size of the message, in bytes, including this header; max
   * 65536-header (network byte order)
   */
  unsigned short size;

  /**
   * Is the message encrypted? 
   */
  unsigned short isEncrypted;

  /**
   * CRC checksum of the plaintext  (network byte order)
   */ 
  int checkSum;

  /**
   * What is the identity of the sender (hash of public key) 
   */
  HostIdentity sender;

} UDP6Message;

/* *********** globals ************* */

/* apis (our advertised API and the core api ) */
static CoreAPIForTransport * coreAPI;
static TransportAPI udp6API;

/**
 * thread that listens for inbound messages 
 */
static PTHREAD_T dispatchThread;

/**
 * the socket that we receive all data from 
 */
static int udp6_sock;

/**
 * Statistics handles.
 */
static int stat_octets_total_udp6_in;
static int stat_octets_total_udp6_out;

/**
 * Semaphore for communication with the
 * udp6 server thread.
 */
static Semaphore * serverSignal;
static int udp6_shutdown = YES;

/**
 * configuration 
 */
static CIDR6Network * filteredNetworks_ = NULL;
static Mutex configLock;

/**
 * Get the GNUnet UDP6 port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short getGNUnetUDP6Port() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("UDP6",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("gnunet", "udp6"))) 
      port = ntohs(pse->s_port);      
    else 
      errexit(_("Cannot determine port to bind to. "
		" Define in configuration file in section '%s' under '%s' "
		"or in '%s' under %s/%s.\n"),
	      "UDP6", 
	      "PORT",
	      "/etc/services",
	      "udp6",
	      "gnunet");
  }
  return port;
}

/**
 * Allocate and bind a server socket for the UDP6 transport.
 */
static int passivesock(unsigned short port) {
  struct sockaddr_in6 sin;
  int sock;
  const int on = 1;

  sock = SOCKET(PF_INET6, 
		SOCK_DGRAM, 
		UDP_PROTOCOL_NUMBER);
  if (sock < 0) 
    DIE_STRERROR("socket");
  if ( SETSOCKOPT(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
    DIE_STRERROR("setsockopt");
  if (port != 0) {
    memset(&sin, 0, sizeof(sin)); 
    sin.sin6_family = AF_INET6;
    sin.sin6_port   = htons(port);
    memcpy(&sin.sin6_addr,
	   &in6addr_any,
	   sizeof(IP6addr));
    if (BIND(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      LOG_STRERROR(LOG_FATAL, "bind");
      errexit(_("Failed to bind to UDP6 port %d.\n"),
	      port);
    }
  } /* do not bind if port == 0, then we use
       send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int isBlacklisted(IP6addr * ip) {
  int ret;

  MUTEX_LOCK(&configLock);
  ret = checkIP6Listed(filteredNetworks_,
		       ip);
  MUTEX_UNLOCK(&configLock);
  return ret;
}

/**
 * Listen on the given socket and distribute the packets to the UDP6
 * handler.
 */
static void * listenAndDistribute() {
  struct sockaddr_in6 incoming;
  socklen_t addrlen = sizeof(incoming);  
  int size;
  EncName enc;
  MessagePack * mp;
  UDP6Message udp6m;
#if DEBUG_UDP6
  char * tmp;
#endif

  SEMAPHORE_UP(serverSignal);
  while (udp6_shutdown == NO) {
    mp = MALLOC(sizeof(MessagePack));
    mp->msg = MALLOC(udp6API.mtu + sizeof(UDP6Message));
  RETRY:
    memset(&incoming, 
	   0, 
	   sizeof(struct sockaddr_in6));
    if (udp6_shutdown == YES) {
      FREE(mp->msg);
      FREE(mp);
      break;
    }
    size = RECVFROM(udp6_sock, 
		    mp->msg, 
		    udp6API.mtu + sizeof(UDP6Message), 
		    0,
		    (struct sockaddr * )&incoming, 
		    &addrlen);
    if ( (size < 0) || 
	 (udp6_shutdown == YES) ) {
      if (udp6_shutdown == NO) {
	if ( (errno == EINTR) || 
	     (errno == EAGAIN) ||
	     (errno == ECONNREFUSED) )
	  goto RETRY;
      }
      FREE(mp->msg);
      FREE(mp);
      if (udp6_shutdown == NO)
	LOG_STRERROR(LOG_ERROR, "recvfrom");
      break; /* die/shutdown */
    }
    incrementBytesReceived(size);
    statChange(stat_octets_total_udp6_in,
	       size);
    if ((unsigned int)size <= sizeof(UDP6Message)) {
      char * tmp = MALLOC(INET6_ADDRSTRLEN);
      LOG(LOG_INFO,
	  _("Received invalid UDP6 message from %s:%d, dropping.\n"),
	  inet_ntop(AF_INET6,
		    &incoming,
		    tmp,
		    INET6_ADDRSTRLEN), 
	  ntohs(incoming.sin6_port));
      FREE(tmp);
      goto RETRY;
    }
    memcpy(&udp6m,
	   &((char*)mp->msg)[size - sizeof(UDP6Message)],
	   sizeof(UDP6Message));

    IFLOG(LOG_DEBUG,
	  hash2enc(&udp6m.sender.hashPubKey,
		   &enc));
#if DEBUG_UDP6
    tmp = MALLOC(INET6_ADDRSTRLEN);
    LOG(LOG_DEBUG,
	"Received %d bytes via UDP6 from %s:%d (%s).\n",
	size,
	inet_ntop(AF_INET6,
		  &incoming,
		  tmp,
		  INET6_ADDRSTRLEN), 
	ntohs(incoming.sin6_port),
	&enc);
    FREE(tmp);
#endif
    /* quick test of the packet, if failed, repeat! */
    if (size != ntohs(udp6m.size)) {
      LOG(LOG_WARNING,
	  _("Packed received from %s:%d (UDP6) failed format check."),
	  inet_ntop(AF_INET6,
		    &incoming,
		    tmp,
		    INET6_ADDRSTRLEN), 
	  ntohs(incoming.sin6_port));
      goto RETRY;
    }
    GNUNET_ASSERT(sizeof(struct in6_addr) == sizeof(IP6addr));
    if (YES == isBlacklisted((IP6addr*)&incoming.sin6_addr)) {
      char * tmp = MALLOC(INET6_ADDRSTRLEN);
      LOG(LOG_WARNING,
	  _("Sender %s is blacklisted, dropping message.\n"),
	  inet_ntop(AF_INET6,
		    &incoming,
		    tmp,
		    INET6_ADDRSTRLEN));
      FREE(tmp);
      goto RETRY; /* drop on the floor */
    }
    /* message ok, fill in mp and pass to core */
    mp->tsession     = NULL;
    mp->size        = ntohs(udp6m.size) - sizeof(UDP6Message);    
    mp->isEncrypted = ntohs(udp6m.isEncrypted);
    mp->crc         = ntohl(udp6m.checkSum);
    memcpy(&mp->sender,
	   &udp6m.sender,
	   sizeof(HostIdentity));
    coreAPI->receive(mp);
  }
  /* shutdown */
  SEMAPHORE_UP(serverSignal);
  return NULL;
}


/* *************** API implementation *************** */

/**
 * Verify that a HELO-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param helo the HELO message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on failure
 */
static int verifyHelo(const HELO_Message * helo) {
  Host6Address * haddr;

  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];
  if ( (ntohs(helo->senderAddressSize) != sizeof(Host6Address)) ||
       (ntohs(helo->header.size) != HELO_Message_size(helo)) ||
       (ntohs(helo->header.requestType) != p2p_PROTO_HELO) ||
       (YES == isBlacklisted(&haddr->senderIP)) )
    return SYSERR; /* obviously invalid */
  else {
#if DEBUG_UDP6
    char * tmp = MALLOC(INET6_ADDRSTRLEN);
    LOG(LOG_DEBUG,
	"Verified UDP6 helo from %d.%d.%d.%d:%d.\n",
	inet_ntop(AF_INET6,
		  &haddr->senderIP,
		  tmp,
		  INET6_ADDRSTRLEN), 
	ntohs(haddr->senderPort));
    FREE(tmp);
#endif    
    return OK;
  }
}

/**
 * Create a HELO-Message for the current node. The HELO is created
 * without signature and without a timestamp. The GNUnet core will
 * sign the message and add an expiration time.
 *
 * @param helo where to store the HELO message
 * @return OK on success, SYSERR on error
 */
static int createHELO(HELO_Message ** helo) {
  HELO_Message * msg;
  Host6Address * haddr;
  unsigned short port;

  port = getGNUnetUDP6Port();
  if (port == 0)
    return SYSERR; /* UDP6 transport configured send-only */

  msg = MALLOC(sizeof(HELO_Message) + sizeof(Host6Address));
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)msg)->senderAddress[0];

  if (SYSERR == getPublicIP6Address(&haddr->senderIP)) {
    FREE(msg);
    LOG(LOG_WARNING,
	_("UDP6: Could not determine my public IPv6 address.\n"));
    return SYSERR;
  }
  haddr->senderPort      = htons(port); 
  haddr->reserved        = htons(0);
  msg->senderAddressSize = htons(sizeof(Host6Address));
  msg->protocol          = htons(UDP6_PROTOCOL_NUMBER);
  msg->MTU               = htonl(udp6API.mtu);
  *helo = msg;
  return OK;
}

/**
 * Establish a connection to a remote node.
 * @param helo the HELO-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return OK on success, SYSERR if the operation failed
 */
static int udp6Connect(HELO_Message * helo,
		       TSession ** tsessionPtr) {
  TSession * tsession;
  Host6Address * haddr;
#if DEBUG_UDP6
  char * tmp;
#endif

  tsession = MALLOC(sizeof(TSession));
  tsession->internal = helo;
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];  
#if DEBUG_UDP6
  tmp = MALLOC(INET6_ADDRSTRLEN);
  LOG(LOG_DEBUG,
      "Connecting via UDP6 to %s:%d.\n",
      inet_ntop(AF_INET6,
		&haddr->senderIP,
		tmp,
		INET6_ADDRSTRLEN), 
      ntohs(haddr->senderPort));
  FREE(tmp);
#endif
   (*tsessionPtr) = tsession;
  return OK;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
int udp6Associate(TSession * tsession) {
  return SYSERR; /* UDP6 connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the HELO_Message identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @param isEncrypted is the message encrypted?
 * @param crc CRC32 checksum of the plaintext
 * @return SYSERR on error, OK on success
 */
static int udp6Send(TSession * tsession,
		    const void * message,
		    const unsigned int size,
		    int isEncrypted,
		    const int crc) {
  char * msg;
  UDP6Message mp;
  HELO_Message * helo;
  Host6Address * haddr;
  struct sockaddr_in6 sin; /* an Internet endpoint address */
  int ok;
  int ssize;
#if DEBUG_UDP6
  char * tmp;
#endif
  
  if (udp6_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (size > udp6API.mtu) {
    BREAK();
    return SYSERR;
  }
  helo = (HELO_Message*)tsession->internal;
  if (helo == NULL) 
    return SYSERR;

  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];
  ssize = size + sizeof(UDP6Message);
  msg = MALLOC(ssize);
  mp.checkSum    = htonl(crc);
  mp.isEncrypted = htons(isEncrypted);
  mp.size        = htons(ssize);
  memcpy(&mp.sender,
	 coreAPI->myIdentity,
	 sizeof(HostIdentity));
  memcpy(&msg[size],
	 &mp,
	 sizeof(UDP6Message));
  memcpy(msg,
	 message,
	 size);
  ok = SYSERR;
  memset(&sin, 0, sizeof(sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = haddr->senderPort;
  memcpy(&sin.sin6_addr,
	 &haddr->senderIP.addr,
	 sizeof(IP6addr));
#if DEBUG_UDP6
  tmp = MALLOC(INET6_ADDRSTRLEN);
  LOG(LOG_DEBUG,
      "Sending message of %d bytes via UDP6 to %s:%d..\n",
      ssize,
      inet_ntop(AF_INET6,
		&sin,
		tmp,
		INET6_ADDRSTRLEN), 
      ntohs(sin.sin_port));
  FREE(tmp);
#endif
  if (ssize == SENDTO(udp6_sock,
		      msg,
		      ssize,
		      0, /* no flags */
		      (struct sockaddr*) &sin,
		      sizeof(sin))) {
    ok = OK;
  } else {
    LOG_STRERROR(LOG_WARNING, "sendto");
  }
  incrementBytesSent(ssize);
  statChange(stat_octets_total_udp6_out,
	     ssize);
  FREE(msg);
  return ok;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int udp6Disconnect(TSession * tsession) {
  if (tsession != NULL) {
    if (tsession->internal != NULL)
      FREE(tsession->internal);
    FREE(tsession);
  }
  return OK;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  unsigned short port;

   /* initialize UDP6 network */
  port = getGNUnetUDP6Port();
  udp6_sock = passivesock(port);
  if (port != 0) {
    udp6_shutdown = NO;
    serverSignal = SEMAPHORE_NEW(0);
    if (0 != PTHREAD_CREATE(&dispatchThread,
			    (PThreadMain) &listenAndDistribute,
			    NULL,
			    4*1024))
      return SYSERR;
    SEMAPHORE_DOWN(serverSignal);
  } else
    memset(&dispatchThread,
	   0,
	   sizeof(PTHREAD_T)); /* zero-out */
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int stopTransportServer() {
  if (udp6_shutdown == NO) {
    /* stop the thread, first set shutdown
       to YES, then ensure that the thread
       actually sees the flag by sending
       a dummy message of 1 char */
    udp6_shutdown = YES;
    if (serverSignal != NULL) {
      char msg = '\0';
      struct sockaddr_in sin;
      void * unused;
      
      /* send to loopback */
      sin.sin_family = AF_INET;
      sin.sin_port = htons(getGNUnetUDP6Port());
      *(int*)&sin.sin_addr = htonl(0x7F000001); /* 127.0.0.1 = localhost */
      SENDTO(udp6_sock, 
	     &msg, 
	     sizeof(msg), 
	     0, /* no flags */
	     (struct sockaddr*) &sin,
	     sizeof(sin));
      SEMAPHORE_DOWN(serverSignal);
      SEMAPHORE_FREE(serverSignal);
      PTHREAD_JOIN(&dispatchThread, &unused);
    }
  }
  CLOSE(udp6_sock);  
  udp6_sock = -1;
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static void reloadConfiguration(void) {
  char * ch;

  MUTEX_LOCK(&configLock);
  FREENONNULL(filteredNetworks_);
  ch = getConfigurationString("UDP6",
			      "BLACKLIST");
  if (ch == NULL)
    filteredNetworks_ = parseRoutes6("");
  else {
    filteredNetworks_ = parseRoutes6(ch);
    FREE(ch);    
  }
  MUTEX_UNLOCK(&configLock);
}

/**
 * Convert UDP6 address to a string.
 */
static char * addressToString(const HELO_Message * helo) {
  char * ret;
  char * tmp;
  Host6Address * haddr;
  
  haddr = (Host6Address*) &((HELO_Message_GENERIC*)helo)->senderAddress[0];  
  ret = MALLOC(INET6_ADDRSTRLEN+16);
  tmp = MALLOC(INET6_ADDRSTRLEN);  
  SNPRINTF(ret,
	   INET6_ADDRSTRLEN+16,
	   "%s:%d (UDP6)",
	   inet_ntop(AF_INET6,
		     haddr,
		     tmp,
		     INET6_ADDRSTRLEN), 
	   ntohs(haddr->senderPort));
  FREE(tmp);
  return ret;
}

/**
 * The default maximum size of each outbound UDP6 message, 
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1452

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp6 transport API.
 */ 
TransportAPI * inittransport_udp6(CoreAPIForTransport * core) {
  int mtu;

  coreAPI = core;
  stat_octets_total_udp6_in 
    = statHandle(_("# bytes received via udp6"));
  stat_octets_total_udp6_out 
    = statHandle(_("# bytes sent via udp6"));

  MUTEX_CREATE(&configLock);
  reloadConfiguration();
  mtu = getConfigurationInt("UDP6",
			    "MTU");
  if (mtu == 0)
    mtu = MESSAGE_SIZE;
  if (mtu < 1200)
    LOG(LOG_ERROR,
	_("MTU for '%s' is probably to low (fragmentation not implemented!)\n"),
	"UDP6");

  udp6API.protocolNumber       = UDP6_PROTOCOL_NUMBER;
  udp6API.mtu                  = mtu - sizeof(UDP6Message);
  udp6API.cost                 = 19950;
  udp6API.verifyHelo           = &verifyHelo;
  udp6API.createHELO           = &createHELO;
  udp6API.connect              = &udp6Connect;
  udp6API.send                 = &udp6Send;
  udp6API.sendReliable         = &udp6Send;  /* can't increase reliability */
  udp6API.associate            = &udp6Associate;
  udp6API.disconnect           = &udp6Disconnect;
  udp6API.startTransportServer = &startTransportServer;
  udp6API.stopTransportServer  = &stopTransportServer;
  udp6API.reloadConfiguration  = &reloadConfiguration;
  udp6API.addressToString      = &addressToString;

  return &udp6API;
}

void donetransport_udp6() {
  MUTEX_DESTROY(&configLock);
  FREENONNULL(filteredNetworks_);
}

/* end of udp6.c */
