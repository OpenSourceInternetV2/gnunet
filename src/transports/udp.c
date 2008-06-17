/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/udp.c
 * @brief Implementation of the UDP transport service
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "gnunet_upnp_service.h"
#include "ip.h"
#include "platform.h"

#define DEBUG_UDP GNUNET_NO

static GNUNET_UPnP_ServiceAPI *upnp;

#include "udp_helper.c"

/**
 * Host-Address in a UDP network.
 */
typedef struct
{
  /**
   * claimed IP of the sender, network byte order
   */
  GNUNET_IPv4Address ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_LoadMonitor *load_monitor;

static struct GNUNET_IPv4NetworkSet *filteredNetworks_;

static struct GNUNET_IPv4NetworkSet *allowedNetworks_;

static struct GNUNET_Mutex *configLock;

/**
 * Get the GNUnet UDP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short
getGNUnetUDPPort ()
{
  struct servent *pse;          /* pointer to service information entry        */
  unsigned long long port;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "UDP",
                                                      "PORT", 1, 65535, 2086,
                                                      &port))
    {
      if ((pse = getservbyname ("gnunet", "udp")))
        port = htons (pse->s_port);
      else
        port = 0;
    }
  return (unsigned short) port;
}

/**
 * Allocate and bind a server socket for the UDP transport.
 */
static int
listensock (unsigned short port)
{
  struct sockaddr_in sin;
  int sock;
  const int on = 1;

  sock = SOCKET (PF_INET, SOCK_DGRAM, 17);
  if (sock < 0)
    {
      GNUNET_GE_DIE_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                              GNUNET_GE_IMMEDIATE, "socket");
      return -1;
    }
  if (SETSOCKOPT (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    {
      GNUNET_GE_DIE_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                              GNUNET_GE_IMMEDIATE, "setsockopt");
      return -1;
    }
  GNUNET_GE_ASSERT (NULL, port != 0);
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);
  if (BIND (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                              GNUNET_GE_IMMEDIATE, "bind");
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                     _("Failed to bind to UDP port %d.\n"), port);
      GNUNET_GE_DIE_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_USER |
                              GNUNET_GE_IMMEDIATE, "bind");
      return -1;
    }
  /* do not bind if port == 0, then we use
     send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int
isBlacklisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv4Address ip;
  int ret;

  if (addr_len == sizeof (struct sockaddr_in))
    {
      memcpy (&ip, &((struct sockaddr_in *) addr)->sin_addr,
              sizeof (GNUNET_IPv4Address));
    }
  else if (addr_len == sizeof (GNUNET_IPv4Address))
    {
      memcpy (&ip, addr, addr_len);
    }
  else
    {
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (configLock);
  ret = GNUNET_check_ipv4_listed (filteredNetworks_, ip);
  GNUNET_mutex_unlock (configLock);
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isWhitelisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv4Address ip;
  int ret;

  if (addr_len == sizeof (struct sockaddr_in))
    {
      memcpy (&ip, &((struct sockaddr_in *) addr)->sin_addr,
              sizeof (GNUNET_IPv4Address));
    }
  else if (addr_len == sizeof (GNUNET_IPv4Address))
    {
      memcpy (&ip, addr, addr_len);
    }
  else
    {
      return GNUNET_SYSERR;
    }
  ret = GNUNET_OK;
  GNUNET_mutex_lock (configLock);
  if (allowedNetworks_ != NULL)
    ret = GNUNET_check_ipv4_listed (allowedNetworks_, ip);
  GNUNET_mutex_unlock (configLock);
  return ret;
}

static int
isRejected (const void *addr, unsigned int addr_len)
{
  if ((GNUNET_YES == isBlacklisted (addr,
                                    addr_len)) ||
      (GNUNET_YES != isWhitelisted (addr, addr_len)))
    {
#if DEBUG_UDP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Rejecting traffic from %u.%u.%u.%u.\n",
                     GNUNET_PRIP (ntohl (*(int *) addr)));
#endif
      return GNUNET_YES;
    }
  return GNUNET_NO;
}


/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
verifyHello (const GNUNET_MessageHello * hello)
{
  const HostAddress *haddr;

  haddr = (const HostAddress *) &hello[1];
  if ((ntohs (hello->senderAddressSize) != sizeof (HostAddress)) ||
      (ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
      (ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if ((GNUNET_YES == isBlacklisted (&haddr->ip,
                                    sizeof (GNUNET_IPv4Address))) ||
      (GNUNET_YES != isWhitelisted (&haddr->ip, sizeof (GNUNET_IPv4Address))))
    {
#if DEBUG_UDP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Rejecting UDP HELLO from %u.%u.%u.%u:%u due to configuration.\n",
                     GNUNET_PRIP (ntohl (*(int *) &haddr->ip.addr)),
                     ntohs (haddr->port));
#endif
      return GNUNET_SYSERR;     /* obviously invalid */
    }
#if DEBUG_UDP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Verified UDP HELLO from %u.%u.%u.%u:%u.\n",
                 GNUNET_PRIP (ntohl (*(int *) &haddr->ip.addr)),
                 ntohs (haddr->port));
#endif
  return GNUNET_OK;
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
createhello ()
{
  static HostAddress last_addr;
  GNUNET_MessageHello *msg;
  HostAddress *haddr;
  unsigned short port;

  port = getGNUnetUDPPort ();
  if (port == 0)
    return NULL;                /* UDP transport configured send-only */

  msg = GNUNET_malloc (sizeof (GNUNET_MessageHello) + sizeof (HostAddress));
  haddr = (HostAddress *) & msg[1];


  if (!(((upnp != NULL) &&
         (GNUNET_OK == upnp->get_ip (port,
                                     "UDP",
                                     &haddr->ip))) ||
        (GNUNET_SYSERR !=
         GNUNET_IP_get_public_ipv4_address (cfg, ectx, &haddr->ip))))
    {
      GNUNET_free (msg);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("UDP: Could not determine my public IP address.\n"));
      return NULL;
    }
  haddr->port = htons (port);
  haddr->reserved = htons (0);
  if (0 != memcmp (haddr, &last_addr, sizeof (HostAddress)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "UDP uses IP address %u.%u.%u.%u.\n",
                     GNUNET_PRIP (ntohl (*(int *) &haddr->ip)));
      last_addr = *haddr;
    }
  msg->senderAddressSize = htons (sizeof (HostAddress));
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP);
  msg->MTU = htonl (udpAPI.mtu);
  return msg;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
udpSend (GNUNET_TSession * tsession,
         const void *message, const unsigned int size, int important)
{
  UDPMessage *mp;
  GNUNET_MessageHello *hello;
  HostAddress *haddr;
  struct sockaddr_in sin;       /* an Internet endpoint address */
  int ok;
  int ssize;
  size_t sent;

  GNUNET_GE_ASSERT (NULL, tsession != NULL);
  if (udp_sock == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size > udpAPI.mtu)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  hello = (GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;

  haddr = (HostAddress *) & hello[1];
  ssize = size + sizeof (UDPMessage);
  mp = GNUNET_malloc (ssize);
  mp->header.size = htons (ssize);
  mp->header.type = 0;
  mp->sender = *(coreAPI->myIdentity);
  memcpy (&mp[1], message, size);
  ok = GNUNET_SYSERR;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = haddr->port;

  GNUNET_GE_ASSERT (ectx,
                    sizeof (struct in_addr) == sizeof (GNUNET_IPv4Address));
  memcpy (&sin.sin_addr, &haddr->ip, sizeof (GNUNET_IPv4Address));
#if DEBUG_UDP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Sending message of %d bytes via UDP to %u.%u.%u.%u:%u.\n",
                 ssize, GNUNET_PRIP (ntohl (*(int *) &sin.sin_addr)),
                 ntohs (sin.sin_port));
#endif
#ifndef MINGW
  if (GNUNET_YES == GNUNET_socket_send_to (udp_sock,
                                           GNUNET_NC_NONBLOCKING,
                                           mp,
                                           ssize, &sent, (const char *) &sin,
                                           sizeof (sin)))
#else
  sent =
    win_ols_sendto (udp_sock, mp, ssize, (const char *) &sin, sizeof (sin));
  if (sent != SOCKET_ERROR)
#endif
    {
      ok = GNUNET_OK;
      if (stats != NULL)
        stats->change (stat_bytesSent, sent);
    }
  else
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _
                     ("Failed to send message of size %d via UDP to %u.%u.%u.%u:%u: %s\n"),
                     ssize, GNUNET_PRIP (ntohl (*(int *) &sin.sin_addr)),
                     ntohs (sin.sin_port), STRERROR (errno));
      if (stats != NULL)
        stats->change (stat_bytesDropped, ssize);
    }
  GNUNET_free (mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  int sock;
  unsigned short port;

  GNUNET_GE_ASSERT (ectx, selector == NULL);
  /* initialize UDP network */
  port = getGNUnetUDPPort ();
  if (port != 0)
    {
      sock = listensock (port);
      if (sock == -1)
        return GNUNET_SYSERR;
      selector = GNUNET_select_create ("udp", GNUNET_YES, ectx, load_monitor, sock, sizeof (struct sockaddr_in), 0,     /* timeout */
                                       &select_message_handler,
                                       NULL,
                                       &select_accept_handler,
                                       &isRejected,
                                       &select_close_handler,
                                       NULL, 64 * 1024,
                                       16 /* max sockets */ );
      if (selector == NULL)
        return GNUNET_SYSERR;
    }
#ifndef MINGW
  sock = SOCKET (PF_INET, SOCK_DGRAM, 17);
#else
  sock = win_ols_socket (PF_INET, SOCK_DGRAM, 17);
#endif
  if (sock == -1)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "socket");
      GNUNET_select_destroy (selector);
      selector = NULL;
      return GNUNET_SYSERR;
    }
  udp_sock = GNUNET_socket_create (ectx, load_monitor, sock);
  GNUNET_GE_ASSERT (ectx, udp_sock != NULL);
  return GNUNET_OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static int
reloadConfiguration ()
{
  char *ch;

  GNUNET_mutex_lock (configLock);
  GNUNET_free_non_null (filteredNetworks_);
  GNUNET_free_non_null (allowedNetworks_);
  ch = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "UDP", "BLACKLIST", "", &ch);
  filteredNetworks_ = GNUNET_parse_ipv4_network_specification (ectx, ch);
  GNUNET_free (ch);
  ch = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "UDP", "WHITELIST", "", &ch);
  if (strlen (ch) > 0)
    allowedNetworks_ = GNUNET_parse_ipv4_network_specification (ectx, ch);
  else
    allowedNetworks_ = NULL;
  GNUNET_free (ch);
  GNUNET_mutex_unlock (configLock);
  return 0;
}

/**
 * Convert UDP hello to IP address
 */
static int
helloToAddress (const GNUNET_MessageHello * hello,
                void **sa, unsigned int *sa_len)
{
  const HostAddress *haddr = (const HostAddress *) &hello[1];
  struct sockaddr_in *serverAddr;

  *sa_len = sizeof (struct sockaddr_in);
  serverAddr = GNUNET_malloc (sizeof (struct sockaddr_in));
  *sa = serverAddr;
  memset (serverAddr, 0, sizeof (struct sockaddr_in));
  serverAddr->sin_family = AF_INET;
  memcpy (&serverAddr->sin_addr, haddr, sizeof (GNUNET_IPv4Address));
  serverAddr->sin_port = haddr->port;
  return GNUNET_OK;
}

/**
 * The default maximum size of each outbound UDP message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1472

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
GNUNET_TransportAPI *
inittransport_udp (GNUNET_CoreAPIForTransport * core)
{
  unsigned long long mtu;

  ectx = core->ectx;
  cfg = core->cfg;
  load_monitor = core->load_monitor;
  GNUNET_GE_ASSERT (ectx, sizeof (HostAddress) == 8);
  GNUNET_GE_ASSERT (ectx, sizeof (UDPMessage) == 68);
  coreAPI = core;
  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "UDP",
                                                      "MTU",
                                                      sizeof (UDPMessage)
                                                      +
                                                      GNUNET_P2P_MESSAGE_OVERHEAD
                                                      +
                                                      sizeof
                                                      (GNUNET_MessageHeader) +
                                                      32, 65500,
                                                      MESSAGE_SIZE, &mtu))
    {
      return NULL;
    }
  if (mtu < 1200)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                   _("MTU %llu for `%s' is probably too low!\n"), mtu, "UDP");
  if (GNUNET_GC_get_configuration_value_yesno (cfg, "UDP", "UPNP", GNUNET_YES)
      == GNUNET_YES)
    {
      upnp = coreAPI->request_service ("upnp");

      if (upnp == NULL)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                       "The UPnP service could not be loaded. To disable UPnP, set the "
                       "configuration option \"UPNP\" in section \"UDP\" to \"NO\"\n");
    }
  stats = coreAPI->request_service ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via UDP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via UDP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by UDP (outgoing)"));
      stat_udpConnected
        = stats->create (gettext_noop ("# UDP connections (right now)"));
    }
  configLock = GNUNET_mutex_create (GNUNET_NO);
  reloadConfiguration ();
  udpAPI.protocolNumber = GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP;
  udpAPI.mtu = mtu - sizeof (UDPMessage);
  udpAPI.cost = 20000;
  udpAPI.verifyHello = &verifyHello;
  udpAPI.createhello = &createhello;
  udpAPI.connect = &udpConnect;
  udpAPI.send = &udpSend;
  udpAPI.associate = &udpAssociate;
  udpAPI.disconnect = &udpDisconnect;
  udpAPI.startTransportServer = &startTransportServer;
  udpAPI.stopTransportServer = &stopTransportServer;
  udpAPI.helloToAddress = &helloToAddress;
  udpAPI.testWouldTry = &testWouldTry;

  return &udpAPI;
}

void
donetransport_udp ()
{
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  if (upnp != NULL)
    {
      coreAPI->release_service (upnp);
      upnp = NULL;
    }
  GNUNET_mutex_destroy (configLock);
  configLock = NULL;
  GNUNET_free_non_null (filteredNetworks_);
  coreAPI = NULL;
}

/* end of udp.c */
