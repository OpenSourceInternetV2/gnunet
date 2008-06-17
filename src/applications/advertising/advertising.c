/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file advertising/advertising.c
 * @brief Cron-jobs that exchange hellos to ensure that the network is
 * connected (nodes know of each other).  This is implemented as
 * an application and not a service (since no API is provided for
 * clients to call on -- this just happens in the background).
 *
 * Nevertheless, every GNUnet peer should probably run advertising
 * at the moment.
 *
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_topology_service.h"
#include "bootstrap.h"
#include "platform.h"

/**
 * Send our hello to a random connected host on a regular basis.
 */
#define HELLO_BROADCAST_FREQUENCY (2 * cronMINUTES)

/**
 * From time to time, forward one hello from one peer to
 * a random other peer.
 */
#define HELLO_FORWARD_FREQUENCY (45 * cronSECONDS)

/**
 * Meanings of the bits in activeCronJobs (ACJ).
 */
#define ACJ_NONE 0
#define ACJ_ANNOUNCE 1
#define ACJ_FORWARD 2
#define ACJ_ALL (ACJ_ANNOUNCE | ACJ_FORWARD)

#define DEBUG_ADVERTISING NO

static CoreAPIForApplication *coreAPI;

static Transport_ServiceAPI *transport;

static Identity_ServiceAPI *identity;

static Pingpong_ServiceAPI *pingpong;

static Topology_ServiceAPI *topology;

static Stats_ServiceAPI *stats;

static struct GE_Context *ectx;

static int stat_hello_in;

static int stat_hello_nat_in;

static int stat_hello_verified;

static int stat_hello_update;

static int stat_hello_discard;

static int stat_hello_no_transport;

static int stat_hello_ping_busy;

static int stat_hello_noselfad;

static int stat_hello_send_error;

static int stat_hello_out;

static int stat_hello_fwd;

static int stat_plaintextPingSent;


/**
 * Which types of cron-jobs are currently scheduled
 * with cron?
 */
static int activeCronJobs = ACJ_NONE;

static cron_t lasthelloMsg = 0;

static double
getConnectPriority ()
{
  double preference;

  /* we should'nt give lots of bandwidth for hellos if we're close to
     the connection goal */
  preference = topology->getSaturation ();
  if (preference <= 0.0001)
    preference = 0xFFFF;
  else
    preference = 1 / preference;
  /* always give some decent, but compared to (migrated) content
     competitive amount of bandwidth to peers sending (valid)
     hellos */
  if (preference < 0.2)
    preference = 0.2;
  return preference;
}

static void
callAddHost (void *cls)
{
  P2P_hello_MESSAGE *hello = cls;

  if (stats != NULL)
    stats->change (stat_hello_verified, 1);
  identity->addHost (hello);
  FREE (hello);
}

/**
 * We have received a hello.  Verify (signature, integrity,
 * ping-pong) and store identity if ok.
 *
 * @param message the hello message
 * @return SYSERR on error, OK on success
 */
static int
receivedhello (const PeerIdentity * sender, const MESSAGE_HEADER * message)
{
  TSession *tsession;
  P2P_hello_MESSAGE *copy;
  PeerIdentity foreignId;
  const P2P_hello_MESSAGE *msg;
  MESSAGE_HEADER *ping;
  char *buffer;
  int helloEnd;
  int mtu;
  int res;
  cron_t now;
  EncName enc;

  /* first verify that it is actually a valid hello */
  msg = (const P2P_hello_MESSAGE *) message;
  if ((ntohs (msg->header.size) < sizeof (P2P_hello_MESSAGE)) ||
      (ntohs (msg->header.size) != P2P_hello_MESSAGE_size (msg)))
    {
      GE_BREAK_OP (ectx, 0);
      return SYSERR;
    }
  identity->getPeerIdentity (&msg->publicKey, &foreignId);
  if (!equalsHashCode512 (&msg->senderIdentity.hashPubKey,
                          &foreignId.hashPubKey))
    {
      GE_BREAK_OP (ectx, 0);
      return SYSERR;            /* public key and host hash do not match */
    }
  if (SYSERR == verifySig (&msg->senderIdentity,
                           P2P_hello_MESSAGE_size (msg)
                           - sizeof (Signature)
                           - sizeof (PublicKey)
                           - sizeof (MESSAGE_HEADER),
                           &msg->signature, &msg->publicKey))
    {
      IF_GELOG (ectx,
                GE_WARNING | GE_BULK | GE_USER,
                hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _
              ("HELLO message from `%s' has an invalid signature. Dropping.\n"),
              (char *) &enc);
      GE_BREAK_OP (ectx, 0);
      return SYSERR;            /* message invalid */
    }
  if ((TIME_T) ntohl (msg->expirationTime) > TIME (NULL) + MAX_HELLO_EXPIRES)
    {
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _
              ("HELLO message has expiration too far in the future. Dropping.\n"));
      GE_BREAK_OP (ectx, 0);
      return SYSERR;
    }
  if (SYSERR == transport->verifyhello (msg))
    {
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GE_INFO | GE_BULK | GE_USER,
                hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
              GE_DEBUG | GE_BULK | GE_USER,
              "Transport verification of HELLO message from `%s' failed (%u).\n",
              &enc, ntohs (msg->protocol));
#endif
      return OK;                /* not good, but do process rest of message */
    }
  if (stats != NULL)
    stats->change (stat_hello_in, 1);
#if DEBUG_ADVERTISING
  IF_GELOG (ectx,
            GE_INFO | GE_REQUEST | GE_USER,
            hash2enc (&msg->senderIdentity.hashPubKey, &enc));
  GE_LOG (ectx,
          GE_INFO | GE_REQUEST | GE_USER,
          "HELLO advertisement from `%s' for protocol %d received.\n",
          &enc, ntohs (msg->protocol));
#endif
  if (ntohs (msg->protocol) == NAT_PROTOCOL_NUMBER)
    {
      /* We *can* not verify NAT.  Ever.  So all we
         can do is just accept it.  The best thing
         that we may do is check that it was not
         forwarded by another peer (forwarding NAT
         advertisements is invalid), but even that
         check can not be done securely (since we
         have to accept hellos in plaintext).  Thus
         we take NAT advertisements at face value
         (which is OK since we never attempt to
         connect to a NAT). */
      identity->addHost (msg);
      if (stats != NULL)
        stats->change (stat_hello_nat_in, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
		GE_INFO | GE_REQUEST | GE_USER,
		hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
	      GE_INFO | GE_REQUEST | GE_USER,
	      "HELLO advertisement from `%s' for NAT, no verification required.\n",
	      &enc);
#endif
      return OK;
    }

  /* Then check if we have seen this hello before, if it is identical
     except for the TTL, we trust it and do not play PING-PONG */
  copy = identity->identity2Hello (&foreignId, ntohs (msg->protocol), NO);
  if (NULL != copy)
    {
      if ((ntohs (copy->senderAddressSize) ==
           ntohs (msg->senderAddressSize)) &&
          (0 == memcmp (&msg->MTU,
                        &copy->MTU,
                        sizeof (unsigned short) * 2 +
                        sizeof (unsigned int) +
                        ntohs (copy->senderAddressSize))))
        {
          /* ok, we've seen this one exactly like this before (at most the
             TTL has changed); thus we can 'trust' it without playing
             ping-pong */
          identity->addHost (msg);
          if (stats != NULL)
            stats->change (stat_hello_update, 1);
          FREE (copy);
#if DEBUG_ADVERTISING
	  IF_GELOG (ectx,
		    GE_INFO | GE_REQUEST | GE_USER,
		    hash2enc (&msg->senderIdentity.hashPubKey, &enc));
	  GE_LOG (ectx,
		  GE_INFO | GE_REQUEST | GE_USER,
		  "HELLO advertisement from `%s' for protocol %d updates old advertisement, no verification required.\n",
		  &enc, ntohs (msg->protocol));
#endif
          return OK;
        }
#if DEBUG_ADVERTISING
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "HELLO advertisement differs from prior knowledge,"
              " requireing ping-pong confirmation.\n");
#endif
      FREE (copy);
    }

  if (YES == GC_get_configuration_value_yesno (coreAPI->cfg,
                                               "GNUNETD",
                                               "PRIVATE-NETWORK", NO))
    {
      /* the option 'PRIVATE-NETWORK' can be used
         to limit the connections of this peer to
         peers of which the hostkey has been copied
         by hand to data/hosts;  if this option is
         given, GNUnet will not accept advertisements
         of peers that the local node does not already
         know about.  Note that in order for this
         option to work, HOSTLISTURL should either
         not be set at all or be set to a trusted
         peer that only advertises the private network.
         Also, the option does NOT work at the moment
         if the NAT transport is loaded; for that,
         a couple of lines above would need some minor
         editing :-). */
#if DEBUG_ADVERTISING
      GE_LOG (ectx,
              GE_INFO | GE_BULK | GE_USER,
              "Private network, discarding unknown advertisements\n");
#endif
      return SYSERR;
    }

  /* Ok, must play PING-PONG. Add the hello to the temporary
     (in-memory only) buffer to make it available for a short
     time in order to play PING-PONG */
  identity->addHostTemporarily (msg);

  now = get_time ();
  if ((sender != NULL) &&
      ((now - lasthelloMsg) / cronSECONDS) *
      (os_network_monitor_get_limit (coreAPI->load_monitor,
                                     Download))
      < P2P_hello_MESSAGE_size (msg) * 10)
    {
      /* do not use more than about 10% of the
         available bandwidth to VERIFY hellos (by sending
         our own with a PING).  This does not affect
         the hello advertising.  Sure, we should not
         advertise much more than what other peers
         can verify, but the problem is that buggy/
         malicious peers can spam us with hellos, and
         we don't want to follow that up with massive
         hello-ing by ourselves. */
#if DEBUG_ADVERTISING
      GE_LOG (ectx,
              GE_INFO | GE_BULK | GE_USER,
              "Not enough resources to verify HELLO message at this time (%u * %u < %u * 10)\n",
              (unsigned int) ((now - lasthelloMsg) / cronSECONDS),
              (unsigned int) os_network_monitor_get_limit (coreAPI->
                                                           load_monitor,
                                                           Download),
              (unsigned int) P2P_hello_MESSAGE_size (msg));
#endif
      if (stats != NULL)
        stats->change (stat_hello_discard, 1);
      return SYSERR;
    }
  lasthelloMsg = now;


  /* Establish session as advertised in the hello */
  tsession = transport->connect (msg, __FILE__, NO);
  if (tsession == NULL)
    {
      if (stats != NULL)
        stats->change (stat_hello_no_transport, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
		GE_INFO | GE_REQUEST | GE_USER,
		hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
	      GE_INFO | GE_REQUEST | GE_USER,
	      "Failed to connect to `%s'.  Verification failed.\n",
	      &enc);
#endif
      return SYSERR;            /* could not connect */
    }

  /* build message to send, ping must contain return-information,
     such as a selection of our hellos... */
  mtu = transport->getMTU (tsession->ttype);
  if (mtu == 0)
    {
      mtu = 2048;               /* bound size */
    }
  else
    {
      GE_ASSERT (ectx, mtu > P2P_MESSAGE_OVERHEAD);
      mtu -= P2P_MESSAGE_OVERHEAD;
    }
  copy = MALLOC (P2P_hello_MESSAGE_size (msg));
  memcpy (copy, msg, P2P_hello_MESSAGE_size (msg));
  ping = pingpong->pingUser (&msg->senderIdentity,
                             &callAddHost, copy, YES, rand ());
  if (ping == NULL)
    {
      res = SYSERR;
      GE_LOG (ectx,
              GE_INFO | GE_REQUEST | GE_USER,
              _("Could not send HELLO+PING, ping buffer full.\n"));
      transport->disconnect (tsession, __FILE__);
      if (stats != NULL)
        stats->change (stat_hello_ping_busy, 1);
      return SYSERR;
    }
  buffer = MALLOC (mtu);
  if (mtu > ntohs (ping->size))
    {
      helloEnd = transport->getAdvertisedhellos (mtu - ntohs (ping->size),
                                                 buffer);
      GE_ASSERT (ectx, mtu - ntohs (ping->size) >= helloEnd);
    }
  else
    {
      helloEnd = -2;
    }
  if (helloEnd <= 0)
    {
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _
              ("Failed to create an advertisement for this peer. Will not send PING.\n"));
      FREE (buffer);
      if (stats != NULL)
        stats->change (stat_hello_noselfad, 1);
      transport->disconnect (tsession, __FILE__);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
		GE_INFO | GE_REQUEST | GE_USER,
		hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
	      GE_INFO | GE_REQUEST | GE_USER,
	      "Failed to connect advertisement for myself.  Verification failed.\n",
	      &enc);
#endif
      return SYSERR;
    }
  res = OK;
  memcpy (&buffer[helloEnd], ping, ntohs (ping->size));
  helloEnd += ntohs (ping->size);
  FREE (ping);

  /* ok, finally we can send! */
  if ((res == OK) &&
      (SYSERR == coreAPI->sendPlaintext (tsession, buffer, helloEnd)))
    {

      if (stats != NULL)
        stats->change (stat_hello_send_error, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
		GE_INFO | GE_REQUEST | GE_USER,
		hash2enc (&msg->senderIdentity.hashPubKey, &enc));
      GE_LOG (ectx,
	      GE_INFO | GE_REQUEST | GE_USER,
	      "Failed to transmit advertisement for myself.  Verification failed.\n",
	      &enc);
#endif
      res = SYSERR;
    }
  if (res == OK)
    {
      if (stats != NULL)
        stats->change (stat_plaintextPingSent, 1);
    }
  FREE (buffer);
  if (SYSERR == transport->disconnect (tsession, __FILE__))
    res = SYSERR;
  return res;
}

typedef struct
{
  /* the hello message */
  P2P_hello_MESSAGE *m;
  /* send the hello in 1 out of n cases */
  int n;
} SendData;

static int
broadcastHelper (const PeerIdentity * hi,
                 const unsigned short proto, int confirmed, void *cls)
{
  SendData *sd = cls;
  P2P_hello_MESSAGE *hello;
  TSession *tsession;
  int prio;
#if DEBUG_ADVERTISING
  EncName other;
#endif

  if (confirmed == NO)
    return OK;
  if (proto == NAT_PROTOCOL_NUMBER)
    {
      sd->n--;
      return OK;                /* don't advertise NAT addresses via broadcast */
    }
  if ((sd->n != 0) && (weak_randomi (sd->n) != 0))
    return OK;
#if DEBUG_ADVERTISING
  IF_GELOG (ectx,
            GE_DEBUG | GE_REQUEST | GE_USER,
            hash2enc (&hi->hashPubKey, &other));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Entering `%s' with target `%s'.\n", __FUNCTION__, &other);
#endif
  if (0 == memcmp (hi, coreAPI->myIdentity, sizeof (PeerIdentity)))
    return OK;                  /* never advertise to myself... */
  prio = (int) getConnectPriority ();
  if (prio >= EXTREME_PRIORITY)
    prio = EXTREME_PRIORITY / 4;
  if (OK == coreAPI->queryPeerStatus (hi, NULL, NULL))
    {
      coreAPI->unicast (hi, &sd->m->header, prio, HELLO_BROADCAST_FREQUENCY);
      if (stats != NULL)
        stats->change (stat_hello_out, 1);
      return OK;
    }
  /* with even lower probability (with n peers
     trying to contact with a probability of 1/n^2,
     we get a probability of 1/n for this, which
     is what we want: fewer attempts to contact fresh
     peers as the network grows): */
  if ((sd->n != 0) && (weak_randomi (sd->n) != 0))
    return OK;

  /* establish short-lived connection, send, tear down */
  hello = identity->identity2Hello (hi, proto, NO);
  if (NULL == hello)
    {
#if DEBUG_ADVERTISING
      GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER,
              "Exit from `%s' (error: `%s' failed).\n",
              __FUNCTION__, "identity2Hello");
#endif
      return OK;
    }
  tsession = transport->connect (hello, __FILE__, YES);
  FREE (hello);
  if (tsession == NULL)
    {
#if DEBUG_ADVERTISING
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Exit from `%s' (%s error).\n",
              __FUNCTION__, "transportConnect");
#endif
      return OK;                /* could not connect */
    }
  if (stats != NULL)
    stats->change (stat_hello_out, 1);
  coreAPI->sendPlaintext (tsession,
                          (char *) &sd->m->header,
                          P2P_hello_MESSAGE_size (sd->m));
  transport->disconnect (tsession, __FILE__);
#if DEBUG_ADVERTISING
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "Exit from %s.\n", __FUNCTION__);
#endif
  return OK;
}

/**
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist (called for each transport)...
 */
static void
broadcasthelloTransport (TransportAPI * tapi, void *cls)
{
  const int *prob = cls;
  SendData sd;
  cron_t now;

  if (os_network_monitor_get_load (coreAPI->load_monitor, Upload) > 100)
    return;                     /* network load too high... */
  if (((*prob) != 0) && (0 != weak_randomi (*prob)))
    return;                     /* ignore */
  now = get_time ();
  sd.n = identity->forEachHost (now, NULL, NULL);       /* just count */
  sd.m = transport->createhello (tapi->protocolNumber);
  if (sd.m == NULL)
    return;
#if DEBUG_ADVERTISING
  GE_LOG (ectx,
          GE_INFO | GE_REQUEST | GE_USER,
          _("Advertising my transport %d to selected peers.\n"),
          tapi->protocolNumber);
#endif
  identity->addHost (sd.m);
  if (sd.n < 1)
    {
      if (identity->forEachHost (0, NULL, NULL) == 0)
        GE_LOG (ectx,
                GE_WARNING | GE_BULK | GE_USER,
                _("Announcing ourselves pointless: "
                  "no other peers are known to us so far.\n"));
      FREE (sd.m);
      return;                   /* no point in trying... */
    }
  identity->forEachHost (now, &broadcastHelper, &sd);
  FREE (sd.m);
}

/**
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist...
 */
static void
broadcasthello (void *unused)
{
  unsigned int i;

  if (os_network_monitor_get_load (coreAPI->load_monitor, Upload) > 100)
    return;                     /* network load too high... */
  if (os_cpu_get_load (coreAPI->ectx, coreAPI->cfg) > 100)
    return;                     /* CPU load too high... */
  i = transport->forEach (NULL, NULL);
  if (i > 0)
    transport->forEach (&broadcasthelloTransport, &i);
}

typedef struct
{
  P2P_hello_MESSAGE *msg;
  int prob;
} FCC;

static void
forwardCallback (const PeerIdentity * peer, void *cls)
{
  FCC *fcc = cls;
  if (os_network_monitor_get_load (coreAPI->load_monitor, Upload) > 100)
    return;                     /* network load too high... */
  if ((fcc->prob != 0) && (weak_randomi (fcc->prob) != 0))
    return;                     /* only forward with a certain chance */
  if (equalsHashCode512 (&peer->hashPubKey,
                         &fcc->msg->senderIdentity.hashPubKey))
    return;                     /* do not bounce the hello of a peer back
                                   to the same peer! */
  if (stats != NULL)
    stats->change (stat_hello_fwd, 1);
  coreAPI->unicast (peer, &fcc->msg->header, 0, /* priority */
                    HELLO_BROADCAST_FREQUENCY);
}

/**
 * Forward hellos from all known hosts to all connected hosts.
 */
static int
forwardhelloHelper (const PeerIdentity * peer,
                    unsigned short protocol, int confirmed, void *data)
{
  int *probability = data;
  P2P_hello_MESSAGE *hello;
  TIME_T now;
  int count;
  FCC fcc;

  if (os_network_monitor_get_load (coreAPI->load_monitor, Upload) > 100)
    return SYSERR;              /* network load too high... */
  if (confirmed == NO)
    return OK;
  if (protocol == NAT_PROTOCOL_NUMBER)
    return OK;                  /* don't forward NAT addresses */
  hello = identity->identity2Hello (peer, protocol, NO);
  if (NULL == hello)
    return OK;                  /* this should not happen */
  /* do not forward expired hellos */
  TIME (&now);
  if ((TIME_T) ntohl (hello->expirationTime) < now)
    {
#if DEBUG_ADVERTISING
      EncName enc;
      /* remove hellos that expired */
      IF_GELOG (ectx,
                GE_INFO | GE_REQUEST | GE_USER,
                hash2enc (&peer->hashPubKey, &enc));
      GE_LOG (ectx,
              GE_INFO | GE_REQUEST | GE_USER,
              "Removing HELLO from peer `%s' (expired %ds ago).\n",
              &enc, now - ntohl (hello->expirationTime));
#endif
      identity->delHostFromKnown (peer, protocol);
      FREE (hello);
      (*probability)--;
      return OK;
    }
  if (weak_randomi ((*probability) + 1) != 0)
    {
      FREE (hello);
      return OK;                /* only forward with a certain chance,
                                   (on average: 1 peer per run!) */
    }
  count = coreAPI->forAllConnectedNodes (NULL, NULL);
  if (count > 0)
    {
      fcc.msg = hello;
      fcc.prob = count;
      coreAPI->forAllConnectedNodes (&forwardCallback, &fcc);
    }
  FREE (hello);
  return OK;
}

/**
 * Forward hellos from all known hosts to all connected hosts.
 * We do on average 1 forwarding (by random selection of
 * source and target).
 */
static void
forwardhello (void *unused)
{
  int count;

  if (os_cpu_get_load (coreAPI->ectx, coreAPI->cfg) > 100)
    return;                     /* CPU load too high... */
  if (os_network_monitor_get_load (coreAPI->load_monitor, Upload) > 100)
    return;                     /* network load too high... */
  count = identity->forEachHost (0, NULL, NULL);
  if (count > 0)
    identity->forEachHost (0,   /* ignore blacklisting */
                           &forwardhelloHelper, &count);
}

/**
 * Type for a hello send via an encrypted channel.
 */
static int
ehelloHandler (const PeerIdentity * sender, const MESSAGE_HEADER * message)
{
  if (OK == receivedhello (sender, message))
    {
      /* if the hello was ok, update traffic preference
         for the peer (depending on how much we like
         to learn about other peers) */
      coreAPI->preferTrafficFrom (sender, getConnectPriority ());
    }
  return OK;                    /* even if we had errors processing the hello, keep going */
}

/**
 * Type for a hello send in plaintext.
 */
static int
phelloHandler (const PeerIdentity * sender,
               const MESSAGE_HEADER * message, TSession * session)
{
  receivedhello (sender, message);
  return OK;
}

/**
 * The configuration has changed, update set of running cron jobs.
 * Does not have to suspend cron since this guaranteed to be a cron
 * job!
 */
static int
configurationUpdateCallback (void *ctx,
                             struct GC_Configuration *cfg,
                             struct GE_Context *ectx,
                             const char *section, const char *option)
{
  if (0 != strcmp (section, "NETWORK"))
    return 0;
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE))
    {
      if (YES == GC_get_configuration_value_yesno (cfg,
                                                   "NETWORK",
                                                   "DISABLE-ADVERTISEMENTS",
                                                   NO))
        cron_del_job (coreAPI->cron,
                      &broadcasthello, HELLO_BROADCAST_FREQUENCY, NULL);
      activeCronJobs -= ACJ_ANNOUNCE;
    }
  else
    {
      if (YES != GC_get_configuration_value_yesno (cfg,
                                                   "NETWORK",
                                                   "DISABLE-ADVERTISEMENTS",
                                                   NO))
        cron_add_job (coreAPI->cron,
                      &broadcasthello,
                      15 * cronSECONDS, HELLO_BROADCAST_FREQUENCY, NULL);
      activeCronJobs += ACJ_ANNOUNCE;
    }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD))
    {
      if (YES != GC_get_configuration_value_yesno (cfg,
                                                   "NETWORK",
                                                   "HELLOEXCHANGE", YES))
        {
          cron_del_job (coreAPI->cron, &forwardhello, HELLO_FORWARD_FREQUENCY, NULL);   /* seven minutes: exchange */
        }
      activeCronJobs -= ACJ_FORWARD;
    }
  else
    {
      if (YES == GC_get_configuration_value_yesno (cfg,
                                                   "NETWORK",
                                                   "HELLOEXCHANGE", YES))
        {
          cron_add_job (coreAPI->cron,
                        &forwardhello,
                        15 * cronSECONDS, HELLO_FORWARD_FREQUENCY, NULL);
        }
      activeCronJobs += ACJ_FORWARD;
    }
  return 0;
}

/**
 * Start advertising.
 */
int
initialize_module_advertising (CoreAPIForApplication * capi)
{
  coreAPI = capi;
  ectx = capi->ectx;
  identity = capi->requestService ("identity");
  if (identity == NULL)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  transport = capi->requestService ("transport");
  if (transport == NULL)
    {
      GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      return SYSERR;
    }
  pingpong = capi->requestService ("pingpong");
  if (pingpong == NULL)
    {
      GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      capi->releaseService (transport);
      transport = NULL;
      return SYSERR;
    }
  topology = capi->requestService ("topology");
  if (topology == NULL)
    {
      GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      capi->releaseService (transport);
      transport = NULL;
      capi->releaseService (pingpong);
      pingpong = NULL;
      return SYSERR;
    }
  stats = capi->requestService ("stats");
  if (stats != NULL)
    {
      stat_hello_in =
        stats->create (gettext_noop ("# Peer advertisements received"));
      stat_hello_nat_in =
        stats->
        create (gettext_noop ("# Peer advertisements of type NAT received"));
      stat_hello_verified =
        stats->
        create (gettext_noop ("# Peer advertisements confirmed via PONG"));
      stat_hello_update =
        stats->
        create (gettext_noop
                ("# Peer advertisements updating earlier HELLOs"));
      stat_hello_discard =
        stats->
        create (gettext_noop ("# Peer advertisements discarded due to load"));
      stat_hello_no_transport =
        stats->
        create (gettext_noop
                ("# Peer advertisements for unsupported transport"));
      stat_hello_ping_busy =
        stats->
        create (gettext_noop
                ("# Peer advertisements not confirmed due to ping busy"));
      stat_hello_noselfad =
        stats->
        create (gettext_noop
                ("# Peer advertisements not confirmed due to lack of self ad"));
      stat_hello_send_error =
        stats->
        create (gettext_noop
                ("# Peer advertisements not confirmed due to send error"));
      stat_hello_out =
        stats->create (gettext_noop ("# Self advertisments transmitted"));
      stat_hello_fwd =
        stats->create (gettext_noop ("# Foreign advertisements forwarded"));
      stat_plaintextPingSent =
        stats->create (gettext_noop ("# plaintext PING messages sent"));
    }

  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("`%s' registering handler %d (plaintext and ciphertext)\n"),
          "advertising", p2p_PROTO_hello);

  capi->registerHandler (p2p_PROTO_hello, &ehelloHandler);
  capi->registerPlaintextHandler (p2p_PROTO_hello, &phelloHandler);
  if (0 != GC_attach_change_listener (capi->cfg,
                                      &configurationUpdateCallback, NULL))
    GE_BREAK (capi->ectx, 0);
  startBootstrap (capi);
  GE_ASSERT (capi->ectx,
             0 == GC_set_configuration_value_string (capi->cfg,
                                                     capi->ectx,
                                                     "ABOUT",
                                                     "advertising",
                                                     _
                                                     ("ensures that this peer is known by other"
                                                      " peers and discovers other peers")));
  return OK;
}

/**
 * Stop advertising.
 */
void
done_module_advertising ()
{
  stopBootstrap ();
  GC_detach_change_listener (coreAPI->cfg,
                             &configurationUpdateCallback, NULL);
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE))
    {
      cron_del_job (coreAPI->cron,
                    &broadcasthello, HELLO_BROADCAST_FREQUENCY, NULL);
      activeCronJobs -= ACJ_ANNOUNCE;
    }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD))
    {
      cron_del_job (coreAPI->cron, &forwardhello, HELLO_FORWARD_FREQUENCY, NULL);       /* seven minutes: exchange */
      activeCronJobs -= ACJ_FORWARD;
    }
  coreAPI->unregisterHandler (p2p_PROTO_hello, &ehelloHandler);
  coreAPI->unregisterPlaintextHandler (p2p_PROTO_hello, &phelloHandler);
  coreAPI->releaseService (transport);
  transport = NULL;
  coreAPI->releaseService (identity);
  identity = NULL;
  coreAPI->releaseService (pingpong);
  pingpong = NULL;
  coreAPI->releaseService (topology);
  topology = NULL;
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  coreAPI = NULL;
}




/* end of advertising.c */
