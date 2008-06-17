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
 * @file server/heloexchange.c
 * @brief Cron-jobs that exchange HELOs to ensure that the network is
 * connected (nodes know of each other).
 *
 * @author Christian Grothoff
 */

#include "gnunet_util.h"

#include "heloexchange.h"
#include "keyservice.h"
#include "knownhosts.h"
#include "pingpong.h"
#include "handler.h"
#include "traffic.h"
#include "connection.h"
#include "httphelo.h"

#define HELO_BROADCAST_FREQUENCY (2 * cronMINUTES)
#define HELO_FORWARD_FREQUENCY (4 * cronMINUTES)


#define DEBUG_HELOEXCHANGE NO

/* ************* internal Methods **************** */

/**
 * Tell everybody we are there...
 */
static void broadcastHELO(void * unused);
 
/**
 * Forward HELOs from all known hosts to all known hosts.
 */
static void forwardHELO(void * unused);

#if VERBOSE_STATS
/* handles for stats */
static int stat_helo_received;
static int stat_helo_valid_received;
static int stat_helo_forwarded;
static int stat_helo_initiated;
#endif

/**
 * Meanings of the bits in activeCronJobs (ACJ).
 */
#define ACJ_NONE 0
#define ACJ_ANNOUNCE 1
#define ACJ_FORWARD 2
#define ACJ_ALL (ACJ_ANNOUNCE | ACJ_FORWARD)

/**
 * Which types of cron-jobs are currently scheduled
 * with cron?
 */
static int activeCronJobs = ACJ_NONE;

static cron_t lastHELOMsg = 0; 

/* ******************** CODE ********************* */

/**
 * Type for a HELO send via an encrypted channel.
 */
int eHELOHandler(const HostIdentity * sender,
		 const p2p_HEADER * message) {
  if (OK == receivedHELO(message)) {
    /* if the HELO was ok, update traffic preference
       for the peer (depending on how much we like
       to learn about other peers) */
    double preference;
    
    /* we should'nt give lots of bandwidth for HELOs
       if we're less than 2 peers away from the connection
       goal */
    preference = (double) getConnectPriority() / 4;
    /* see also afs/policy.h: give some decent, but compared to
       (migrated) content competitive amount of bandwidth to peers
       sending (valid) HELOs */
    if (preference < 0.4)
      preference = 0.4;
    updateTrafficPreference(sender, 
			    preference);    
  }
  return OK; /* even if we had errors processing the HELO, keep going */
}

/**
 * The configuration has changed, update set of
 * running cron jobs.  Does not have to suspend
 * cron since this guaranteed to be a cron job!
 */
static void configurationUpdateCallback() {
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE)) {
    if (testConfigurationString("NETWORK",
				"DISABLE-ADVERTISEMENTS",
				"YES")) 
      delCronJob(&broadcastHELO,
		 HELO_BROADCAST_FREQUENCY,
		 NULL); 
    activeCronJobs -= ACJ_ANNOUNCE;
  } else {
    if (testConfigurationString("NETWORK",
				"HELOEXCHANGE",
				"YES")) 
      addCronJob(&broadcastHELO,
		 15 * cronSECONDS, 
		 HELO_BROADCAST_FREQUENCY,
		 NULL); 
    activeCronJobs += ACJ_ANNOUNCE;
  }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD)) {
    if (! testConfigurationString("NETWORK",
				  "HELOEXCHANGE",
				  "YES")) 
      delCronJob(&forwardHELO,
		 HELO_FORWARD_FREQUENCY,
		 NULL); /* seven minutes: exchange */
    activeCronJobs -= ACJ_FORWARD;
  } else {
    if (! testConfigurationString("NETWORK",
				  "DISABLE-ADVERTISEMENTS",
				  "YES")) 
      addCronJob(&broadcastHELO,
		 15 * cronSECONDS, 
		 HELO_BROADCAST_FREQUENCY,
		 NULL); 
    activeCronJobs += ACJ_FORWARD;
  }
}

/**
 * Initialize a few cron jobs. Must be called after
 * initcron (!).
 */
void initHeloExchange() {
#if VERBOSE_STATS
  stat_helo_received
    = statHandle(_("# HELO messages received overall"));
  stat_helo_valid_received
    = statHandle(_("# valid HELO messages received"));
  stat_helo_forwarded
    = statHandle(_("# HELO messages forwarded from other peers"));
  stat_helo_initiated
    = statHandle(_("# HELO messages originated from this peer"));
#endif
  registerp2pHandler(p2p_PROTO_HELO,
		     &eHELOHandler);
  registerConfigurationUpdateCallback(&configurationUpdateCallback);
  if (! testConfigurationString("NETWORK",
				"DISABLE-ADVERTISEMENTS",
				"YES")) {
    addCronJob(&broadcastHELO,
	       15 * cronSECONDS, 
	       HELO_BROADCAST_FREQUENCY,
	       NULL); 
    activeCronJobs += ACJ_ANNOUNCE;
  } else
    LOG(LOG_WARNING,
	_("Network advertisements disabled by configuration!\n"));
  if (testConfigurationString("NETWORK",
			      "HELOEXCHANGE",
			      "YES") == YES) {
    addCronJob(&forwardHELO,
	       4 * cronMINUTES, /* see connection.c: SECONDS_INACTIVE_DROP */
	       HELO_FORWARD_FREQUENCY,
	       NULL); 
    activeCronJobs += ACJ_FORWARD;
  }
#if DEBUG_HELOEXCHANGE
  else
    LOG(LOG_DEBUG, 
	"HELO forwarding disabled!\n");
#endif
}

/**
 * Stops a few cron jobs that exchange HELOs.
 */
void doneHeloExchange() {
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE)) {
    delCronJob(&broadcastHELO,
	       HELO_BROADCAST_FREQUENCY,
	       NULL); 
    activeCronJobs -= ACJ_ANNOUNCE;
  }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD)) {
    delCronJob(&forwardHELO,
	       HELO_FORWARD_FREQUENCY,
	       NULL); /* seven minutes: exchange */
    activeCronJobs -= ACJ_FORWARD;
  }
  unregisterConfigurationUpdateCallback(&configurationUpdateCallback);
}



/**
 * We have received a HELO.  Verify (signature, integrity,
 * ping-pong) and store identity if ok.
 *
 * @param message the HELO message
 * @return SYSERR on error, OK on success
 */
int receivedHELO(const p2p_HEADER * message) {
  TSession * tsession;
  HELO_Message * copy;
  HostIdentity foreignId;
  HELO_Message * msg;
  char * buffer;    
  int heloEnd;
  int mtu;
  int res;
  cron_t now;

  /* first verify that it is actually a valid HELO */
  msg = (HELO_Message* ) message;
#if VERBOSE_STATS
  statChange(stat_helo_received, 1);
#endif
  if (ntohs(msg->header.size) != HELO_Message_size(msg))
    return SYSERR;
  getHostIdentity(&msg->publicKey,
		  &foreignId);
  if (!equalsHashCode160(&msg->senderIdentity.hashPubKey,
			 &foreignId.hashPubKey))
    return SYSERR; /* public key and host hash do not match */
  if (SYSERR == verifySig(&msg->senderIdentity,
			  HELO_Message_size(msg) 
			  - sizeof(Signature) 
			  - sizeof(PublicKey) 
			  - sizeof(p2p_HEADER),
			  &msg->signature,
			  &msg->publicKey)) {
    EncName enc;
    IFLOG(LOG_WARNING,
	  hash2enc(&msg->senderIdentity.hashPubKey,
		   &enc));
    LOG(LOG_WARNING, 
	_("HELO message from '%s' invalid (signature invalid). Dropping.\n"),
	(char*)&enc);
    return SYSERR; /* message invalid */  
  }
  if ((TIME_T)ntohl(msg->expirationTime) > TIME(NULL) + MAX_HELO_EXPIRES) {
     LOG(LOG_WARNING, 
	 _("HELO message received invalid (expiration time over limit). Dropping.\n"));   
    return SYSERR;
  }
  if (SYSERR == transportVerifyHelo(msg)) 
    return OK; /* not good, but do process rest of message */ 
  
#if VERBOSE_STATS
  statChange(stat_helo_valid_received, 1);
#endif
#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("HELO advertisement for protocol %d received.\n"),
      ntohs(msg->protocol));
#endif
  if (ntohs(msg->protocol) == NAT_PROTOCOL_NUMBER) {
    /* We *can* not verify NAT.  Ever.  So all we
       can do is just accept it.  The best thing
       that we may do is check that it was not
       forwarded by another peer (forwarding NAT
       advertisements is invalid), but even that
       check can not be done securely (since we
       have to accept HELOs in plaintext).  Thus
       we take NAT advertisements at face value
       (which is OK since we never attempt to
       connect to a NAT). */
    bindAddress(msg);
    return OK;
  }

  /* Then check if we have seen this HELO before, if it is identical
     except for the TTL, we trust it and do not play PING-PONG */
  if (OK == identity2Helo(&foreignId,
			  ntohs(msg->protocol),
			  NO,
			  &copy) ) {
    if ( (ntohs(copy->senderAddressSize) ==
	  ntohs(msg->senderAddressSize)) &&
	 (0 == memcmp(&msg->senderAddressSize,
		      &copy->senderAddressSize,
		      sizeof(unsigned short)*2+
		      sizeof(unsigned int) + 
		      ntohs(copy->senderAddressSize)) ) ) {
      /* ok, we've seen this one exactly like this before (at most the
	 TTL has changed); thus we can 'trust' it without playing
	 ping-pong */
      bindAddress(msg);
      FREE(copy);
      return OK;
    } else {
#if DEBUG_HELOEXCHANGE
      LOG(LOG_DEBUG,
	  "advertised HELO differs from prior knowledge,"
	  " requireing ping-pong confirmation.\n");
      LOG(LOG_EVERYTHING,
	  "HELO-diff: %d -- %d, %d -- %d, %d -- %d, %d -- %d\n",
	  msg->senderAddressSize,
	  copy->senderAddressSize,
	  msg->protocol,
	  copy->protocol,
	  msg->MTU,
	  copy->MTU,
	  *(int*)&msg->senderAddress,
	  *(int*)&copy->senderAddress);
#endif
    }
    FREE(copy);
  }

  if (testConfigurationString("GNUNETD",
			      "PRIVATE-NETWORK",
			      "YES")) {
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
    return SYSERR; 
  }

  cronTime(&now);
  if ( (now - lastHELOMsg) *
       getConfigurationInt("LOAD",
			   "MAXNETDOWNBPSTOTAL") /
       cronSECONDS / 100
       < HELO_Message_size(msg) ) {
    /* do not use more than about 1% of the 
       available bandwidth to VERIFY HELOs (by sending
       our own with a PING).  This does not affect
       the HELO advertising.  Sure, we should not
       advertise much more than what other peers
       can verify, but the problem is that buggy/
       malicious peers can spam us with HELOs, and
       we don't want to follow that up with massive
       HELO-ing by ourselves. */
    return SYSERR;
  }
  lastHELOMsg = now;

  /* Ok, must play PING-PONG. Add the HELO to the temporary
     (in-memory only) buffer to make it available for a short
     time in order to play PING-PONG */
  copy = MALLOC(HELO_Message_size(msg));
  memcpy(copy,
	 msg,
	 HELO_Message_size(msg));
  addTemporaryHost(copy);
  

  /* Establish session as advertised in the HELO */
  copy = MALLOC(HELO_Message_size(msg));
  memcpy(copy,
	 msg,
	 HELO_Message_size(msg));
  if (SYSERR == transportConnect(copy, /* copy is freed by callee,
					  except on SYSERR! */
				 &tsession)) {
    FREE(copy);
    return SYSERR; /* could not connect */
  }    

  /* build message to send, ping must contain return-information,
     such as a selection of our HELOs... */
  mtu = transportGetMTU(tsession->ttype);
  buffer = MALLOC(mtu);
  heloEnd = getAdvertisedHELOs(mtu - sizeof(PINGPONG_Message),
			       buffer);
  if (heloEnd == -1) {
    LOG(LOG_WARNING,
	"'%s' failed. Will not send PING.\n",
	"getAdvertisedHELOs");
    FREE(buffer);
    transportDisconnect(tsession);    
    return SYSERR;
  }
  copy = MALLOC(HELO_Message_size(msg));
  memcpy(copy,
	 msg,
	 HELO_Message_size(msg));
  res = OK;
  if (SYSERR == pingAction(&msg->senderIdentity,
			   (CronJob)&bindAddress,
			   copy,
			   (PINGPONG_Message*)&buffer[heloEnd])) {
    FREE(copy);
    res = SYSERR;
    LOG(LOG_INFO,
	_("Could not send HELOs+PING, ping buffer full.\n"));
  }
  /* ok, finally we can send! */
  if (res == OK) {
    if (SYSERR == transportSend(tsession,
				buffer,
				heloEnd + sizeof(PINGPONG_Message),
				NO, /* not encrypted */
				crc32N(buffer, 
				       heloEnd 
				       + sizeof(PINGPONG_Message)))) {
      res = SYSERR;
    } else {
      updateTrafficSendCounter(p2p_PROTO_HELO,
			       heloEnd);    
      updateTrafficSendCounter(p2p_PROTO_PING,
			       sizeof(PINGPONG_Message));
    }
  }
  FREE(buffer);
  if (SYSERR == transportDisconnect(tsession))
    res = SYSERR;
  return res;
}

typedef struct {
  /* the CRC of the message */
  int crc;
  /* the HELO message */
  HELO_Message * m;
  /* send the HELO in 1 out of n cases */
  int n;
} SendData;

static void broadcastHelper(const HostIdentity * hi,
			    const unsigned short proto,
			    SendData * sd) {
  HELO_Message * helo;
  TSession * tsession;
  EncName other;
  int prio;

  if (proto == NAT_PROTOCOL_NUMBER)
    return; /* don't advertise NAT addresses via broadcast */
  if (randomi(sd->n) != 0) 
    return;
  hash2enc(&hi->hashPubKey,
	   &other);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_DEBUG,
      "Entering '%s' with target '%s'.\n",
      __FUNCTION__,
      &other);
#endif
  if (hostIdentityEquals(hi,
			 &myIdentity))
    return; /* never advertise to myself... */
  prio = getConnectPriority();
  if (prio >= EXTREME_PRIORITY)
    prio = EXTREME_PRIORITY / 4;
  if (YES == isConnected(hi)) {
    sendToNode(hi,
	       &sd->m->header,
	       prio,
	       HELO_BROADCAST_FREQUENCY);
#if VERBOSE_STATS
    statChange(stat_helo_initiated, 1);
#endif
    return;
  }
  /* with even lower probability (with n peers
     trying to contact with a probability of 1/n^2,
     we get a probability of 1/n for this, which
     is what we want: fewer attempts to contact fresh
     peers as the network grows): */
  if (randomi(sd->n) != 0)
    return;
  if (SYSERR == outgoingCheck(prio))
    return; /* peer too busy */

  /* establish short-lived connection, send, tear down */
  if (SYSERR == identity2Helo(hi,
			      proto,
			      NO,
			      &helo)) {
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG,
	"Exit from '%s' (error: '%s' failed).\n",
	__FUNCTION__,
	"identity2Helo");
#endif
    return;
  }
  if (SYSERR == transportConnect(helo, /* helo is freed by callee,
					  except on SYSERR! */
				 &tsession)) {
    FREE(helo);
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG,
	"Exit from '%s' (%s error).\n",
	__FUNCTION__,
	"transportConnect");
#endif
    return; /* could not connect */
  }
  if (OK == transportSend(tsession,
			  &sd->m->header,
			  HELO_Message_size(sd->m),
			  NO, /* not encrypted */
			  sd->crc)) {
    updateTrafficSendCounter(p2p_PROTO_HELO,
			     HELO_Message_size(sd->m));
  }
#if VERBOSE_STATS
  statChange(stat_helo_initiated, 1);
#endif
  transportDisconnect(tsession);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_DEBUG,
      "Exit from %s.\n",
      __FUNCTION__);
#endif
 }

/**
 * Tell a couple of random hosts on the currentKnownHost list 
 * that we exist (called for each transport)...
 */
static void broadcastHELOTransport(TransportAPI * tapi,
				   void * unused) {
  SendData sd;
  cron_t now;

#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Enter '%s'.\n",
      __FUNCTION__);
#endif
  cronTime(&now);
  sd.n = forEachHost(NULL, 
		     now, 
		     NULL); /* just count */
  if (SYSERR == transportCreateHELO(tapi->protocolNumber,
				    &sd.m))
    return;
#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("Advertising my transport %d to selected peers.\n"),
      tapi->protocolNumber);
#endif
  bindAddress(sd.m);
  if (sd.n < 1) {
    LOG(LOG_WARNING,
	_("Announcing ourselves pointless: no other peers are known to us so far.\n"));
    FREE(sd.m);
    return; /* no point in trying... */
  }
  sd.crc = crc32N(sd.m, 
		  HELO_Message_size(sd.m));

  forEachHost((HostIterator)&broadcastHelper,
	      now, 
	      &sd);
  FREE(sd.m);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Exit '%s'.\n",
      __FUNCTION__);
#endif
}

/**
 * Tell a couple of random hosts on the currentKnownHost list 
 * that we exist...
 */
static void broadcastHELO(void * unused) {
  forEachTransport(&broadcastHELOTransport,
		   NULL);
}


/**
 * Forward HELOs from all known hosts to all connected hosts.
 */
static void forwardHELOHelper(const HostIdentity * identity,
			      const unsigned short protocol,
			      int * probability) {
  HELO_Message * helo;
  TIME_T now;
  int count;

  if (protocol == NAT_PROTOCOL_NUMBER)
    return; /* don't forward NAT addresses */
  if (randomi((*probability)+1) != 0)
    return; /* only forward with a certain chance,
	       (on average: 1 peer per run!) */
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "forwarding HELOs\n");
#endif
  if (SYSERR == identity2Helo(identity,
			      protocol,
			      NO,
			      &helo))
    return; /* this should not happen */
  helo->header.requestType 
    = htons(p2p_PROTO_HELO); 
  helo->header.size
    = htons(HELO_Message_size(helo));
  /* do not forward expired HELOs */
  TIME(&now);
  if ((TIME_T)ntohl(helo->expirationTime) < now) {
    EncName enc;
    /* remove HELOs that expired */ 
    IFLOG(LOG_INFO,
	  hash2enc(&identity->hashPubKey,
		   &enc));
    LOG(LOG_INFO,
	_("Removing HELO from peer '%s' (expired %ds ago).\n"),
	&enc,
	now - ntohl(helo->expirationTime));
    delHostFromKnown(identity, protocol);
    FREE(helo);
    return;
  }
  count = forEachConnectedNode(NULL, 
			       NULL);
#if VERBOSE_STATS
  statChange(stat_helo_forwarded, 
	     count);
#endif
  if (count == 0)
    count = 1; /* avoid division by 0 */
  broadcast(&helo->header, 
	    0,  /* priority: 0 */
	    ((*probability) / count)
	    * HELO_BROADCAST_FREQUENCY);  /* send before the next round... */
  FREE(helo);
}

/**
 * Forward HELOs from all known hosts to all connected hosts.
 */
static void forwardHELO(void * unused) {
  int count;
  int conn;

#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Enter '%s'.\n",
      __FUNCTION__);
#endif
  count = forEachHost(NULL, 
		      0, 
		      NULL);  
  conn = forEachConnectedNode(NULL, 
			      NULL);
  count = count * conn; /* reduce to 1 message on average for each
			   period; yes, we get always a bunch at a 
			   time, but that's ok */
  forEachHost((HostIterator)&forwardHELOHelper,
	      0, /* ignore blacklisting */
	      &count);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Exit '%s'.\n",
      __FUNCTION__);
#endif
}

/* end of heloexchange.c */
