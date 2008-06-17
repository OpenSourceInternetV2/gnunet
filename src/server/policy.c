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
 * @file server/policy.c
 * @brief bandwidth allocation code for outbound messages
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "policy.h"

#define DEBUG_POLICY NO

/**
 * Various statistic handles 
 **/
static int stat_outgoing_ok;
static int stat_outgoing_drop;

/**
 * Configuration...
 **/
static CIDRNetwork * trustedNetworks_ = NULL;

/**
 * Initialize the policy module.
 **/
void initPolicy() {
  char * ch;

  ch = getConfigurationString("NETWORK",
			      "TRUSTED");
  if (ch == NULL) {
    trustedNetworks_ = parseRoutes("127.0.0.0/8;"); /* by default, trust localhost only */
  } else {
    trustedNetworks_ = parseRoutes(ch);    
    if (trustedNetworks_ == NULL) 
      errexit("Malformed entry in the configuration in section %s under %s: %s\n",
	      "NETWORK",
	      "TRUSTED", 
	      ch); 
    FREE(ch);
  }
  stat_outgoing_ok
    = statHandle("# times outgoing msg sent (bandwidth ok)");
  stat_outgoing_drop
    = statHandle("# times outgoing msg deferred (bandwidth stressed)");
  statSet(stat_outgoing_ok, 0);
  statSet(stat_outgoing_drop, 0);
}

void donePolicy() {
  FREE(trustedNetworks_);
}

/**
 * A new packet is supposed to be send out. Should it be
 * dropped because the load is too high?
 * <p>
 * @param priority the highest priority of contents in the packet
 * @return OK if the packet should be handled, SYSERR if the packet should be dropped.
 **/
int outgoingCheck(unsigned int priority) {
  int load;
  unsigned int delta;

  load = getNetworkLoadUp(); /* how much free bandwidth do we have? */
  if (load >= 150) {
    statChange(stat_outgoing_drop, 1);
    return SYSERR; /* => always drop */
  }
  if (load > 100) { 
    if (priority >= EXTREME_PRIORITY) {
      statChange(stat_outgoing_ok, 1);  
      return OK; /* allow administrative msgs */
    } else {
      statChange(stat_outgoing_drop, 1);
      return SYSERR; /* but nothing else */
    }
  }
  if (load <= 50) { /* everything goes */
    statChange(stat_outgoing_ok, 1);  
    return OK; /* allow */
  }
  /* Now load in [51, 100].  Between 51% and 100% load:
     at 51% require priority >= 1 = (load-50)^3
     at 52% require priority >= 8 = (load-50)^3
     at 75% require priority >= 15626 = (load-50)^3
     at 100% require priority >= 125000 = (load-50)^3
     (cubic function)
  */ 
  delta = load - 50; /* now delta is in [1,50] with 50 == 100% load */
  if (delta * delta * delta > priority ) {
#if DEBUG_POLICY 
    LOG(LOG_DEBUG, 
	"DEBUG: network load too high (%d%%, priority is %u, require %d), "
	"dropping outgoing.\n",
	load,
	priority,
	delta * delta * delta);
#endif
    statChange(stat_outgoing_drop, 1);
    return SYSERR; /* drop */
  } else {
#if DEBUG_POLICY
    LOG(LOG_DEBUG, 
	"DEBUG: network load ok (%d%%, priority is %u >= %d), "
	"sending outgoing.\n",
	load,
	priority,
	delta * delta * delta);
#endif
    statChange(stat_outgoing_ok, 1);  
    return OK; /* allow */
  }
}

/**
 * Is this IP labeled as trusted for CS connections?
 **/
int isWhitelisted(IPaddr ip) {
  return checkIPListed(trustedNetworks_,
		       ip);
}

/* end of policy.c */

