/*
     This file is part of GNUnet.
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
 * @file applications/fs/module/anonymity.c
 * @brief code for checking if cover traffic is sufficient
 * @author Christian Grothoff
 */

#include "platform.h"
#include "anonymity.h"
#include "gnunet_protocols.h"

/**
 * consider traffic volume before sending out content.
 * ok, so this is not 100% clean since it kind-of
 * belongs into the gap code (since it is concerned
 * with anonymity and GAP messages).  So we should
 * probably move it below the callback by passing
 * the anonymity level along.  But that would
 * require changing the DataProcessor somewhat,
 * which would also be ugly.  So to keep things
 * simple, we do the anonymity-level check for
 * outgoing content right here.
 *
 * @return OK if cover traffic is sufficient
 */
int checkCoverTraffic(Traffic_ServiceAPI * traffic,
		      unsigned int level) {
  unsigned int count;
  unsigned int peers;
  unsigned int sizes;
  unsigned int timevect;

  if (level == 0)
    return OK;
  level--;
  if (traffic == NULL)
    return SYSERR;
  if (OK != traffic->get(5 * cronSECONDS / TRAFFIC_TIME_UNIT, /* TTL_DECREMENT/TTU */
			 P2P_PROTO_gap_RESULT,
			 TC_RECEIVED,
			 &count,
			 &peers,
			 &sizes,
			 &timevect)) {
    LOG(LOG_WARNING,
	_("Failed to get traffic stats.\n"));
    return SYSERR;
  }
  if (level > 1000) {
    if (peers < level / 1000) {
      LOG(LOG_DEBUG,
	  "Not enough cover traffic to satisfy anonymity requirements (%u, %u peers). "
	  "Result dropped.\n",
	  level,
	  peers);
      return SYSERR;
    }
    if (count < level % 1000) {
      LOG(LOG_DEBUG,
	  "Not enough cover traffic to satisfy anonymity requirements (%u, %u messages). "
	  "Result dropped.\n",
	  level,
	  count);
      return SYSERR;
    }
  } else {
    if (count < level) {
      LOG(LOG_DEBUG,
	  "Not enough cover traffic to satisfy anonymity requirements (%u, %u messages). "
	  "Result dropped.\n",
	  level,
	  count);
      return SYSERR;
    }
  }
  return OK;
}
		
/* end of anonymity.c */