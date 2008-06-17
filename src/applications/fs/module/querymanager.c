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
 * @file applications/fs/module/querymanager.c
 * @brief forwarding of queries
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_core.h"
#include "fs.h"
#include "querymanager.h"

#define DEBUG_QUERYMANAGER NO

typedef struct {
  HashCode512 query;
  unsigned int type;
  ClientHandle client;
} TrackRecord;

/**
 * Array of the queries we are currently sending out.
 */
static TrackRecord ** trackers;

static unsigned int trackerCount;
static unsigned int trackerSize;

/**
 * Mutex for all query manager structures.
 */
static Mutex queryManagerLock;

static CoreAPIForApplication * coreAPI;

static void removeEntry(unsigned int off) {
  GNUNET_ASSERT(off < trackerCount);
  FREE(trackers[off]);
  trackers[off] = trackers[--trackerCount];
  trackers[trackerCount] = NULL;
  if ( (trackerSize > 64) &&
       (trackerSize > 2 * trackerCount) )
    GROW(trackers, trackerSize, trackerSize / 2);
}

static void ceh(ClientHandle client) {
  int i;
  MUTEX_LOCK(&queryManagerLock);
  for (i=trackerCount-1;i>=0;i--)
    if (trackers[i]->client == client)
      removeEntry(i);
  MUTEX_UNLOCK(&queryManagerLock);
}

/**
 * Keep track of a query.  If a matching response
 * shows up, transmit the response to the client.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void trackQuery(const HashCode512 * query,
		unsigned int type,
		const ClientHandle client) {
  int i;

  GNUNET_ASSERT(client != NULL);
  MUTEX_LOCK(&queryManagerLock);
  for (i=trackerCount-1;i>=0;i--)
    if ( (trackers[i]->client == client) &&
	 (equalsHashCode512(&trackers[i]->query,
			    query)) ) {
      MUTEX_UNLOCK(&queryManagerLock);
      return;
    }
  if (trackerSize == trackerCount)
    GROW(trackers,
	 trackerSize,
	 trackerSize * 2);
  trackers[trackerCount] = MALLOC(sizeof(TrackRecord));
  trackers[trackerCount]->query = *query;
  trackers[trackerCount]->type = type;
  trackers[trackerCount]->client = client;
  trackerCount++;
  MUTEX_UNLOCK(&queryManagerLock);
}

/**
 * Stop keeping track of a query.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void untrackQuery(const HashCode512 * query,
		  const ClientHandle client) {
  int i;

  MUTEX_LOCK(&queryManagerLock);
  for (i=trackerCount-1;i>=0;i--)
    if ( (trackers[i]->client == client) &&
	 (equalsHashCode512(&trackers[i]->query,
			    query)) ) {
      removeEntry(i);
      MUTEX_UNLOCK(&queryManagerLock);
      return;
    }
  MUTEX_UNLOCK(&queryManagerLock);
}

/**
 * We received a reply from 'responder'.
 * Forward to client (if appropriate).
 *
 * @param value the response
 */
void processResponse(const HashCode512 * key,
		     const Datastore_Value * value) {
  int i;
  CS_fs_reply_content_MESSAGE * rc;
  unsigned int matchCount;

  GNUNET_ASSERT(ntohl(value->size) > sizeof(Datastore_Value));
  matchCount = 0;
  MUTEX_LOCK(&queryManagerLock);
  for (i=trackerCount-1;i>=0;i--) {
    if ( (equalsHashCode512(&trackers[i]->query,
			    key)) &&
	 ( (trackers[i]->type == ANY_BLOCK) ||
	   (trackers[i]->type == ntohl(value->type)) ) ) {
      matchCount++;
      rc = MALLOC(sizeof(CS_fs_reply_content_MESSAGE) +
		  ntohl(value->size) - sizeof(Datastore_Value));
      rc->header.size = htons(sizeof(CS_fs_reply_content_MESSAGE) +
			      ntohl(value->size) - sizeof(Datastore_Value));
      rc->header.type = htons(CS_PROTO_gap_RESULT);
      memcpy(&rc[1],
	     &value[1],
	     ntohl(value->size) - sizeof(Datastore_Value));
#if DEBUG_QUERYMANAGER
      LOG(LOG_DEBUG,
	  "Sending reply to client waiting in slot %u.\n",
	  i);
#endif
      coreAPI->sendToClient(trackers[i]->client,
			    &rc->header);
      FREE(rc);
    }
  }
#if DEBUG_QUERYMANAGER
  if (matchCount == 0) {
    EncName enc;

    IFLOG(LOG_DEBUG,
	  hash2enc(key,
		   &enc));
    LOG(LOG_DEBUG,
	"Reply `%s' did not match any request.\n",
	&enc);
  }
#endif
  MUTEX_UNLOCK(&queryManagerLock);
}

/**
 * Initialize the query management.
 */
int initQueryManager(CoreAPIForApplication * capi) {
  coreAPI = capi;
  capi->registerClientExitHandler(&ceh);
  GROW(trackers,
       trackerSize,
       64);
  MUTEX_CREATE(&queryManagerLock);
  return OK;
}

void doneQueryManager() {
  int i;
  for (i=trackerCount-1;i>=0;i--)
    FREE(trackers[i]);
  GROW(trackers,
       trackerSize,
       0);
  trackerCount = 0;
  coreAPI->unregisterClientExitHandler(&ceh);
  MUTEX_DESTROY(&queryManagerLock);
  coreAPI = NULL;
}

/* end of querymanager.c */
