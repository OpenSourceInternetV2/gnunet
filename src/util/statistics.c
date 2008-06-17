/*
  This file is part of GNUnet.
  (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file util/statistics.c
 * @brief keeping statistics of GNUnet activities
 * @author Christian Grothoff
 *
 * This module keeps a mapping of strings to (unsigned long long)
 * values. Every entry in the mapping can be accessed with a handle
 * (int) which can be obtained from the string. The module can be used
 * to keep track of certain statistical information, such as the
 * number of bytes received, messages sent, kilobytes stored, and so
 * on.<p>
 *
 * When used within gnunetd, the gnunet-stats tool can be used to
 * print the statistical information stored in this module.
 **/

#include "gnunet_util.h"
#include "platform.h"

/* ***************** global statistics ***************** */

/**
 * When did the module start? 
 **/
static cron_t startTime;

/**
 * How many values do we keep statistics for? 
 **/
static unsigned int statCounters = 0;

/**
 * What are these values (value) 
 **/
static unsigned long long * values = NULL;

/**
 * A description for each of the values 
 **/
static char ** descriptions = NULL;

/**
 * lock for the stat module 
 **/
static Mutex statLock;

/**
 * Initialize the statistics module.
 **/
void initStatistics() {
  cronTime(&startTime);
  MUTEX_CREATE_RECURSIVE(&statLock);
}

/**
 * Shutdown the statistics module.
 **/
void doneStatistics() {
  int i;

  MUTEX_DESTROY(&statLock);
  for (i=0;i<statCounters;i++)
    FREE(descriptions[i]);
  FREENONNULL(descriptions);
  FREENONNULL(values);
  descriptions = NULL;
  values = NULL;
}

/**
 * Get a handle to a statistical entity.
 *
 * @param name a description of the entity
 * @return a handle for updating the associated value
 **/
int statHandle(char * name) {
  int i;
  if (name == NULL)
    errexit("statHandle called with name being NULL\n");
  MUTEX_LOCK(&statLock);
  for (i=0;i<statCounters;i++)
    if (0 == strcmp(descriptions[i], name)) {
      MUTEX_UNLOCK(&statLock);
      return i;
    }

  GROW(values,
       statCounters,
       statCounters+1);
  statCounters--;
  GROW(descriptions,
       statCounters,
       statCounters+1);
  descriptions[statCounters-1] = STRDUP(name);
  MUTEX_UNLOCK(&statLock);   
  return statCounters-1;
}

/**
 * Manipulate statistics. Sets the statistics associated with the
 * handle to value.
 *
 * @param handle the handle for the value to change
 * @param value to what the value should be set
 **/
void statSet(const int handle,
	     const unsigned long long value) {
  MUTEX_LOCK(&statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    LOG(LOG_WARNING,
	"WARNING: invalid call to statSet, h=%d, statC=%d!\n",
	handle,
	statCounters);
    MUTEX_UNLOCK(&statLock);
    return;
  }
  values[handle] = value;
  MUTEX_UNLOCK(&statLock);
}

/**
 * Manipulate statistics. Changes the statistics associated with the
 * value by delta.
 *
 * @param handle the handle for the value to change
 * @param delta by how much should the value be changed
 **/
void statChange(const int handle,
		const int delta) {
  MUTEX_LOCK(&statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    LOG(LOG_WARNING,
	"WARNING: invalid call to statChange, h=%d, statC=%d!\n",
	handle,
	statCounters);
    MUTEX_UNLOCK(&statLock);
    return;
  }
  values[handle] += delta;
  MUTEX_UNLOCK(&statLock);
}

/**
 * Send statistics to a TCP socket.
 * May send multiple messages if the overall size
 * would be too big otherwise.
 **/
int sendStatistics(ClientHandle sock,
		   CS_HEADER * message,
		   SendToClientCallback callback) {
  STATS_CS_MESSAGE * statMsg;
  int pos; /* position in the values-descriptions */
  int start;
  int end;
  int mpos; /* postion in the message */
  
  statMsg = (STATS_CS_MESSAGE*)MALLOC(MAX_BUFFER_SIZE);
  statMsg->header.tcpType 
    = htons(STATS_CS_PROTO_STATISTICS);
  statMsg->totalCounters 
    = htonl(statCounters);
  statMsg->statCounters 
    = htons(0);
  statMsg->startTime 
    = htonll(startTime);
  
  start = 0;  
  while (start < statCounters) {
    pos = start;
    /* first pass: gauge how many statistic numbers
       and their descriptions we can send in one message */
    mpos = 0;
    while ( (pos < statCounters) &&
	    (mpos + sizeof(unsigned long long) 
	     + strlen(descriptions[pos]) + 1
	     < MAX_BUFFER_SIZE - sizeof(STATS_CS_MESSAGE)) ) {
      mpos += sizeof(unsigned long long); /* value */
      mpos += strlen(descriptions[pos])+1;
      pos++;
    }
    end = pos;
    /* second pass: copy values and messages to message */
    for (pos=start;pos<end;pos++)
      ((STATS_CS_MESSAGE_GENERIC*)statMsg)->values[pos-start] = htonll(values[pos]);
    mpos = sizeof(unsigned long long) * (end - start);
    for (pos=start;pos<end;pos++) {
      strcpy(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg))->values)[mpos],
	     descriptions[pos]);
      mpos += strlen(descriptions[pos])+1;
    }
    statMsg->statCounters = htonl(end - start);
    statMsg->header.size = htons(mpos + sizeof(STATS_CS_MESSAGE));
    /* printf("writing message of size %d with stats %d to %d out of %d to socket\n",
       ntohs(statMsg->header.size),
       start, end, statCounters);*/
    if (SYSERR == callback(sock,
			   &statMsg->header))
      break; /* abort, socket error! */
    start = end;
  }
  FREE(statMsg);
  return OK;
}

/* end of statistics.c */
