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
 * CHAT CORE. This is the code that is plugged
 * into the GNUnet core to enable chatting.
 *
 * @author Christian Grothoff
 * @file applications/chat/chat.c
 */

#include "chat.h"
#include "platform.h"

static CoreAPIForApplication * coreAPI = NULL;

#define MAX_LAST_MESSAGES 12
#define MAX_CLIENTS 4

static ClientHandle clients[MAX_CLIENTS];
static int clientCount;
static HashCode160 lastMsgs[MAX_LAST_MESSAGES];
static int ringIndex;
static Mutex chatMutex;

static void markSeen(HashCode160 * hc) {
  if (++ringIndex >= MAX_LAST_MESSAGES)
    ringIndex = 0;
  memcpy(&lastMsgs[ringIndex], 
	 hc, 
	 sizeof(HashCode160));
}

static int handleChatMSG(const HostIdentity * sender,
			 const p2p_HEADER * message) {
  int i;
  int j;
  CHAT_CS_MESSAGE * cmsg;
  CHAT_p2p_MESSAGE * pmsg;
  HashCode160 hc;

  if (ntohs(message->size) != sizeof(CHAT_p2p_MESSAGE)) {
    LOG(LOG_WARNING,
	_("Message received from peer is invalid.\n"));
    return SYSERR;
  }
  pmsg = (CHAT_p2p_MESSAGE*)message;
  cmsg = (CHAT_CS_MESSAGE*) message;

  /* check if we have seen this message already */
  hash(pmsg,
       sizeof(CHAT_p2p_MESSAGE),
       &hc);
  j = -1;
  MUTEX_LOCK(&chatMutex);
  for (i=0;i<MAX_LAST_MESSAGES;i++)
    if (equalsHashCode160(&hc, &lastMsgs[i]))
      j = i;
  if (j == -1) { 
    /* we have not seen it before, send to all TCP clients
       and broadcast to all peers */
    markSeen(&hc); 
    for (j=0;j<clientCount;j++)
      coreAPI->sendToClient(clients[j],
		    &cmsg->header);
    coreAPI->broadcastToConnected(message, 5, 1);
    pmsg->nick[CHAT_NICK_LENGTH-1] = '\0'; 
    pmsg->message[CHAT_MSG_LENGTH-1] = '\0';
    /*
    LOG(LOG_DEBUG,
	" CHAT: received new message from %s: %s\n",
	&pmsg->nick[0],
	&pmsg->message[0]);
    */
  }
  MUTEX_UNLOCK(&chatMutex);
  return OK;
}

static void csHandleChatRequest(ClientHandle client,
				const CS_HEADER * message) {
  int i;
  int j;
  CHAT_CS_MESSAGE * cmsg;
  CHAT_p2p_MESSAGE * pmsg;
  HashCode160 hc;

  if (ntohs(message->size) != sizeof(CHAT_CS_MESSAGE)) {
    LOG(LOG_WARNING,
	_("Message received from client is invalid\n"));
    return; /* invalid message */
  }
  pmsg = (CHAT_p2p_MESSAGE*)message;
  cmsg = (CHAT_CS_MESSAGE*) message;
  hash(pmsg,
       sizeof(CHAT_p2p_MESSAGE),
       &hc);
  MUTEX_LOCK(&chatMutex);
  markSeen(&hc);

  /* forward to all other TCP chat clients */
  j = -1; /* marker to check if this is a new client */
  for (i=0;i<clientCount;i++)
    if (clients[i] == client) 
      j = i;
    else 
      coreAPI->sendToClient(clients[i],
		    message);
  if (j == -1) {
    if (clientCount == MAX_CLIENTS)
      LOG(LOG_WARNING,
	  _("Maximum number of chat clients reached.\n"));
    else {
      clients[clientCount++] = client;
      LOG(LOG_DEBUG,
	  _("Now %d of %d chat clients at this node.\n"),
	  clientCount, MAX_CLIENTS);
    }
  }
  /* forward to all other nodes in the network */
  coreAPI->broadcastToConnected(&pmsg->header, 5, 1);
  MUTEX_UNLOCK(&chatMutex);
}

static void chatClientExitHandler(ClientHandle client) {
  int i;
  MUTEX_LOCK(&chatMutex);
  for (i=0;i<clientCount;i++)
    if (clients[i] == client) {
      LOG(LOG_DEBUG,
	  "Chat client exits.\n");
      clients[i] = clients[--clientCount];
      break;
    }
  MUTEX_UNLOCK(&chatMutex);
}

/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 */
int initialize_chat_protocol(CoreAPIForApplication * capi) {
  int ok = OK;

  GNUNET_ASSERT(CHAT_p2p_PROTO_MSG == CHAT_CS_PROTO_MSG);
  GNUNET_ASSERT(sizeof(CHAT_p2p_MESSAGE) == sizeof(CHAT_CS_MESSAGE));
  MUTEX_CREATE(&chatMutex);
  clientCount = 0;
  coreAPI = capi;
  LOG(LOG_DEBUG,
      "CHAT registering handlers %d and %d\n",
      CHAT_p2p_PROTO_MSG,
      CHAT_CS_PROTO_MSG);

  if (SYSERR == capi->registerHandler(CHAT_p2p_PROTO_MSG,
				      &handleChatMSG))
    ok = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&chatClientExitHandler))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(CHAT_CS_PROTO_MSG,
					    (CSHandler)&csHandleChatRequest))
    ok = SYSERR;
  return ok;
}

void done_chat_protocol() {
  coreAPI->unregisterHandler(CHAT_p2p_PROTO_MSG,
			   &handleChatMSG);
  coreAPI->unregisterClientExitHandler(&chatClientExitHandler);
  coreAPI->unregisterClientHandler(CHAT_CS_PROTO_MSG,
				   (CSHandler)&csHandleChatRequest);
  MUTEX_DESTROY(&chatMutex);
  coreAPI = NULL;
}

/* end of afs.c */
