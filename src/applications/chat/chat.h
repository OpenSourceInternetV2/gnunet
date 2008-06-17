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
 * @author Christian Grothoff
 * @file applications/chat/chat.h
 **/
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "gnunet_core.h"

#define CHAT_NICK_LENGTH 32
#define CHAT_MSG_LENGTH 1024

typedef struct {
  p2p_HEADER header; 
  char nick[CHAT_NICK_LENGTH];
  char message[CHAT_MSG_LENGTH];
} CHAT_p2p_MESSAGE;

typedef struct {
  CS_HEADER header;
  char nick[CHAT_NICK_LENGTH];
  char message[CHAT_MSG_LENGTH];  
} CHAT_CS_MESSAGE;


/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 **/
int initialize_chat_protocol(CoreAPIForApplication * capi);
 
void done_chat_protocol();

#endif
