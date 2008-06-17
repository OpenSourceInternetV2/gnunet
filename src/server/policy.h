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
 * @file server/policy.h
 * @author Christian Grothoff
 **/

#ifndef POLICY_H
#define POLICY_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "platform.h"

/* ****************** functions ******************** */

void initPolicy();

void donePolicy();

/**
 * A new packet is supposed to be send out. Should it be
 * dropped because the load is too high?
 * <p>
 * @param priority the highest priority of contents in the packet
 * @return OK if the packet should be handled, SYSERR if the packet should be dropped.
 **/
int outgoingCheck(unsigned int priority);

int isWhitelisted(IPaddr ip);

#endif
/* end of policy.h */
