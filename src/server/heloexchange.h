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
 * Cron-jobs exchanging routing information (HELOs messages)
 * @author Christian Grothoff
 * @file server/heloexchange.h
 **/

#ifndef HELOEXCHANGE_H
#define HELOEXCHANGE_H

#include "gnunet_core.h"

/**
 * initialize a few cron jobs. Must be called after
 * initcron (!).
 **/
void initHeloExchange();

/**
 * Stops a few cron jobs that exchange HELOs.
 **/
void doneHeloExchange();

/**
 * We have received a HELO. Verify (signature, integrity,
 * ping-pong) and store identity if ok & protocol supported.
 **/
int receivedHELO(p2p_HEADER * message);
 
/**
 * How long may a HELO be valid (in seconds). We use 10 days, do not
 * change (would break compatibility with peers that have a different
 * limit).
 **/
#define MAX_HELO_EXPIRES (60 * 60 * 24 * 10)

/* end of heloexchange.h */
#endif
