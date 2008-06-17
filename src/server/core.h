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
 * @file server/core.h
 * @brief Implementation of the APIs to the GNUnet core
 * @author Christian Grothoff
 **/

#ifndef CORE_H
#define CORE_H

/**
 * Initialize the CORE's globals.
 **/
void initCore();

/**
 * Shutdown the CORE modules (also shuts down all
 * application modules).
 **/
void doneCore();

CoreAPIForTransport * getCoreAPIForTransport();

CoreAPIForApplication * getCoreAPIForApplication();

void loadApplicationModules();

/**
 * Processing of a message from the transport layer
 * (receive implementation).
 */
void core_receive(MessagePack * mp);

#endif
