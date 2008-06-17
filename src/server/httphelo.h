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
 * @author Christian Grothoff
 * @file server/httphelo.h
 **/

#ifndef HTTPHELO_H
#define HTTPHELO_H

#include "gnunet_core.h"

void initHttpHelo();
void doneHttpHelo();

/**
 * Download hostlist from the web. This method is invoked
 * when gnunetd starts and if we suddenly know no more hosts.
 **/
void downloadHostlist();

typedef void (*HELO_Callback)(HELO_Message * helo,
			      void * arg);

/**
 * Download hostlist from the web and call method
 * on each HELO.
 **/
void downloadHostlistHelper(char * url,
			    HELO_Callback callback,
			    void * arg);

/* end of httphelo.h */
#endif
