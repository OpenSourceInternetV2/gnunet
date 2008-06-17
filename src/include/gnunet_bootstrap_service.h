/*
     This file is part of GNUnet
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_boostrap_service.h
 * @brief API that can be used to bootstrap a GNUnet P2P network
 * @author Christian Grothoff
 */

#ifndef HTTPhello_H
#define HTTPhello_H

#include "gnunet_core.h"

/**
 * Definition of a callback function that processes
 * hello messages generated by the bootstrap API.
 */
typedef void (*hello_Callback)(const P2P_hello_MESSAGE * helo,
			       void * arg);

/**
 * @brief Definition of the bootstrap API.
 */
typedef struct {

  /**
   * Obtain hellos (i.e. by downloading form the web) and call the
   * callback on each hello.
   *
   * @param callback the method to call
   * @param arg extra argument to the method
   */
  void (*bootstrap)(hello_Callback callback,
		    void * arg);

} Bootstrap_ServiceAPI;


/* end of gnunet_bootstrap_service.h */
#endif
