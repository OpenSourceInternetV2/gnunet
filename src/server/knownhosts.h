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
 * @file server/knownhosts.h
 * @brief Code to maintain the list of currently known hosts
 * (in memory structure of data/hosts) and temporary blacklisting
 * information.
 * @author Christian Grothoff
 **/ 

#ifndef KNOWNHOSTS_H
#define KNOWNHOSTS_H

#include "gnunet_util.h"
#include "transport.h"

/* ********************** Exported globals ******************************* */

extern HostIdentity myIdentity;

/* **************** prototypes ****************** */

/**
 * Type of an iterator over all hosts.
 * @param identity the identity of the host
 * @param protocol the available protocol
 * @param data the data-argument passed to forEachHost
 **/
typedef void (*HostIterator)(const HostIdentity * identity, 
			     const unsigned short protocol,
			     void * data);

/**
 * Initialize the knownhosts module.
 **/
void initKnownhosts();

/**
 * Shutdown the knownhosts module.
 **/
void doneKnownhosts();

/**
 * Check if 2 hosts are the same (returns 1 if yes)
 * @param first the first host
 * @param second the second host
 * @returns 1 if the hosts are the same, 0 otherwise
 **/
int hostIdentityEquals(const HostIdentity * first, 
		       const HostIdentity * second);
 
/**
 * Delete a host from the list
 **/
void delHostFromKnown(const HostIdentity * identity,
		      const unsigned short protocol);

/**
 * Add a host to the temporary list.
 **/
void addTemporaryHost(HELO_Message * tmp);

/**
 * Bind a host addres (helo) to a hostId.
 * @param msg the verified (!) HELO message body
 **/
void bindAddress(HELO_Message * msg);

/**
 * Obtain the public key and address of a known host. If no specific
 * protocol is specified (ANY_PROTOCOL_NUMBER), the HELO for the
 * cheapest protocol is returned.
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        ANY_PROTOCOL_NUMBER  if we do not care which protocol
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 **/
int identity2Helo(const HostIdentity *  hostId,
		  const unsigned short protocol,
		  int tryTemporaryList,
		  HELO_Message ** result);

/**
 * Blacklist a host. This method is called if a host
 * failed to respond to a connection attempt.
 * @param desparation how desperate are we to connect? [0,MAXHOSTS]
 * @param strict should we reject incoming connections?
 * @return OK on success SYSERR on error
 **/
int blacklistHost(HostIdentity * identity,
		  int desperation,
		  int strict);

/**
 * Is the node currently 'strictly' blacklisted?
 * @param identity node to check
 * @return YES if true, else NO
 **/
int isBlacklistedStrict(HostIdentity * identity);

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return OK on success SYSERR on error
 **/
int whitelistHost(HostIdentity * identity);

/**
 * Call a method for each known host.
 * @param callback the method to call for each host, may be NULL
 * @param now the time to use for excluding hosts due to blacklisting, use 0 
 *        to go through all hosts.
 * @param data an argument to pass to the method
 * @return the number of known hosts matching
 **/
int forEachHost(HostIterator callback,
		cron_t now,
		void * data);
 
/**
 * Call this method periodically to scan data/hosts for new hosts.
 **/
void cronScanDirectoryDataHosts(void * unused);

/**
 * Get an estimate of the network size.
 * @return the estimated number of nodes, SYSERR on error
 **/
int estimateNetworkSize();

#endif
/* end of knownhosts.h */

