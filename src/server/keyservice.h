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
 * This module encapsulates the (private) hostkey.
 * @author Christian Grothoff
 * @file server/keyservice.h
 **/

#ifndef KEYSERVICE_H
#define KEYSERVICE_H

#include "connection.h"

/**
 * Global: our identity.
 **/
extern HostIdentity myIdentity;

/**
 * Initialize KeyService. Also initializes hostkey's randInit.
 **/
void initKeyService(char * toolName); 

void doneKeyService();

/**
 * Get the public key of the host
 * @return reference to the public key. Do not free it!
 **/
PublicKey * getPublicHostkey();

/**
 * Obtain identity from publicHostkey.
 * @param pubKey the public key of the host
 * @param result address where to write the identity of the node
 **/
void getHostIdentity(PublicKey * pubKey,
		     HostIdentity * result);


/** 
 * Sign arbitrary data. ALWAYS use only on data we entirely generated.
 * @param data what to sign
 * @param size how big is the data
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 **/
int signData(void * data,
	     unsigned short size,
	     Signature * result);

/**
 * Decrypt a given block with the hostkey. 
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 **/
int decryptData(RSAEncryptedData * block,
		void * result,
		unsigned int max);




/* end of keyservice.h */

#endif
