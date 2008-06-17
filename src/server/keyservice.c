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
 * @file server/keyservice.c
 * @brief encapsulation of the hostkey of the peer
 * @author Christian Grothoff
 */

#include "gnunet_util.h"

#include "keyservice.h"
#include "knownhosts.h"

/**
 * The identity of THIS node.
 */
HostIdentity myIdentity;

/**
 * The SECRET hostkey. Keep local, never export outside of this
 * module (except hostkey.c)!
 */
static Hostkey hostkey;

/**
 * The public hostkey
 */
static PublicKey * publicKey;

static void initHelper(TransportAPI * tapi,
		       void * unused) {
  HELO_Message * helo;

  createSignedHELO(tapi);
  if (OK == transportCreateHELO(tapi->protocolNumber,
				&helo)) {
    bindAddress(helo);
    FREE(helo);
  }
}

#define HOSTKEYFILE ".hostkey"

/**
 * Initialize KeyService. Configuration must be initialized at this
 * point. You must call this method first!
 */
void initKeyService(char * toolName) {
  char * gnHome;
  char * hostkeyfile;
  HostKeyEncoded * encHostkey;
  unsigned short len;
  int res;
  EncName myself;

  gnHome = getFileName("",
		       "GNUNETD_HOME",
		       "Configuration file must specify a directory for GNUnet to store per-peer data under %s%s\n");
  hostkeyfile = MALLOC(strlen(gnHome) + strlen(HOSTKEYFILE)+2);
  strcpy(hostkeyfile, gnHome);
  FREE(gnHome);
  strcat(hostkeyfile, "/");
  strcat(hostkeyfile, HOSTKEYFILE);
  res = readFile(hostkeyfile, 
		 sizeof(unsigned short), 
		 &len);
  if (res == sizeof(unsigned short)) {
    encHostkey = (HostKeyEncoded*) MALLOC(ntohs(len));
    if (ntohs(len) != 
	readFile(hostkeyfile, ntohs(len), encHostkey)) {
      FREE(encHostkey);
      LOG(LOG_WARNING,
	  _("Existing hostkey in file '%s' failed format check, creating new hostkey.\n"),
	  hostkeyfile);
      encHostkey = NULL;
    }
  } else
    encHostkey = NULL;
  if ( ( (0 == strcmp("gnunetd",
		      toolName)) ||
	 (0 == strcmp("gnunet-transport-check",
		      toolName)) ) &&
       (encHostkey == NULL) ) { /* make new hostkey */
    LOG(LOG_MESSAGE, 
	_("Creating new hostkey (this may take a while).\n"));
    hostkey = makeHostkey();
    if (hostkey == NULL)
      errexit("could not create hostkey\n");
    encHostkey = encodeHostkey(hostkey);
    if (encHostkey == NULL)
      errexit("encode hostkey failed\n");
    writeFile(hostkeyfile, 
	      encHostkey, 
	      ntohs(encHostkey->len),
	      "600");
    LOG(LOG_MESSAGE, 
	_("Done creating hostkey.\n"));
  } else {
    if (encHostkey != NULL) {
      hostkey = decodeHostkey(encHostkey);    
      FREE(encHostkey);
    } else 
      hostkey = NULL;
  }
  FREE(hostkeyfile);
  if (hostkey != NULL) {
    publicKey = MALLOC(sizeof(PublicKey));
    getPublicKey(hostkey, 
		 publicKey);
    getHostIdentity(publicKey, 
		    &myIdentity);  
    IFLOG(LOG_DEBUG,
	  hash2enc(&myIdentity.hashPubKey,
		   &myself));
    LOG(LOG_DEBUG,
	_("I am peer '%s'.\n"),
	&myself);
    forEachTransport(&initHelper, NULL);
  } else {
    publicKey = NULL;
    memset(&myIdentity,
	   0,
	   sizeof(HostIdentity));
  }
}

void doneKeyService() {
  FREENONNULL(publicKey);
  if (hostkey != NULL)
    freeHostkey(hostkey);
}

/**
 * Get the public key of the host
 * @return reference to the public key. Do not free it!
 */
PublicKey * getPublicHostkey() {
  return publicKey;
}

/**
 * Obtain identity from publicHostkey.
 * @param pubKey the public key of the host
 * @param result address where to write the identity of the node
 */
void getHostIdentity(PublicKey * pubKey,
		     HostIdentity * result) {
  hash(pubKey,
       sizeof(PublicKey),
       &result->hashPubKey);
}

/** 
 * Sign arbitrary data. ALWAYS use only on data we generated
 * entirely! 
 * @return SYSERR on error, OK on success
 */
int signData(void * data,
	     unsigned short size,
	     Signature * result) {
  return sign(hostkey, 
	      size, 
	      data, 
	      result);
}

/**
 * Decrypt a given block with the hostkey. 
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int decryptData(RSAEncryptedData * block,
		void * result,
		unsigned int max) {
  return decryptHostkey(hostkey, 
			block, 
			result, 
			max);
}


/* end of keyservice */
