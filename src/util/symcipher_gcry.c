/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file util/symcipher_gcry.c
 * @brief Symetric encryption services.
 * @author Christian Grothoff
 * @author Ioana Patrascu
 **/

#include "gnunet_util.h"

#include "gcry/blowfish.h"

/**
 * Create a new SessionKey (for Blowfish)
 **/
void makeSessionkey(SESSIONKEY * key) {
  int i;
  for (i=0;i<SESSIONKEY_LEN;i++)
    key->key[i] = rand();
}


/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result the output parameter in which to store the encrypted result
 * @returns the size of the encrypted block, -1 for errors
 **/
int encryptBlock(void * block, 
		 unsigned short len,
		 SESSIONKEY * sessionkey,
		 unsigned char * iv,
		 void * result) {
  BLOWFISH_context handle;

  do_bf_setkey(&handle, 
	       (byte*)sessionkey, 
	       sizeof(SESSIONKEY));
  cipher_setiv(&handle, 
	       iv,
	       sizeof(SESSIONKEY)/2);  
  do_cfb_encrypt(&handle,
		 (byte*)result,
		 block,
		 len);
  return len;
}

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the block to decrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 **/
int decryptBlock(SESSIONKEY * sessionkey, 
		 void * block,
		 unsigned short size,
		 unsigned char * iv,
		 void * result) {
  BLOWFISH_context c;

  do_bf_setkey(&c,
	       (byte*)sessionkey, 
	       sizeof(SESSIONKEY));
  cipher_setiv(&c,
	       iv,
	       sizeof(SESSIONKEY)/2);
  do_cfb_decrypt(&c,
		 (byte*)result,
		 (byte*)block,
		 size);
  return size;
}

/* end of symcipher_gcry.c */
