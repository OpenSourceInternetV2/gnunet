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
 * @file util/symcipher_openssl.c
 * @brief Symetric encryption services.
 * @author Christian Grothoff
 * @author Ioana Patrascu
 **/

#include "gnunet_util.h"
#include "platform.h"
#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
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
  int outlen = 0;
  EVP_CIPHER_CTX ctx;
  
  if ( (block == NULL) || (sessionkey == NULL) ) {
    LOG(LOG_FAILURE,
	"FAILURE: encyrptBlock called with NULL in arguments\n");
    return -1;  
  }
  /* compute result size by adding block-length, always padded */
  EVP_EncryptInit(&ctx, 
		  EVP_bf_cfb(), 
		  sessionkey->key,
		  iv);
#if SSL_MICRO >= 6
  if (0 == EVP_EncryptUpdate(&ctx, 
			     result, 
			     &outlen,
			     block, len)) {
    LOG(LOG_FAILURE,
	"FAILURE: symcipher.c-encryptBlock: EVP_EncryptUpdate failed!\n");
    return -1;
  }
#else
  EVP_EncryptUpdate(&ctx, result, &outlen, block, len);
#endif
  len = outlen; /* save bytes written so far */
  outlen = 0;
#if SSL_MICRO >= 6
  if (0 == EVP_EncryptFinal(&ctx,
                            &((unsigned char*)result)[len],
			    &outlen)) {
    LOG(LOG_FAILURE,
	"FAILURE: symcipher.c-encryptBlock: EVP_EncryptFinal failed!\n");
    return -1;
  }
#else
  EVP_EncryptFinal(&ctx, 
                   &((unsigned char*)result)[len],
		   &outlen);
#endif
  outlen += len; /* add both updates together */
  EVP_CIPHER_CTX_cleanup(&ctx);
  return outlen;
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
  int outlen = 0;
  EVP_CIPHER_CTX ctx;

  /* use blowfish-cfb */
  EVP_DecryptInit(&ctx, 
		  EVP_bf_cfb(), 
		  sessionkey->key, 
		  iv);
#if SSL_MICRO >= 6
  if (0 == EVP_DecryptUpdate(&ctx, 
			     result, 
			     &outlen,
			     block, 
			     size)) {
    LOG(LOG_FAILURE,
	"FAILURE: symcipher.c-decryptBlock: EVP_DecryptUpdate failed!\n");
    return -1;
  }
#else
  EVP_DecryptUpdate(&ctx, 
		    result, 
		    &outlen, 
		    block, 
		    size);
#endif
  size = outlen;
  outlen = 0; 
#if SSL_MICRO >= 6
  if (0 == EVP_DecryptFinal(&ctx, &((unsigned char*)result)[size], &outlen)) {
    LOG(LOG_FAILURE,
	"FAILURE: symcipher.c-decryptBlock: EVP_DecryptFinal failed!\n");
    return -1;
  }
#else
  EVP_DecryptFinal(&ctx, 
		   &((unsigned char*)result)[size], 
		   &outlen);
#endif
  EVP_CIPHER_CTX_cleanup(&ctx);
  return size+outlen;
}

/* end of symcipher_openssl.c */
