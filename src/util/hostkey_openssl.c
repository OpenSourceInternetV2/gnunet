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
 * @file util/hostkey_openssl.c
 * @brief public key cryptography (RSA) with OpenSSL
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>


#define HOSTKEY(a) ((RSA *)(a)->internal)
#define HOSTKEYL(a) ((a)->internal)



#define HOSTKEY_LEN 2048
#define EXTRA_CHECKS YES

/**
 * Initialize Random number generator.
 **/
void initRAND() {
  srand((unsigned int)time(NULL));
}

/**
 * This HostKey implementation uses RSA.
 **/
Hostkey makeHostkey() {
  Hostkey ret;
  RSA * hk;

  hk = RSA_generate_key(HOSTKEY_LEN, 65535, NULL, 0);
  if (hk == NULL) {
    LOG(LOG_ERROR,
	"ERROR: RSA_generate_key failed: %s\n",
	ERR_error_string(ERR_get_error(), NULL));  
    return NULL;
  }
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = hk;
  return ret;
}

/**
 * Free memory occupied by hostkey
 **/
void freeHostkey(Hostkey hostkey) {
  RSA_free(HOSTKEY(hostkey));
  FREE(hostkey);
}


/**
 * Extract the public key of the host.
 * @param hostkey the hostkey to extract into the result.
 * @param result where to write the result.
 **/
void getPublicKey(Hostkey hostkey,
		  PublicKey * result) {
  unsigned short sizen;
  unsigned short sizee;
  unsigned short size;

  sizen = BN_num_bytes(HOSTKEY(hostkey)->n);
  sizee = BN_num_bytes(HOSTKEY(hostkey)->e);
  size = sizen + sizee+2*sizeof(unsigned short);
  if (size != sizeof(PublicKey)-sizeof(result->padding)) 
    errexit("FATAL: sizeof public key does not match size (%u!=%u)\n",
	    size, 
	    sizeof(PublicKey)-sizeof(result->padding));
  if (RSA_KEY_LEN != sizen+sizee) 
    errexit("FATAL: PublicKey datastructure wrong (%u+%u!=%u)!\n",
	    sizen, 
	    sizee, 
	    RSA_KEY_LEN);
  result->len = htons(size);
  result->sizen = htons(sizen);
  result->padding = 0;
  if (sizen != BN_bn2bin(HOSTKEY(hostkey)->n,
			 &result->key[0])) 
    errexit("FATAL: BN_bn2bin(n) did not return expected size %u (%s)\n",
	    sizen, 
	    ERR_error_string(ERR_get_error(), NULL));
  if (sizee != BN_bn2bin(HOSTKEY(hostkey)->e,
			 &result->key[sizen]))
    errexit("FATAL: BN_bn2bin(e) did not return expected size %u (%s)\n",
	    sizee, 
	    ERR_error_string(ERR_get_error(), NULL));
}


/**
 * Internal: publicKey => RSA-Key
 **/
static Hostkey public2Hostkey(PublicKey * publicKey) {
  Hostkey ret;
  RSA * result;
  int sizen;
  int sizee;

  if (ntohs(publicKey->len) != sizeof(PublicKey)-sizeof(publicKey->padding)) {
    LOG(LOG_ERROR,
	"ERROR: public2Hostkey: received invalid publicKey (size=%d)\n",
	ntohs(publicKey->len));
    return NULL;
  }
  sizen = ntohs(publicKey->sizen);
  sizee = ntohs(publicKey->len) - sizen - 2*sizeof(unsigned short);
  if ( (sizen != RSA_ENC_LEN) || 
       (sizee + sizen != RSA_KEY_LEN)) {
    LOG(LOG_ERROR,
	"ERROR: public2Hostkey: received invalid publicKey (sizee=%d, sizen=%d)\n",
	sizee,
	sizen);
    return NULL;
  }
  result = RSA_new();
  result->n = BN_bin2bn(&publicKey->key[0], 
			sizen, 
			NULL);
  result->e = BN_bin2bn(&publicKey->key[sizen],
			sizee, 
			NULL);
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = result;
  return ret;
}

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @returns encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 **/
HostKeyEncoded * encodeHostkey(Hostkey hostkey) {
  /*
               BIGNUM *n;               public modulus
               BIGNUM *e;               public exponent
               BIGNUM *d;               private exponent
               BIGNUM *p;               secret prime factor
               BIGNUM *q;               secret prime factor
               BIGNUM *dmp1;            d mod (p-1)
               BIGNUM *dmq1;            d mod (q-1)
               BIGNUM *iqmp;            q^-1 mod p
  */
  unsigned short sizen;
  unsigned short sizee;
  unsigned short sized;
  unsigned short sizep;
  unsigned short sizeq;
  unsigned short sizedmp1;
  unsigned short sizedmq1;
  unsigned short sizeiqmp;
  unsigned short size;
  HostKeyEncoded * retval;

  sizen = BN_num_bytes(HOSTKEY(hostkey)->n);
  sizee = BN_num_bytes(HOSTKEY(hostkey)->e);
  sized = BN_num_bytes(HOSTKEY(hostkey)->d);
  if (HOSTKEY(hostkey)->p != NULL)
    sizep = BN_num_bytes(HOSTKEY(hostkey)->p);
  else
    sizep = 0;
  if (HOSTKEY(hostkey)->q != NULL)
    sizeq = BN_num_bytes(HOSTKEY(hostkey)->q);
  else
    sizeq = 0;
  if (HOSTKEY(hostkey)->dmp1 != NULL)
    sizedmp1 = BN_num_bytes(HOSTKEY(hostkey)->dmp1);
  else
    sizedmp1 = 0;
  if (HOSTKEY(hostkey)->dmq1 != NULL)
    sizedmq1 = BN_num_bytes(HOSTKEY(hostkey)->dmq1);
  else
    sizedmq1 = 0;
  if (HOSTKEY(hostkey)->iqmp != NULL)
    sizeiqmp = BN_num_bytes(HOSTKEY(hostkey)->iqmp);
  else
    sizeiqmp = 0;
  size = sizen+sizee+sized+sizep+sizeq+sizedmp1+sizedmq1+sizeiqmp+sizeof(HostKeyEncoded);
  retval = (HostKeyEncoded *) MALLOC(size);
  retval->len = htons(size);
  retval->sizen = htons(sizen);
  retval->sizee = htons(sizee);
  retval->sized = htons(sized);
  retval->sizep = htons(sizep);
  retval->sizeq = htons(sizeq);
  retval->sizedmp1 = htons(sizedmp1);
  retval->sizedmq1 = htons(sizedmq1);
  BN_bn2bin(HOSTKEY(hostkey)->n, &((HostKeyEncoded_GENERIC *)retval)->key[0]);
  BN_bn2bin(HOSTKEY(hostkey)->e, &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen]);
  BN_bn2bin(HOSTKEY(hostkey)->d, &((HostKeyEncoded_GENERIC *)retval)->key[0+
            sizen+sizee]);
  if (HOSTKEY(hostkey)->p != NULL)
    BN_bn2bin(HOSTKEY(hostkey)->p, 
	      &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen+sizee+sized]);
  if (HOSTKEY(hostkey)->q != NULL)
    BN_bn2bin(HOSTKEY(hostkey)->q, 
	      &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen+sizee+sized+
              sizep]);
  if (HOSTKEY(hostkey)->dmp1 != NULL)
    BN_bn2bin(HOSTKEY(hostkey)->dmp1, 
	      &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen+sizee+sized+
              sizep+sizeq]);
  if (HOSTKEY(hostkey)->dmq1 != NULL)
    BN_bn2bin(HOSTKEY(hostkey)->dmq1, 
	      &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen+sizee+sized+
              sizep+sizeq+sizedmp1]);
  if (HOSTKEY(hostkey)->iqmp != NULL)
    BN_bn2bin(HOSTKEY(hostkey)->iqmp, 
	      &((HostKeyEncoded_GENERIC *)retval)->key[0+sizen+sizee+sized+
              sizep+sizeq+sizedmp1+sizedmq1]);
  return retval;
}

/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 **/
Hostkey decodeHostkey(HostKeyEncoded * encoding) {
  unsigned short sizen;
  unsigned short sizee;
  unsigned short sized;
  unsigned short sizep;
  unsigned short sizeq;
  unsigned short sizedmp1;
  unsigned short sizedmq1;
  unsigned short size;
  unsigned short sum;
  RSA * result;
  Hostkey ret;

  result = RSA_new();
  size    = ntohs(encoding->len) - sizeof(HostKeyEncoded);
  sizen   = ntohs(encoding->sizen);
  sizee   = ntohs(encoding->sizee);
  sized   = ntohs(encoding->sized);
  sizep   = ntohs(encoding->sizep);
  sizeq   = ntohs(encoding->sizeq);
  sizedmp1= ntohs(encoding->sizedmp1);
  sizedmq1= ntohs(encoding->sizedmq1);
  sum = 0;
  result->n= BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum], sizen,
                       NULL); sum += sizen;
  result->e= BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum], sizee,
                       NULL); sum += sizee;
  result->d= BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum], sized,
                       NULL); sum += sized;
  if (sizep != 0) {
    result->p = BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum],
                          sizep, NULL); sum += sizep;
  } else
    result->p = NULL;
  if (sizeq != 0) {
    result->q = BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum],
                          sizeq, NULL); sum += sizeq;
  } else
    result->q = NULL;
  if (sizedmp1 != 0) {
    result->dmp1= BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum],
                            sizedmp1, NULL); sum += sizedmp1;
  } else
    result->dmp1 = NULL;
  if (sizedmq1 != 0) {
    result->dmq1 = BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum],
                             sizedmq1, NULL); sum += sizedmq1;
  } else
    result->dmq1 = NULL;
  if (size - sum > 0) 
    result->iqmp= BN_bin2bn(&((HostKeyEncoded_GENERIC *)encoding)->key[sum],
                            size-sum, NULL);
  else
    result->iqmp = NULL;
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = result;
  return ret;
}

/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns SYSERR on error, OK if ok
 **/
int encryptHostkey(void * block, 
		   unsigned short size,
		   PublicKey * publicKey,
		   RSAEncryptedData * target) {
  Hostkey foreignkey;
  int rs;
  int len;

  foreignkey = public2Hostkey(publicKey);
  if (foreignkey == NULL)
    return SYSERR;
  rs = RSA_size(HOSTKEY(foreignkey));
  /* now encrypt. First get size of the block */
  if (size > (rs - 41)) {
    LOG(LOG_ERROR,
	"ERROR: HostKey::encryptHostkey() called with %d"
	" bytes where foreignkey allows only %d\n",
	size, 
	rs-41);
    freeHostkey(foreignkey);
    return SYSERR;
  }
  if (rs != sizeof(RSAEncryptedData)) {
    LOG(LOG_FAILURE,
	"FAILURE: assertion failed: %d (=RSA_size(foreignkey)) != %d\n",
	rs,
	sizeof(RSAEncryptedData));
    freeHostkey(foreignkey);
    return SYSERR;
  }
  len = RSA_public_encrypt(size, 
			   block, 
			   &target->encoding[0], 
			   HOSTKEY(foreignkey),
			   RSA_PKCS1_PADDING);
  if (len != RSA_ENC_LEN) {
    LOG(LOG_ERROR,
	"ERROR: RSA-Encoding has unexpected length %d (%s)!",
	len,
	ERR_error_string(ERR_get_error(), NULL));
    freeHostkey(foreignkey);
    return SYSERR;
  }
  freeHostkey(foreignkey);
  return OK;
}

/**
 * Decrypt a given block with the hostkey. 
 *
 * @param hostkey the hostkey with which to decrypt this block
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 **/
int decryptHostkey(Hostkey hostkey, 
		   RSAEncryptedData * block,
		   void * result,
		   unsigned int max) {
  RSAEncryptedData tmp; /* this is as big as the result can possibly get */
  int size;

  if (block == NULL)
    return -1;

  size = RSA_private_decrypt(sizeof(RSAEncryptedData), 
			     &block->encoding[0],
			     &tmp.encoding[0], 
			     HOSTKEY(hostkey),
			     RSA_PKCS1_PADDING);
  if ( (size == -1) || 
       (size > max) ) {
    ERR_load_crypto_strings();
    LOG(LOG_WARNING,
	"WARNING: RSA_private_decrypt failed, size %d, expected %d (%s)\n",
	size, 
	max,
	ERR_error_string(ERR_get_error(), NULL));
    ERR_free_strings();
    return -1;
  }
  memcpy(result,
	 &tmp.encoding[0],
	 size);
  return size;
}

/**
 * Sign a given block.
 *
 * @param hostkey the hostkey with which to sign this block
 * @param size how many bytes to sign
 * @param block the data to sign
 * @param sig where to write the signature
 * @return SYSERR on error, OK on success
 **/
int sign(Hostkey hostkey, 
	 unsigned short size,
	 void * block,
	 Signature * sig) {
#if EXTRA_CHECKS
  PublicKey pkey;
#endif
  int rs = RSA_size(HOSTKEY(hostkey));
  unsigned int sigSize;
  HashCode160 hc;

  if (block == NULL)
    return SYSERR;
  if (rs != sizeof(Signature)) {
    LOG(LOG_ERROR,
	"ERROR: sign: signature length (RSA_size) has unexpected value (%d)!",
	rs);
    return SYSERR;
  }
  hash(block, 
       size,
       &hc);
  if (1 != RSA_sign(NID_ripemd160,
		    (unsigned char*)&hc,
		    sizeof(HashCode160),
		    &sig->sig[0],
		    &sigSize,
		    HOSTKEY(hostkey))) {
    LOG(LOG_ERROR,
	"ERROR: RSA_sign failed! (%s)",
	ERR_error_string(ERR_get_error(), NULL));
    return SYSERR;
  }
  if (sigSize != sizeof(Signature)) {
    LOG(LOG_ERROR,
	"ERROR: sign: sigSize wrong (%u != %u)!",
	sigSize,
	sizeof(Signature));
    return SYSERR;
  }
#if EXTRA_CHECKS
  if (1 != RSA_verify(NID_ripemd160,
		      (unsigned char*)&hc,
		      sizeof(HashCode160),
		      &sig->sig[0],
		      sizeof(Signature),
		      HOSTKEY(hostkey))) 
    LOG(LOG_FAILURE,
	"FAILURE: OpenSSL error: direct verification failed!\n");
  
  getPublicKey(hostkey, &pkey);
  if (SYSERR == verifySig(block, size, sig, &pkey)) {
    LOG(LOG_FAILURE,
	"FAILURE: sign: generated signature does not pass verification!\n");
    if (1 != RSA_verify(NID_ripemd160,
			(unsigned char*)&hc,
			sizeof(HashCode160),
			&sig->sig[0],
			sizeof(Signature),
			HOSTKEY(hostkey))) 
      LOG(LOG_FAILURE,
	  "FAILURE: OpenSSL error: direct verification failed, too!\n");
    else
      LOG(LOG_FAILURE,
	  "FAILURE: getPublicKey must have failed, direct verification is OK!\n");
     
   return SYSERR;
  }
#endif
  return OK;
}

/**
 * Verify signature.
 *
 * @param block the signed data
 * @param len the length of the block 
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns OK if ok, SYSERR if invalid
 **/
int verifySig(void * block,
	      unsigned short len,
	      Signature * sig,	      
	      PublicKey * publicKey) {
  Hostkey hostkey;
  int rs;
  HashCode160 hc;
 
  hostkey = public2Hostkey(publicKey);
  if ( (hostkey == NULL) || 
       (sig == NULL) || 
       (block == NULL))
    return SYSERR; /* hey, no data !? */
  rs = RSA_size(HOSTKEY(hostkey));
  if (rs != RSA_ENC_LEN) 
    errexit("FATAL: verifySig: rs != RSA_ENC_LEN (%d)!",
	    rs);  
  hash(block, 
       len, 
       &hc);
  if (1 != RSA_verify(NID_ripemd160,
		      (unsigned char*)&hc,
		      sizeof(HashCode160),
		      &sig->sig[0],
		      sizeof(Signature),
		      HOSTKEY(hostkey))) {
    LOG(LOG_ERROR,
	"ERROR: verifySig: signature mismatch (%s)\n",
	ERR_error_string(ERR_get_error(), NULL));
    freeHostkey(hostkey);
    return SYSERR;
  }
  freeHostkey(hostkey);
  return OK;
}


/* end of hostkey_openssl.c */
