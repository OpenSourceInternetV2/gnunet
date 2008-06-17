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
 * @file util/hostkey_gcry.c
 * @brief hostkey.h implementation using util/gcry/
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"
#include "locking_gcrypt.h"
#include "gcry/rsa.h"

#define HOSTKEY_LEN 2048
#define EXTRA_CHECKS YES

#define DIM(v) (sizeof(v)/sizeof((v)[0]))
static byte rmd160asn[15] = /* Object ID is 1.3.36.3.2.1 */
  { 0x30, 0x21, 0x30, 0x09, 0x06, 
    0x05, 0x2b, 0x24, 0x03, 0x02, 
    0x01, 0x05, 0x00, 0x04, 0x14 };


#ifndef DID_MPI_TYPEDEF
#define DID_MPI_TYPEDEF
typedef struct gcry_mpi *MPI;
#endif
#ifndef RSA_SKEY_DEFINED
#define RSA_SKEY_DEFINED
typedef struct {
  MPI n;	    /* public modulus */
  MPI e;	    /* public exponent */
  MPI d;	    /* exponent */
  MPI p;	    /* prime  p. */
  MPI q;	    /* prime  q. */
  MPI u;	    /* inverse of p mod q. */
} RSA_secret_key;
#endif
#define HOSTKEY(a) ((RSA_secret_key*)(a)->internal)
#define HOSTKEYL(a) ((a)->internal)


/**
 * Initialize Random number generator.
 **/
void initRAND() {
  srand((unsigned int)time(NULL));
}

/**
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 **/
static void adjust(char * buf,
		   size_t size,
		   size_t target) {
  if (size < target) {
    memmove(&buf[target-size],
	    buf,
	    size);    
    memset(buf, 
	   0, 
	   target-size);
  }
}
		   

/**
 * This HostKey implementation uses RSA.
 **/
Hostkey makeHostkey() {
  Hostkey s_key;

  s_key = MALLOC(sizeof(Hostkey__));
  HOSTKEYL(s_key) = MALLOC(sizeof(RSA_secret_key));
  memset(HOSTKEY(s_key), 0, sizeof(RSA_secret_key));
  lockGcrypt();
  rsa_generate(HOSTKEY(s_key), 
	       HOSTKEY_LEN, 
	       257 /* e */);
  unlockGcrypt();
  return s_key;
}

/**
 * Free memory occupied by hostkey
 **/
void freeHostkey(Hostkey hostkey) {
  if (HOSTKEY(hostkey)->n != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->n);
  if (HOSTKEY(hostkey)->e != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->e);
  if (HOSTKEY(hostkey)->p != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->p);
  if (HOSTKEY(hostkey)->q != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->q);
  if (HOSTKEY(hostkey)->d != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->d);
  if (HOSTKEY(hostkey)->u != NULL)
    gcry_mpi_release(HOSTKEY(hostkey)->u);
  FREE(HOSTKEY(hostkey));
  FREE(hostkey);
}

/**
 * Internal: publicKey => RSA-Key
 **/
static Hostkey public2Hostkey(PublicKey * publicKey) {
  RSA_secret_key * result;
  Hostkey ret;
  GcryMPI n;
  GcryMPI e;
  size_t size;
  int rc;

  /* len = sizen + sizee + 4 == publickey - padding! */
  if ( ( ntohs(publicKey->sizen) != RSA_ENC_LEN ) ||
       ( ntohs(publicKey->len) != sizeof(PublicKey) - sizeof(publicKey->padding)) ) {
    LOG(LOG_ERROR,
	"ERROR: public2Hostkey: received invalid publicKey (%d, %d)\n",
	ntohs(publicKey->len),
	ntohs(publicKey->sizen)); 
    return NULL;
  }
  size = RSA_ENC_LEN;
  rc = gcry_mpi_scan(&n,
		     GCRYMPI_FMT_USG,
		     &publicKey->key[0],
		     &size);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: gcry_mpi_scan of n failed (%d)\n",
	rc);
    return NULL;
  }
  size = RSA_KEY_LEN - RSA_ENC_LEN;
  rc = gcry_mpi_scan(&e,
		     GCRYMPI_FMT_USG,
		     &publicKey->key[RSA_ENC_LEN],
		     &size);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: gcry_mpi_scan of e failed (%d)\n",
	rc);
    gcry_mpi_release(n);
    return NULL;
  }
  result = MALLOC(sizeof(RSA_secret_key));
  ret = MALLOC(sizeof(Hostkey__));
  HOSTKEYL(ret) = result;
  memset(result, 0, sizeof(RSA_secret_key));
  result->n = n;
  result->e = e;
  return ret;
}

#if EXTRA_CHECKS
static void testPublicKey(Hostkey hostkey,
			  PublicKey * pkey) {
  Hostkey pk = public2Hostkey(pkey);
  if (mpi_cmp(HOSTKEY(hostkey)->n,
	      HOSTKEY(pk)->n)) 
    errexit("FAILURE: n mismatch in testPublicKey!\n");
  if (mpi_cmp(HOSTKEY(hostkey)->e,
	      HOSTKEY(pk)->e)) 
    errexit("FAILURE: e mismatch in testPublicKey!\n");
  freeHostkey(pk);
}
#endif

/**
 * Extract the public key of the host.
 *
 * @param hostkey the hostkey to extract into the result.
 * @param result where to write the result.
 **/
void getPublicKey(Hostkey hostkey,
		  PublicKey * result) {
  size_t size;
  int rc;
  
  result->len = htons(sizeof(PublicKey) - sizeof(result->padding));
  result->sizen = htons(RSA_ENC_LEN);
  result->padding = 0;
  size = RSA_ENC_LEN;
  rc = gcry_mpi_print(GCRYMPI_FMT_USG, 
		      &result->key[0], 
		      &size, 
		      HOSTKEY(hostkey)->n);
  if (rc) 
    errexit("FATAL: gcry_mpi_print of n failed: %d\n",
	    rc);
  adjust(&result->key[0], size, RSA_ENC_LEN);

  size = RSA_KEY_LEN - RSA_ENC_LEN; 
  rc = gcry_mpi_print(GCRYMPI_FMT_USG, 
		      &result->key[RSA_ENC_LEN], 
		      &size, 
		      HOSTKEY(hostkey)->e);
  if (rc) 
    errexit("FATAL: gcry_mpi_print of e failed: %d\n",
	    rc);
  adjust(&result->key[RSA_ENC_LEN], 
	 size,
	 RSA_KEY_LEN - RSA_ENC_LEN);
#if EXTRA_CHECKS
  testPublicKey(hostkey, result);
#endif
}

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @returns encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 **/
HostKeyEncoded * encodeHostkey(Hostkey hostkey) {
  /* libgcrypt */

  HostKeyEncoded * retval;
  GcryMPI pkv[6];
  void * pbu[6];
  size_t sizes[6];
  int rc;
  int i;
  int size;

  pkv[0] = HOSTKEY(hostkey)->n;
  pkv[1] = HOSTKEY(hostkey)->e;
  pkv[2] = HOSTKEY(hostkey)->d;
  pkv[3] = HOSTKEY(hostkey)->p;
  pkv[4] = HOSTKEY(hostkey)->q;
  pkv[5] = HOSTKEY(hostkey)->u;
  size = sizeof(HostKeyEncoded);
  for (i=0;i<6;i++) {
    if (pkv[i] != NULL) {
      rc = gcry_mpi_aprint(GCRYMPI_FMT_USG,
			   &pbu[i],
			   &sizes[i],
			   pkv[i]);
      size += sizes[i];
      if (rc) {
	LOG(LOG_ERROR,
	    "ERROR: gcry_mpi_aprint failed: %d\n", 
	    rc);
	while (i>0) 
	  FREENONNULL(pbu[--i]);	
	return NULL;
      }
    } else {
      pbu[i] = NULL;
      sizes[i] = 0;
    }
  }
  if (size >= 65536) 
    errexit("FATAL: size of serialized private key >= 64k\n");  
  retval = MALLOC(size);
  retval->len = htons(size);
  i = 0;
  retval->sizen = htons(sizes[0]);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i], 
	 pbu[0],
	 sizes[0]);
  i += sizes[0];
  retval->sizee = htons(sizes[1]);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i],
	 pbu[1],
	 sizes[1]);
  i += sizes[1];
  retval->sized = htons(sizes[2]);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i],
	 pbu[2],
	 sizes[2]);
  i += sizes[2];
  /* swap p and q! */
  retval->sizep = htons(sizes[4]);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i],
	 pbu[4],
	 sizes[4]);
  i += sizes[4];
  retval->sizeq = htons(sizes[3]);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i],
	 pbu[3],
	 sizes[3]);
  i += sizes[3];
  retval->sizedmp1 = htons(0);
  retval->sizedmq1 = htons(0);
  memcpy(&((HostKeyEncoded_GENERIC*)(retval))->key[i],
	 pbu[5],
	 sizes[5]);
  for (i=0;i<6;i++) 
    if (pbu[i] != NULL)
      free(pbu[i]);  /* allocated in gcry, do NOT use "FREE" */
  return retval;
}

/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 **/
Hostkey decodeHostkey(HostKeyEncoded * encoding) {
  RSA_secret_key * result;
  Hostkey ret;
  GcryMPI n,e,d,p,q,u;
  int rc;
  size_t size;
  int pos;

  pos = 0;
  size = ntohs(encoding->sizen);
  rc = gcry_mpi_scan(&n,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		     &size);
  pos += ntohs(encoding->sizen);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: could not decode hostkey (%d)\n",
	rc);
    return NULL;
  }
  size = ntohs(encoding->sizee);
  rc = gcry_mpi_scan(&e,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		     &size);
  pos += ntohs(encoding->sizee);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: could not decode hostkey (%d)\n",
	rc);
    gcry_mpi_release(n);
    return NULL;
  }
  size = ntohs(encoding->sized);
  rc = gcry_mpi_scan(&d,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		     &size);
  pos += ntohs(encoding->sized);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: could not decode hostkey (%d)\n",
	rc);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    return NULL;
  }
  /* swap p and q! */
  size = ntohs(encoding->sizep);
  if (size > 0) {
    rc = gcry_mpi_scan(&q,
		       GCRYMPI_FMT_USG,
		       &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		       &size);
    pos += ntohs(encoding->sizep);
    if (rc) {
      LOG(LOG_ERROR,
	  "ERROR: could not decode hostkey (%d)\n",
	  rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      return NULL;
    }
  } else
    q = NULL;
  size = ntohs(encoding->sizeq);
  if (size > 0) {
    rc = gcry_mpi_scan(&p,
		       GCRYMPI_FMT_USG,
		       &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		       &size);
    pos += ntohs(encoding->sizeq);
    if (rc) {
      LOG(LOG_ERROR,
	  "ERROR: could not decode hostkey (%d)\n",
	  rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      if (q != NULL)
	gcry_mpi_release(q);
      return NULL;
    }
  } else
    p = NULL;
  pos += ntohs(encoding->sizedmp1);
  pos += ntohs(encoding->sizedmq1);
  
  size = ntohs(encoding->len) - sizeof(HostKeyEncoded) - pos;
  if (size > 0) {
    rc = gcry_mpi_scan(&u,
		       GCRYMPI_FMT_USG,
		       &((HostKeyEncoded_GENERIC*)(encoding))->key[pos],
		       &size);
    if (rc) {
      LOG(LOG_ERROR,
	  "ERROR: could not decode hostkey (%d)\n",
	  rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      if (p != NULL)
	gcry_mpi_release(p);
      if (q != NULL)
	gcry_mpi_release(q);
      return NULL;
    }
  } else
    u = NULL;

  ret = MALLOC(sizeof(Hostkey__));  
  result = MALLOC(sizeof(RSA_secret_key));
  HOSTKEYL(ret) = result;
  memset(result, 0, sizeof(RSA_secret_key));
  result->n = n;
  result->e = e;
  result->d = d;
  result->p = p;
  result->q = q;
  result->u = u;
  return ret;
}

/**
 * Encrypt a block with the public key of another host that uses the
 * same cypher.
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
  Hostkey pubkey;
  MPI val;
  MPI rval;
  size_t isize;
  int rc;
  int nbits = HOSTKEY_LEN;  
  unsigned char * frame = NULL;
  size_t nframe = (nbits+7) / 8;
  unsigned int i;

  /* pkcs#1 block type 2 padding */    
  if ((size + 7 > (unsigned short)nframe) || (0 == nframe))
    errexit("FATAL: encryptHostkey: data to encrypt too long for key (%u > %u)\n",
	    size, nframe);
  frame = MALLOC(nframe);
  frame[0] = 0;
  frame[1] = 2; /* block type */
  for (i=2;i<nframe-size-1;i++) /* pad with non-null random bytes */
    frame[i] = 1+randomi(255);
  frame[nframe-size-1] = 0; /* terminate padding with zero */
  /* and at the end add the actual data */
  memcpy(&frame[nframe-size], block, size);
  /* end of pkcs#1 padding */

  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     frame,
		     &nframe);
  FREE(frame);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: encryptHostkey - gcry_mpi_scan failed (%d)\n", 
	rc);
    return SYSERR;
  }
  pubkey = public2Hostkey(publicKey);
  rsa_encrypt(val, &rval, HOSTKEY(pubkey));
  gcry_mpi_release(val);
  freeHostkey(pubkey);
  isize = sizeof(RSAEncryptedData);
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      (char*)target,
		      &isize, 
		      rval);
  gcry_mpi_release(rval);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: encryptHostkey - gcry_mpi_print failed (%d)\n", 
	rc);
    return SYSERR;
  }
  adjust(&target->encoding[0],
	 isize,
	 sizeof(RSAEncryptedData));
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
  size_t size;
  GcryMPI val;
  GcryMPI res;
  int rc;
  char * endp;
  char * tmp;

  size = sizeof(RSAEncryptedData);
  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     &block->encoding[0],
		     &size);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: hostkeyDecrypt: gcry_mpi_scan failed (%d)\n",
	rc);
    return SYSERR;
  }
  rc = rsa_decrypt(&res, &val, HOSTKEY(hostkey));
  gcry_mpi_release(val);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: hostkeyDecrypt: rsa_decrypt failed (%d)\n",
	rc);
    return SYSERR;
  }

  size = max + HOSTKEY_LEN / 8;
  tmp = MALLOC(size);
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      tmp,
		      &size,
		      res);
  gcry_mpi_release(res);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: gcry_mpi_print failed (%d)\n",
	rc);
    FREE(tmp);
    return SYSERR;
  }
  endp = tmp;
  if (*endp == 0) {
    fprintf(stderr, "0");
    endp++;
    size--;
  }
  if ( (!size) || 
       (*endp != 0x02 )) {
    /* int i; */
    LOG(LOG_ERROR,
	"ERROR: not a pkcs-1 block type 2 (size=%d, *tmp=%d)!\n",
	size, 
	(int)*tmp);
    /* for (i=0;i<size;i++)
       fprintf(stderr, "%x ", (unsigned char) tmp[i]); 
       fprintf(stderr, "\n"); */
    FREE(tmp);
    return SYSERR;
  }
  /* serach the end of the padding */
  while ( (size > 0) && 
	  ((*endp) != 0) ) {
    size--;
    endp++;
  }
  if ( (size == 0) || 
       (*endp != 0x0) ) {
    LOG(LOG_ERROR,
	"ERROR: not a pkcs-1 block type 2 (size=%d, *endp=%d)\n",
	size, (int) *endp);
    FREE(tmp);
    return SYSERR;
  }
  size--;
  endp++;

  if (size > max)
    size = max;
  memcpy(result,
	 endp,
	 size);
  FREE(tmp);
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
  MPI data;
  size_t ssize;
  GcryMPI rval;
  HashCode160 hc;
  int rc;
  int nbits = HOSTKEY_LEN;  
  unsigned char * frame = NULL;
  size_t nframe = (nbits+7) / 8;
  unsigned int i;

  hash(block, size, &hc);
  /* pkcs#1 block type 1 padding */    
  frame = MALLOC(nframe);
  frame[0] = 0;
  frame[1] = 1; /* block type */
  for (i=2;i<nframe-sizeof(HashCode160)-DIM(rmd160asn)-1;i++) /* pad with 0xFF */
    frame[i] = 0xFF;
  frame[nframe-sizeof(HashCode160)-DIM(rmd160asn)-1] = 0; /* terminate padding with zero */
  /* copy ASN */
  memcpy(&frame[nframe-sizeof(HashCode160)-DIM(rmd160asn)],
	 &rmd160asn[0],
	 DIM(rmd160asn));
  /* and at the end add the actual data */
  memcpy(&frame[nframe-sizeof(HashCode160)], 
	 &hc, 
	 sizeof(HashCode160));
  /* end of pkcs#1 type 1 padding */

  rc = gcry_mpi_scan(&data,
		     GCRYMPI_FMT_USG,
		     frame,
		     &nframe);
  FREE(frame);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: encryptHostkey - gcry_mpi_scan failed (%d)\n", 
	rc);
    return SYSERR;
  }
  rc = rsa_sign(&rval,
		data, 
		HOSTKEY(hostkey));
  gcry_mpi_release(data);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: sign: rsa_sign failed (%d)\n",
	rc);
    return SYSERR;
  }
  ssize = sizeof(Signature);
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      (char*)sig,
		      &ssize,
		      rval);
  gcry_mpi_release(rval);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: sign: gcry_mpi_print failed (%d)\n",
	rc);
    return SYSERR;
  }
  adjust(&sig->sig[0],
	 ssize,
	 sizeof(Signature));
#if EXTRA_CHECKS
  {
	    PublicKey pubKey;
	    getPublicKey(hostkey, &pubKey);
  if (OK != verifySig(block, size, sig, &pubKey))
	  errexit("FATAL: verifySig failed for my own signature!\n");
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
  size_t size;
  GcryMPI val;
  MPI sigdata;
  Hostkey hostkey;
  HashCode160 hc;
  int rc;
  int nbits = HOSTKEY_LEN;  
  unsigned char * frame = NULL;
  size_t nframe = (nbits+7) / 8;
  unsigned int i;
 
  size = sizeof(Signature);
  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     (char*)sig,
		     &size);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: sign: gcry_mpi_scan failed (%d)\n",
	rc);
    return SYSERR;
  }
  hash(block, len, &hc);
  /* pkcs#1 block type 1 padding */    
  frame = MALLOC(nframe);
  frame[0] = 0;
  frame[1] = 1; /* block type */
  for (i=2;i<nframe-sizeof(HashCode160)-DIM(rmd160asn)-1;i++) /* pad with 0xFF */
    frame[i] = 0xFF;
  frame[nframe-sizeof(HashCode160)-DIM(rmd160asn)-1] = 0; /* terminate padding with zero */
  /* copy ASN */
  memcpy(&frame[nframe-sizeof(HashCode160)-DIM(rmd160asn)],
	 &rmd160asn[0],
	 DIM(rmd160asn));

  /* and at the end add the actual data */
  memcpy(&frame[nframe-sizeof(HashCode160)], 
	 &hc, 
	 sizeof(HashCode160));
  /* end of pkcs#1 padding */
  rc = gcry_mpi_scan(&sigdata,
		     GCRYMPI_FMT_USG,
		     frame,
		     &nframe);
  FREE(frame);
  if (rc) {
    LOG(LOG_ERROR,
	"ERROR: encryptHostkey - gcry_mpi_scan failed (%d)\n", 
	rc);
    return SYSERR;
  }

  hostkey = public2Hostkey(publicKey);
  rc = rsa_verify(sigdata,
		  &val,
		  HOSTKEY(hostkey));  
  gcry_mpi_release(val);
  gcry_mpi_release(sigdata);
  freeHostkey(hostkey);
  if (rc) {
    LOG(LOG_WARNING,
	"WARNING: signature verification failed (%d)\n",
	rc);
    return SYSERR;
  } else
    return OK;
}


/* end of hostkey_gcry.c */
