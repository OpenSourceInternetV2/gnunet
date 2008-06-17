/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/hostkey_gcrypt.c
 * @brief public key cryptography (RSA) with libgcrypt
 * @author Christian Grothoff
 *
 * Note that the code locks often needlessly on the gcrypt-locking api.
 * One would think that simple MPI operations should not require locking
 * (since only global operations on the random pool must be locked,
 * strictly speaking).  But libgcrypt does sometimes require locking in
 * unexpected places, so the safe solution is to always lock even if it
 * is not required.  The performance impact is minimal anyway.
 */

#include "gnunet_util.h"
#include "platform.h"
#include "locking_gcrypt.h"

#include <gcrypt.h>
#define HOSTKEY(a) ((gcry_sexp_t)(a)->internal)
#define HOSTKEYL(a) ((a)->internal)


#define HOSTKEY_LEN 2048
#define EXTRA_CHECKS YES


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define DIE_GCRY(cmd, rc) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);



/**
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 */
static void adjust(char * buf,
		   int size,
		   int target) {
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
 * Initialize Random number generator.
 */
void initRAND() {
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  if (! gcry_check_version(GCRYPT_VERSION))
    errexit(_("libgcrypt has not the expected version (version %s is required).\n"),
	    GCRYPT_VERSION);
  srand((unsigned int)time(NULL));
#ifdef gcry_fast_random_poll
  gcry_fast_random_poll ();
#endif
}

/**
 * This HostKey implementation uses RSA.
 */
Hostkey makeHostkey() {
  Hostkey ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;
  int rc;

  lockGcrypt();
  rc = gcry_sexp_build(&s_keyparam, 
		       NULL, 
		       "(genkey(rsa(nbits %d)(rsa-use-e 3:257)))",
		       HOSTKEY_LEN);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc);
    unlockGcrypt();
    return NULL;
  }
  rc = gcry_pk_genkey(&s_key,
		      s_keyparam);
  gcry_sexp_release(s_keyparam);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_genkey", rc);
    unlockGcrypt();
    return NULL;
  }

#if EXTRA_CHECKS
  if ((rc=gcry_pk_testkey(s_key))) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_testkey", rc);
    unlockGcrypt();
    return NULL;
  }
#endif
  unlockGcrypt();
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = s_key;
  return ret;
}

/**
 * Free memory occupied by hostkey
 */
void freeHostkey(Hostkey hostkey) {
  lockGcrypt();
  gcry_sexp_release(HOSTKEY(hostkey));
  unlockGcrypt();
  FREE(hostkey);
}

static int key_from_sexp( gcry_mpi_t *array,
			  gcry_sexp_t sexp, 
			  const char *topname, 
			  const char *elems ) {
  gcry_sexp_t list, l2;
  const char *s;
  int i, idx;
  
  lockGcrypt();
  list = gcry_sexp_find_token( sexp, topname, 0 );
  if( !list ) {
    unlockGcrypt();
    return 1;
  }
  l2 = gcry_sexp_cadr( list );
  gcry_sexp_release ( list );
  list = l2;
  if( !list ) {
    unlockGcrypt();
    return 2;
  }
  
  idx = 0;
  for(s=elems; *s; s++, idx++ ) {
    l2 = gcry_sexp_find_token( list, s, 1 );
    if( !l2 ) {
      for(i=0; i<idx; i++) {
	gcry_free( array[i] );
	array[i] = NULL;
      }
      gcry_sexp_release ( list );
      unlockGcrypt();
      return 3; /* required parameter not found */
    }
    array[idx] = gcry_sexp_nth_mpi( l2, 1, GCRYMPI_FMT_USG );
    gcry_sexp_release ( l2 );
    if( !array[idx] ) {
      for(i=0; i<idx; i++) {
	gcry_free( array[i] );
	array[i] = NULL;
      }
      gcry_sexp_release ( list );
      unlockGcrypt();
      return 4; /* required parameter is invalid */
    }
  }
  gcry_sexp_release ( list );  
  unlockGcrypt();
  return 0;
}

/**
 * Extract the public key of the host.
 * @param hostkey the hostkey to extract into the result.
 * @param result where to write the result.
 */
void getPublicKey(Hostkey hostkey,
		  PublicKey * result) {
  gcry_mpi_t skey[2];
  int size;
  int rc;
  
  lockGcrypt();
  rc = key_from_sexp(skey, 
		     HOSTKEY(hostkey), 
		     "public-key", 
		     "ne");
  if (rc)
    rc = key_from_sexp(skey, 
		       HOSTKEY(hostkey), 
		       "private-key", 
		       "ne");    
  if (rc)
    rc = key_from_sexp(skey, 
		       HOSTKEY(hostkey), 
		       "rsa", 
		       "ne");    
  if (rc) 
    DIE_GCRY("key_from_sexp", rc);
  
  result->len = htons(sizeof(PublicKey) - sizeof(result->padding));
  result->sizen = htons(RSA_ENC_LEN);
  result->padding = 0;
  size = RSA_ENC_LEN;
  rc = gcry_mpi_print(GCRYMPI_FMT_USG, 
		      &result->key[0], 
		      size,
		      &size, 
		      skey[0]);
  if (rc) 
    DIE_GCRY("gcry_mpi_print", rc);
  adjust(&result->key[0], size, RSA_ENC_LEN);
  size = RSA_KEY_LEN - RSA_ENC_LEN; 
  rc = gcry_mpi_print(GCRYMPI_FMT_USG, 
		      &result->key[RSA_ENC_LEN], 
		      size,
		      &size, 
		      skey[1]);
  if (rc) 
    DIE_GCRY("gcry_mpi_print", rc);
  adjust(&result->key[RSA_ENC_LEN], 
	 size,
	 RSA_KEY_LEN - RSA_ENC_LEN);
  unlockGcrypt();
}


/**
 * Internal: publicKey => RSA-Key
 */
static Hostkey public2Hostkey(const PublicKey * publicKey) {
  Hostkey ret;
  gcry_sexp_t result;
  gcry_mpi_t n;
  gcry_mpi_t e;
  size_t size;
  size_t erroff;
  int rc;

  if ( ( ntohs(publicKey->sizen) != RSA_ENC_LEN ) ||
       ( ntohs(publicKey->len) != sizeof(PublicKey) - sizeof(publicKey->padding)) ) {
    BREAK();
    return NULL;
  }
  size = RSA_ENC_LEN;
  lockGcrypt();
  rc = gcry_mpi_scan(&n,
		     GCRYMPI_FMT_USG,
		     &publicKey->key[0],
		     size,
		     &size);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    unlockGcrypt();
    return NULL;
  }
  size = RSA_KEY_LEN - RSA_ENC_LEN;
  rc = gcry_mpi_scan(&e,
		     GCRYMPI_FMT_USG,
		     &publicKey->key[RSA_ENC_LEN],
		     size,
		     &size);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release(n);
    unlockGcrypt();
    return NULL;
  }
  rc = gcry_sexp_build(&result, 
		       &erroff,
 		       "(public-key(rsa(n %m)(e %m)))",
		       n,
		       e);
  gcry_mpi_release(n);
  gcry_mpi_release(e);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc); /* erroff gives more info */
    unlockGcrypt();
    return NULL;
  }  
  unlockGcrypt();
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = result;
  return ret;
}

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @returns encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 */
HostKeyEncoded * encodeHostkey(Hostkey hostkey) {
  /* libgcrypt */

  HostKeyEncoded * retval;
  gcry_mpi_t pkv[6];
  void * pbu[6];
  size_t sizes[6];
  int rc;
  int i;
  int size;

  lockGcrypt();    
#if EXTRA_CHECKS
  if (gcry_pk_testkey(HOSTKEY(hostkey))) {
    BREAK();
    unlockGcrypt();
    return NULL;
  }
#endif

  memset(pkv, 0, sizeof(gcry_mpi_t) * 6);
  rc = key_from_sexp(pkv,
		     HOSTKEY(hostkey),
		     "private-key",
		     "nedpqu");
  if (rc)
    rc = key_from_sexp(pkv,
		       HOSTKEY(hostkey),
		       "rsa",
		       "nedpqu");
  if (rc) 
    rc = key_from_sexp(pkv,
		       HOSTKEY(hostkey),
		       "private-key",
		       "nedpq");
  if (rc)
    rc = key_from_sexp(pkv,
		       HOSTKEY(hostkey),
		       "rsa",
		       "nedpq");
  if (rc) 
    rc = key_from_sexp(pkv,
		       HOSTKEY(hostkey),
		       "private-key",
		       "ned");
  if (rc)
    rc = key_from_sexp(pkv,
		       HOSTKEY(hostkey),
		       "rsa",
		       "ned");
  if (rc) {
    LOG_GCRY(LOG_ERROR, "key_from_sexp", rc);
    unlockGcrypt();
    return NULL;
  }
  size = sizeof(HostKeyEncoded);
  for (i=0;i<6;i++) {
    if (pkv[i] != NULL) {
      rc = gcry_mpi_aprint(GCRYMPI_FMT_USG,
			   (unsigned char**) &pbu[i],
			   &sizes[i],
			   pkv[i]);
      size += sizes[i];
      if (rc) {
	LOG_GCRY(LOG_ERROR, "gcry_mpi_aprint", rc);
	while (i>0) 
	  if (pbu[i] != NULL)
	    free(pbu[--i]);	
	for (i=0;i<6;i++)
	  if (pkv[i] != NULL)
	    gcry_mpi_release(pkv[i]);
	unlockGcrypt();
	return NULL;
      }
    } else {
      pbu[i] = NULL;
      sizes[i] = 0;
    }
  }
  GNUNET_ASSERT(size < 65536);
  retval = MALLOC(size);
  retval->len = htons(size);
  i = 0;
  retval->sizen = htons(sizes[0]);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[0],
	 sizes[0]);
  i += sizes[0];
  retval->sizee = htons(sizes[1]);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[1],
	 sizes[1]);
  i += sizes[1];
  retval->sized = htons(sizes[2]);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[2],
	 sizes[2]);
  i += sizes[2];
  /* swap p and q! */
  retval->sizep = htons(sizes[4]);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[4],
	 sizes[4]);
  i += sizes[4];
  retval->sizeq = htons(sizes[3]);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[3],
	 sizes[3]);
  i += sizes[3];
  retval->sizedmp1 = htons(0);
  retval->sizedmq1 = htons(0);
  memcpy(&((HostKeyEncoded_GENERIC*)retval)->key[i], 
	 pbu[5],
	 sizes[5]);
  for (i=0;i<6;i++) {
    if (pkv[i] != NULL)
      gcry_mpi_release(pkv[i]);
    if (pbu[i] != NULL)
      free(pbu[i]);
  }
  unlockGcrypt();
  return retval;
}

/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 */
Hostkey decodeHostkey(const HostKeyEncoded * encoding) {
  Hostkey ret;
  gcry_sexp_t res;
  gcry_mpi_t n,e,d,p,q,u;
  int rc;
  size_t size;
  int pos;

  pos = 0;
  size = ntohs(encoding->sizen);
  lockGcrypt();
  rc = gcry_mpi_scan(&n,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		     size,
		     &size);
  pos += ntohs(encoding->sizen);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    unlockGcrypt();
    return NULL;
  }
  size = ntohs(encoding->sizee);
  rc = gcry_mpi_scan(&e,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		     size,
		     &size);
  pos += ntohs(encoding->sizee);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release(n);
    unlockGcrypt();
    return NULL;
  }
  size = ntohs(encoding->sized);
  rc = gcry_mpi_scan(&d,
		     GCRYMPI_FMT_USG,
		     &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		     size,
		     &size);
  pos += ntohs(encoding->sized);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    unlockGcrypt();
    return NULL;
  }
  /* swap p and q! */
  size = ntohs(encoding->sizep);
  if (size > 0) {
    rc = gcry_mpi_scan(&q,
		       GCRYMPI_FMT_USG,
		       &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		       size,
		       &size);
    pos += ntohs(encoding->sizep);
    if (rc) {
      LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      unlockGcrypt();
      return NULL;
    }
  } else
    q = NULL;
  size = ntohs(encoding->sizeq);
  if (size > 0) {
    rc = gcry_mpi_scan(&p,
		       GCRYMPI_FMT_USG,
		       &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		       size,
		       &size);
    pos += ntohs(encoding->sizeq);
    if (rc) {
      LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      if (q != NULL)
	gcry_mpi_release(q);
      unlockGcrypt();
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
		       &((HostKeyEncoded_GENERIC*)encoding)->key[pos],
		       size,
		       &size);
    if (rc) {
      LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release(n);
      gcry_mpi_release(e);
      gcry_mpi_release(d);
      if (p != NULL)
	gcry_mpi_release(p);
      if (q != NULL)
	gcry_mpi_release(q);
      unlockGcrypt();
      return NULL;
    }
  } else
    u = NULL;

  if ( (p != NULL) &&
       (q != NULL) &&
       (u != NULL) ) {
    rc = gcry_sexp_build(&res,
			 &size, /* erroff */
			 "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
			 n, e, d, p, q, u);
  } else {
    if ( (p != NULL) &&
	 (q != NULL) ) {
      rc = gcry_sexp_build(&res,
			   &size, /* erroff */
			   "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)))",
			   n, e, d, p, q);
    } else {
      rc = gcry_sexp_build(&res,
			   &size, /* erroff */
			   "(private-key(rsa(n %m)(e %m)(d %m)))",
			   n, e, d);
    }
  }
  gcry_mpi_release(n);
  gcry_mpi_release(e);
  gcry_mpi_release(d);
  if (p != NULL)
    gcry_mpi_release(p);
  if (q != NULL)
    gcry_mpi_release(q);
  if (u != NULL)
    gcry_mpi_release(u);

  if (rc) 
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc);
#if EXTRA_CHECKS
  if (gcry_pk_testkey(res)) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_testkey", rc);
    unlockGcrypt();
    return NULL;
  }
#endif
  ret = MALLOC(sizeof(Hostkey));
  HOSTKEYL(ret) = res;
  unlockGcrypt();
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
 */
int encryptHostkey(const void * block, 
		   unsigned short size,
		   const PublicKey * publicKey,
		   RSAEncryptedData * target) {
  gcry_sexp_t result;
  gcry_sexp_t data;
  Hostkey pubkey;
  gcry_mpi_t val;
  gcry_mpi_t rval;
  size_t isize;
  size_t erroff;
  int rc;
  
  pubkey = public2Hostkey(publicKey);
  isize = size;
  lockGcrypt();
  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     block,
		     isize,
		     &isize);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    freeHostkey(pubkey);
    unlockGcrypt();
    return SYSERR;
  }
  rc = gcry_sexp_build(&data,
		       &erroff,
		       "(data (flags pkcs1)(value %m))",
		       val);
  gcry_mpi_release(val);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc); /* more info in erroff */
    freeHostkey(pubkey);
    unlockGcrypt();
    return SYSERR;
  }
  
  rc = gcry_pk_encrypt(&result, data, HOSTKEY(pubkey));
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_encrypt", rc); 
    gcry_sexp_release(data);
    freeHostkey(pubkey);
    unlockGcrypt();
    return SYSERR;
  }
  gcry_sexp_release(data);
  freeHostkey(pubkey);

  rc = key_from_sexp(&rval,
		     result,
		     "rsa",
		     "a");
  gcry_sexp_release(result);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "key_from_sexp", rc);
    unlockGcrypt();
    return SYSERR;
  }
  isize = sizeof(RSAEncryptedData);
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      (char*)target,
		      isize,
		      &isize, 
		      rval);
  gcry_mpi_release(rval);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_print", rc);
    unlockGcrypt();
    return SYSERR;
  }
  adjust(&target->encoding[0],
	 isize,
	 sizeof(RSAEncryptedData));
  unlockGcrypt();
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
 */
int decryptHostkey(const Hostkey hostkey, 
		   const RSAEncryptedData * block,
		   void * result,
		   unsigned int max) {
  gcry_sexp_t resultsexp;
  gcry_sexp_t data;
  size_t erroff;
  size_t size;
  gcry_mpi_t val;
  int rc;
  char * endp;
  char * tmp;

  lockGcrypt();
#if EXTRA_CHECKS
  if (gcry_pk_testkey(HOSTKEY(hostkey))) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_testkey", rc);
    unlockGcrypt();
    return -1;
  }
#endif
  size = sizeof(RSAEncryptedData);
  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     &block->encoding[0],
		     size,
		     &size);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    unlockGcrypt();
    return SYSERR;
  }
  rc = gcry_sexp_build(&data,
		       &erroff,
		       "(enc-val(flags)(rsa(a %m)))",
		       val);
  gcry_mpi_release(val);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc); /* more info in erroff */
    unlockGcrypt();
    return SYSERR;
  }
  rc = gcry_pk_decrypt(&resultsexp,
		       data,
		       HOSTKEY(hostkey));
  gcry_sexp_release(data);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_decrypt", rc);
    unlockGcrypt();
    return SYSERR;
  }

  /* resultsexp has format "(value %m)" */
  val = gcry_sexp_nth_mpi(resultsexp, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release(resultsexp);
  if (val == NULL) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_nth_mpi", rc);
    unlockGcrypt();
    return SYSERR;
  }
  tmp = MALLOC(max + HOSTKEY_LEN/8);
  size = max+HOSTKEY_LEN/8;
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      tmp,
		      size,
		      &size,
		      val);
  gcry_mpi_release(val);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_print", rc);
    FREE(tmp);
    unlockGcrypt();
    return SYSERR;
  }

  endp = tmp;
  if (*endp == 0) {
    endp++;
    size--;
  }
  if ( (!size) || 
       (*endp != 0x02 )) {
    LOG(LOG_ERROR,
	_("Received plaintext not in pkcs-1 block type 2 format (size=%d, *tmp=%d)!\n"),
	size, (int)*tmp);
    FREE(tmp);
    unlockGcrypt();
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
	_("Received plaintext not in pkcs-1 block type 2 format (size=%d, *endp=%d)!\n"),
	size, (int) *endp);
    FREE(tmp);
    unlockGcrypt();
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
  unlockGcrypt();
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
 */
int sign(const Hostkey hostkey, 
	 unsigned short size,
	 const void * block,
	 Signature * sig) {
  gcry_sexp_t result;
  gcry_sexp_t data;
  size_t ssize;
  gcry_mpi_t rval;
  HashCode160 hc;
  char * buff;
  int bufSize;
  int rc;

  hash(block, size, &hc);
#define FORMATSTRING "(4:data(5:flags5:pkcs1)(4:hash6:rmd16020:01234567890123456789))"
  bufSize = strlen(FORMATSTRING) + 1;
  buff = MALLOC(bufSize);
  memcpy(buff,
	 FORMATSTRING,
	 bufSize);
  memcpy(&buff[bufSize - strlen("012345678901234567890))")],
	 &hc,
	 sizeof(HashCode160));
  lockGcrypt();
  rc = gcry_sexp_new(&data,
		     buff,
		     bufSize, 
		     0);
  FREE(buff);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_new", rc);
    unlockGcrypt();
    return SYSERR;
  }
  rc = gcry_pk_sign(&result, data, HOSTKEY(hostkey));
  gcry_sexp_release(data);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_pk_sign", rc);
    unlockGcrypt();
    return SYSERR;
  }
  rc = key_from_sexp(&rval,
		     result,
		     "rsa", 
		     "s");
  gcry_sexp_release(result);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "key_from_sexp", rc);
    unlockGcrypt();
    return SYSERR;
  }
  ssize = sizeof(Signature);
  rc = gcry_mpi_print(GCRYMPI_FMT_USG,
		      (char*)sig,
		      ssize,
		      &ssize,
		      rval);
  gcry_mpi_release(rval);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_print", rc);
    unlockGcrypt();
    return SYSERR;
  }
  adjust(&sig->sig[0], 
	 ssize,
	 sizeof(Signature));
  unlockGcrypt();
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
 */
int verifySig(const void * block,
	      unsigned short len,
	      const Signature * sig,	      
	      const PublicKey * publicKey) {
  gcry_sexp_t data;
  gcry_sexp_t sigdata;
  size_t size;
  gcry_mpi_t val;
  Hostkey hostkey;
  HashCode160 hc;
  char * buff;
  int bufSize;
  size_t erroff;
  int rc;
 
  size = sizeof(Signature);
  lockGcrypt();
  rc = gcry_mpi_scan(&val,
		     GCRYMPI_FMT_USG,
		     (char*)sig,
		     size,
		     &size);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_mpi_scan", rc);
    unlockGcrypt();
    return SYSERR;
  }
  rc = gcry_sexp_build(&sigdata,
		       &erroff,
		       "(sig-val(rsa(s %m)))",
		       val);
  gcry_mpi_release(val);
  if (rc) {
    LOG_GCRY(LOG_ERROR, "gcry_sexp_build", rc);
    unlockGcrypt();
    return SYSERR;
  }  
  hash(block, len, &hc);
  bufSize = strlen(FORMATSTRING) + 1;
  buff = MALLOC(bufSize);
  memcpy(buff,
	 FORMATSTRING,
	 bufSize);
  memcpy(&buff[strlen(FORMATSTRING) - strlen("01234567890123456789))")],
	 &hc,
	 sizeof(HashCode160));
  rc = gcry_sexp_new(&data,
		     buff,
		     bufSize, 
		     0);
  FREE(buff);
  hostkey = public2Hostkey(publicKey);
  rc = gcry_pk_verify(sigdata,
		      data,
		      HOSTKEY(hostkey));  
  freeHostkey(hostkey);
  gcry_sexp_release(data);
  gcry_sexp_release(sigdata);
  if (rc) {
    LOG(LOG_WARNING,
	_("RSA signature verification failed at %s:%d: %s\n"),
	__FILE__, __LINE__,
	gcry_strerror(rc));
    unlockGcrypt();
    return SYSERR;
  } else {
    unlockGcrypt();
    return OK;
  }
}


/* end of hostkey_gcrypt.c */
