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
 * @file util/hashing.c
 * @brief RIPE160MD hash related functions
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"

#if ! (USE_OPENSSL || USE_GCRYPT)
#define USE_GCRY 1
#include "gcry/rmd.h"
#endif

#if USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ripemd.h>
#endif

#if USE_GCRYPT
#include <gcrypt.h>
#endif

/**
 * Hash block of given size.
 * @param block the data to hash, length is given as a second argument
 * @param size the length of the data to hash
 * @param ret pointer to where to write the hashcode
 **/
void hash(void * block,
	  int size,
	  HashCode160 * ret) {
#if USE_OPENSSL
  RIPEMD160(block, size, (unsigned char*) ret);
#else
#if USE_GCRYPT
  gcry_md_hash_buffer(GCRY_MD_RMD160,
		      (char*) ret,
		      block,
		      size);
#else
  gcry_rmd160_hash_buffer((char*)ret,
			  block,
			  size);
#endif
#endif
}

/**
 * Compute the hash of an entire file.  Does NOT load the entire file
 * into memory but instead processes it in blocks.  Very important for
 * large files.
 *
 * @return OK on success, SYSERR on error
 */
int getFileHash(char * filename,
		HashCode160 * ret) {
  char * buf;
  unsigned int len;
  unsigned int pos;
  unsigned int delta;
  int fh;
#if USE_GCRYPT
  gcry_md_hd_t hd;
  char * res;

  if (0 != gcry_md_open(&hd,
			GCRY_MD_RMD160,
			0))
    return SYSERR;
#endif
#if USE_GCRY
  RMD160_CONTEXT hd;
  _gcry_rmd160_init(&hd);
#endif
#if USE_OPENSSL
  RIPEMD160_CTX hd;  
  RIPEMD160_Init(&hd);
#endif

  fh = OPEN(filename, O_RDONLY);
  if (fh == -1) {
#if USE_GCRYPT
    gcry_md_close(hd);
#endif
#if USE_OPENSSL
    RIPEMD160_Final((unsigned char*)ret,
		    &hd);
#endif
    return SYSERR;
  }
  pos = 0;
  buf = MALLOC(65536);
  len = getFileSize(filename);
  while (pos < len) {
    delta = 65536;
    if (len - pos < delta)
      delta = len-pos;
    if (delta != READ(fh,
		      buf,
		      delta)) {
      CLOSE(fh);
#if USE_GCRYPT
      gcry_md_close(hd);
#endif
#if USE_OPENSSL
      RIPEMD160_Final((unsigned char*)ret,
		      &hd);
#endif
      FREE(buf);
      return SYSERR;
    }
#if USE_GCRYPT  
    gcry_md_write(hd,
		  buf,
		  delta);
#endif
#if USE_GCRY
    rmd160_write(&hd,
		 buf,
		 delta);
#endif
#if USE_OPENSSL
    RIPEMD160_Update(&hd,
		     buf,
		     delta);
#endif
    pos += delta;
  }
  CLOSE(fh);
#if USE_GCRYPT
  res = gcry_md_read(hd, 0);
  memcpy(ret,
	 res,
	 sizeof(HashCode160));
  gcry_md_close(hd);
#endif
#if USE_GCRY
  rmd160_final(&hd);
  memcpy(ret,
	 hd.buf,
	 sizeof(HashCode160));
#endif
#if USE_OPENSSL
  RIPEMD160_Final((unsigned char*)ret,
		  &hd);
#endif
  FREE(buf);
  return OK;
}


static unsigned char * encoding__ = "0123456789ABCDEF";

/**
 * Convert (hash) block to hex (= filename)
 * @param block the sequence to convert
 * @param result where to store thestring (0-terminated), hex-encoding
 **/
void hash2hex(const HashCode160 * block,
	      HexName * result) {
  unsigned int i;
  unsigned int j;
  unsigned char c;
  unsigned char clow;

  if ((block == NULL) || (result == NULL)) 
    errexit("hash2hex called with block or result NULL!\n");

  result->data[sizeof(HashCode160)*2]=0;
  j=0;
  for (i=0;i<sizeof(HashCode160);i++) {
    c = ((unsigned char *)block)[i]; 
    clow = c & 15; /* get lower nibble */
    result->data[j++] = encoding__[clow];
    clow = c >> 4; /* get higher nibble */
    result->data[j++] = encoding__[clow];
  }  
}

/**
 * Convert hex (filename) to the hostIdentity
 * @param hex the filename
 * @param hash is set to the correspoinding host identity
 **/
void hex2hash(HexName * hex,
	      HashCode160 * hash) {
  unsigned int i;
  unsigned int j;
  unsigned char c;
  unsigned char clow;
  unsigned char chigh;

  if ((hex == NULL) || (hash == NULL)) 
    errexit("hex2hash called with hex or hash NULL!");  
  if (strlen((char*)hex) != sizeof(HashCode160)*2) 
    errexit("assertion failed: strlen(hex) is not %d\n",
	    sizeof(HashCode160)*2);
  
  j=0;
  i=0;
  while (i<sizeof(HashCode160)*2) {
    clow = hex->data[i++];
    if ( (clow >= 'A') && (clow <= 'Z') )
      clow = clow - 'A' + 10;
    else if ( (clow >= '0') && (clow <= '9') )
      clow = clow - '0';
    else
      errexit("hex2hash called with hex not consisting of characters [A-Z][0-9]\n");
    chigh = hex->data[i++];    
    if ( (chigh >= 'A') && (chigh <= 'Z') )
      chigh = chigh - 'A' + 10;
    else if ( (chigh >= '0') && (chigh <= '9') )
      chigh = chigh - '0';
    else
      errexit("hex2hash called with hex not consisting of characters [A-Z][0-9]\n");
    c = clow + (chigh << 4);
    ((unsigned char *)hash)[j++] = c;
  }  
}

/**
 * Convert ch to a hex sequence.  If ch is a HexName, the hex is
 * converted back to a HashCode.  If ch is NULL or an empty string, a
 * random Id is generated.  Otherwise, the hash of the string "ch" is
 * used.
 */
void tryhex2hashOrHashString(char * ch,
			     HashCode160 * hc) {
  if ( (ch == NULL) || (ch[0] == '\0') ) {
    makeRandomId(hc);
    return;
  }
  if (SYSERR == tryhex2hash(ch, hc))
    hash(ch, strlen(ch), hc);
}

/**
 * Try converting a hex to a hash.
 * @param ch the hex sequence
 * @param hash the resulting hash code
 * @return OK on success, SYSERR on error
 **/
int tryhex2hash(char * ch,
		HashCode160 * hash) {
  unsigned int i;
  unsigned int j;
  unsigned char c;
  unsigned char clow;
  unsigned char chigh;

  if ((ch == NULL) || (hash == NULL)) 
    errexit("tryhex2hash called with hex or hash NULL!");  
  if (strlen(ch) != sizeof(HashCode160)*2) {
    LOG(LOG_EVERYTHING,
	"EVERYTHING: string has wrong length (%u) for tryhex2hash.\n",
	strlen(ch));
    return SYSERR;
  }
  
  j=0;
  i=0;
  while (i<sizeof(HashCode160)*2) {
    clow = ch[i++];
    if ( (clow >= 'A') && (clow <= 'Z') )
      clow = clow - 'A' + 10;
    else if ( (clow >= '0') && (clow <= '9') )
      clow = clow - '0';
    else {
      LOG(LOG_EVERYTHING,
	  "EVERYTHING: string has unexpected character (%d) for tryhex2hash.\n",
	  ch[i-1]);
      return SYSERR;
    }
    chigh = ch[i++];    
    if ( (chigh >= 'A') && (chigh <= 'Z') )
      chigh = chigh - 'A' + 10;
    else if ( (chigh >= '0') && (chigh <= '9') )
      chigh = chigh - '0';
    else {
      LOG(LOG_EVERYTHING,
	  "EVERYTHING: string has unexpected character (%d) for tryhex2hash.\n",
	  ch[i-1]);
      return SYSERR;
    }
    c = clow + (chigh << 4);
    ((unsigned char *)hash)[j++] = c;
  }  
  return OK;
}


/**
 * Compute the distance between 2 hashcodes.  The computation must be
 * fast, not involve a.a or a.e (they're used elsewhere), and be
 * somewhat consistent. And of course, the result should be a positive
 * number.
 *
 * @returns a positive number which is a measure for 
 *  hashcode proximity.
 **/
int distanceHashCode160(HashCode160 * a, 
			HashCode160 * b) {
  int x = (a->b - b->b)>>16;
  return ((x*x)>>16);
}

/**
 * Compare two hashcodes.
 * @return 1 if they are equal, 0 if not.
 **/
int equalsHashCode160(const HashCode160 * a, 
		      const HashCode160 * b) {
  return (0 == memcmp(a,b,sizeof(HashCode160)));
}

void makeRandomId(HashCode160 * result) {
  result->a = rand();
  result->b = rand();
  result->c = rand();
  result->d = rand();
  result->e = rand();
}

void deltaId(HashCode160 * a,
	     HashCode160 * b,
	     HashCode160 * result) {
  result->a = b->a - a->a;
  result->b = b->b - a->b;
  result->c = b->c - a->c;
  result->d = b->d - a->d;
  result->e = b->e - a->e;
}

void addHashCodes(HashCode160 * a,
		  HashCode160 * delta,
		  HashCode160 * result) {
  result->a = delta->a + a->a;
  result->b = delta->b + a->b;
  result->c = delta->c + a->c;
  result->d = delta->d + a->d;
  result->e = delta->e + a->e;
}

void xorHashCodes(HashCode160 * a,
		  HashCode160 * b,
		  HashCode160 * result) {
  result->a = b->a ^ a->a;
  result->b = b->b ^ a->b;
  result->c = b->c ^ a->c;
  result->d = b->d ^ a->d;
  result->e = b->e ^ a->e;
}

/**
 * Convert a hashcode into a key.
 **/
void hashToKey(HashCode160 * hc,
	       SESSIONKEY * skey,
	       unsigned char * iv) {
  memcpy(skey,
	 hc,
	 sizeof(SESSIONKEY));
  memcpy(iv, 
	 &(((char *)hc)[BF_KEYSIZE]), 
	 BLOWFISH_BLOCK_LENGTH/2);
  memcpy(&iv[BLOWFISH_BLOCK_LENGTH/2], 
	 &(((char *)hc)[BF_KEYSIZE]),
         BLOWFISH_BLOCK_LENGTH/2);
}




/* end of hashing.c */
