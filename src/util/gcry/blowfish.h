/* rmd.h - RIPE-MD hash functions
 *	Copyright (C) 1998, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_BLOWFISH_H
#define G10_BLOWFISH_H

#include "g10lib.h"

#define BLOWFISH_BLOCKSIZE 8
#define BLOWFISH_ROUNDS 16

typedef struct {
    u32 s0[256];
    u32 s1[256];
    u32 s2[256];
    u32 s3[256];
    u32 p[BLOWFISH_ROUNDS+2];

  byte iv[BLOWFISH_BLOCKSIZE];	/* (this should be ulong aligned) */
  byte lastiv[BLOWFISH_BLOCKSIZE];
    unsigned  unused;  /* in IV */
} BLOWFISH_context;

int
do_bf_setkey (BLOWFISH_context *c, 
	      const byte *key, 
	      unsigned keylen);

void
cipher_setiv( BLOWFISH_context * c, 
	      const byte *iv, 
	      unsigned ivlen );

void
do_cfb_encrypt( BLOWFISH_context * c,
                byte *outbuf, 
		const byte *inbuf, 
		unsigned nbytes );

void
do_cfb_decrypt( BLOWFISH_context * c,
                byte *outbuf, const byte *inbuf, unsigned nbytes);

#endif /*G10_BLOWFISH_H*/

