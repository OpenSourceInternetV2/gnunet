/* rsa.h - RIPE-MD hash functions
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
#ifndef G10_RSA_H
#define G10_RSA_H

#include "mpi/mpi.h"

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

/**
 * Generate a key pair with a key of size NBITS.  
 * USE_E = 0 let Libcgrypt decide what exponent to use.
 *       = 1 request the use of a "secure" exponent; this is required by some 
 *           specification to be 65537.
 *       > 2 Try starting at this value until a working exponent is found.
 * Returns: 2 structures filled with all needed values
 **/
void rsa_generate(RSA_secret_key *sk,
		  unsigned int nbits,
		  unsigned long use_e);

/**
 * Encrypt data with pkey, stores result in *result.
 **/
void rsa_encrypt(MPI data, 
		 MPI * result,
		 RSA_secret_key *pkey);

int rsa_decrypt(MPI *result,
		MPI *data, 
		RSA_secret_key *sk);

int rsa_sign(MPI *resarr,
	     MPI data,
	     RSA_secret_key * sk);

int rsa_verify(MPI hash, 
	       MPI *data, 
	       RSA_secret_key * pk);

#endif /*G10_RSA_H*/

