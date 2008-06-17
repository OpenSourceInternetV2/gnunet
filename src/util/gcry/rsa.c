/* rsa.c  -  RSA function
 *	Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
 *	Copyright (C) 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
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
 *
 * Adopted for GNUnet by Christian Grothoff <grothoff@cs.purdue.edu> on 5/24/3
 */

/* This code uses an algorithm protected by U.S. Patent #4,405,829
   which expired on September 20, 2000.  The patent holder placed that
   patent into the public domain on Sep 6th, 2000.
*/

#include "platform.h"
#include "g10lib.h"
#include "rsa.h"

/* Callback used by the prime generation to test whether the exponent
   is suitable. Returns 0 if the test has been passed. */
static int
check_exponent (void *arg, MPI a) {
  MPI e = arg;
  MPI tmp;
  int result;
  
  mpi_sub_ui (a, a, 1);
  tmp = _gcry_mpi_alloc_like (a);
  result = !gcry_mpi_gcd(tmp, e, a); /* GCD is not 1. */
  gcry_mpi_release (tmp);
  mpi_add_ui (a, a, 1);
  return result;
}


/**
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
static void
public(MPI output, 
       MPI input, 
       RSA_secret_key *pkey ) {
    if( output == input ) { /* powm doesn't like output and input the same */
	MPI x = mpi_alloc( mpi_get_nlimbs(input)*2 );
	mpi_powm( x, input, pkey->e, pkey->n );
	mpi_set(output, x);
	mpi_free(x);
    }
    else
	mpi_powm( output, input, pkey->e, pkey->n );
}



/**
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Or faster:
 *
 *      m1 = c ^ (d mod (p-1)) mod p 
 *      m2 = c ^ (d mod (q-1)) mod q 
 *      h = u * (m2 - m1) mod q 
 *      m = m1 + h * p
 *
 * Where m is OUTPUT, c is INPUT and d,n,p,q,u are elements of SKEY.
 **/
static void
secret(MPI output, MPI input, RSA_secret_key *skey )
{
  #if 0
    mpi_powm( output, input, skey->d, skey->n );
  #else
    MPI m1   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI m2   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI h    = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );

    /* m1 = c ^ (d mod (p-1)) mod p */
    mpi_sub_ui( h, skey->p, 1  );
    mpi_fdiv_r( h, skey->d, h );   
    mpi_powm( m1, input, h, skey->p );
    /* m2 = c ^ (d mod (q-1)) mod q */
    mpi_sub_ui( h, skey->q, 1  );
    mpi_fdiv_r( h, skey->d, h );
    mpi_powm( m2, input, h, skey->q );
    /* h = u * ( m2 - m1 ) mod q */
    mpi_sub( h, m2, m1 );
    if ( mpi_is_neg( h ) ) 
        mpi_add ( h, h, skey->q );
    mpi_mulm( h, skey->u, h, skey->q ); 
    /* m = m2 + h * p */
    mpi_mul ( h, h, skey->p );
    mpi_add ( output, m1, h );
    /* ready */
    
    mpi_free ( h );
    mpi_free ( m1 );
    mpi_free ( m2 );
  #endif
}

static void
test_keys(RSA_secret_key *sk, 
	  unsigned nbits ) {
    MPI test = gcry_mpi_new ( nbits );
    MPI out1 = gcry_mpi_new ( nbits );
    MPI out2 = gcry_mpi_new ( nbits );

    gcry_mpi_randomize(test,
		       nbits,
		       GCRY_WEAK_RANDOM );

    public( out1, test, sk );
    secret( out2, out1, sk );
    if( mpi_cmp( test, out2 ) ) {
      fprintf(stderr,
	      "RSA operation: public, secret failed\n");
      exit(-1);
    }
    secret( out1, test, sk );
    public( out2, out1, sk );
    if( mpi_cmp( test, out2 ) ) {
      fprintf(stderr,
	      "RSA operation: secret, public failed\n");
      exit(-1);
    }
    gcry_mpi_release ( test );
    gcry_mpi_release ( out1 );
    gcry_mpi_release ( out2 );
}




/*********************************************
 **************  interface  ******************
 *********************************************/

/**
 * Generate a key pair with a key of size NBITS.  
 * USE_E = 0 let Libcgrypt decide what exponent to use.
 *       = 1 request the use of a "secure" exponent; this is required by some 
 *           specification to be 65537.
 *       > 2 Try starting at this value until a working exponent is found.
 * Returns: 2 structures filled with all needed values
 */
void rsa_generate(RSA_secret_key *sk, 
		  unsigned int nbits,
		  unsigned long use_e) {
    MPI p, q; /* the two primes */
    MPI d;    /* the private key */
    MPI u;
    MPI t1, t2;
    MPI n;    /* the public key */
    MPI e;    /* the exponent */
    MPI phi;  /* helper: (p-1)(q-1) */
    MPI g;
    MPI f;

    /* make sure that nbits is even so that we generate p, q of equal size */
    if ( (nbits&1) )
      nbits++; 

    if (use_e == 1)   /* Alias for a secure value. */
      use_e = 65537;  /* as demanded by Spinx. */

    /* Public exponent:
       In general we use 41 as this is quite fast and more secure than the
       commonly used 17.  Benchmarking the RSA verify function
       with a 1024 bit key yields (2001-11-08): 
         e=17    0.54 ms
         e=41    0.75 ms
         e=257   0.95 ms
         e=65537 1.80 ms
    */
    e = mpi_alloc( (32+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    if (!use_e)
      mpi_set_ui (e, 41);     /* This is a reasonable secure and fast value */
    else 
      {
        use_e |= 1; /* make sure this is odd */
        mpi_set_ui (e, use_e); 
      }
    
    n = gcry_mpi_new (nbits);

    p = q = NULL;
    do {
      /* select two (very secret) primes */
      if (p)
        gcry_mpi_release (p);
      if (q)
        gcry_mpi_release (q);
      if (use_e)
        { /* Do an extra test to ensure that the given exponent is
             suitable. */
          p = _gcry_generate_secret_prime (nbits/2, check_exponent, e);
          q = _gcry_generate_secret_prime (nbits/2, check_exponent, e);
        }
      else
        { /* We check the exponent later. */
          p = _gcry_generate_secret_prime (nbits/2, NULL, NULL);
          q = _gcry_generate_secret_prime (nbits/2, NULL, NULL);
        }
      if (mpi_cmp (p, q) > 0 ) /* p shall be smaller than q (for calc of u)*/
        mpi_swap(p,q);
      /* calculate the modulus */
      mpi_mul( n, p, q );
    } while ( mpi_get_nbits(n) != nbits );

    /* calculate Euler totient: phi = (p-1)(q-1) */
    t1 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    t2 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    phi = gcry_mpi_snew ( nbits );
    g	= gcry_mpi_snew ( nbits );
    f	= gcry_mpi_snew ( nbits );
    mpi_sub_ui( t1, p, 1 );
    mpi_sub_ui( t2, q, 1 );
    mpi_mul( phi, t1, t2 );
    gcry_mpi_gcd(g, t1, t2);
    mpi_fdiv_q(f, phi, g);

    while (!gcry_mpi_gcd(t1, e, phi)) /* (while gcd is not 1) */
      {
        mpi_add_ui (e, e, 2);
      }

    /* calculate the secret key d = e^1 mod phi */
    d = gcry_mpi_snew ( nbits );
    mpi_invm(d, e, f );
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/
    u = gcry_mpi_snew ( nbits );
    mpi_invm(u, p, q );

    gcry_mpi_release (t1);
    gcry_mpi_release (t2);
    gcry_mpi_release (phi);
    gcry_mpi_release (f);
    gcry_mpi_release (g);

    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;
    sk->u = u;

    /* now we can test our keys (this should never fail!) */
    test_keys(sk, nbits - 64);
}

/**
 * Encrypt data with pkey, stores result in *result.
 **/
void rsa_encrypt (MPI data, 
		  MPI * result,
		  RSA_secret_key *pk) {
  *result = mpi_alloc(mpi_get_nlimbs(pk->n));
  public(*result, data, pk);
}

int rsa_decrypt (MPI *result,
		 MPI *data, 
		 RSA_secret_key *sk) {
    GcryMPI x = MPI_NULL;	/* Data to decrypt.  */
    GcryMPI y;			/* Result.  */

    y = gcry_mpi_snew (gcry_mpi_get_nbits (sk->n));
    x = data[0];
    /* Do the encryption.  */
    secret (y, x, sk);
    /* Copy out result.  */
    *result = y;
    return 0;
}

int rsa_sign(MPI *resarr,
	     MPI data,
	     RSA_secret_key * sk) {
  resarr[0] = mpi_alloc(mpi_get_nlimbs( sk->n ));
  secret(resarr[0], data, sk);
  return 0;
}

int rsa_verify(MPI hash, 
	       MPI *data, 
	       RSA_secret_key * pk) {
    MPI result;
    int rc;

    result = gcry_mpi_new (160);
    public(result, data[0], pk );
    rc = mpi_cmp(result, hash) ? GCRYERR_BAD_SIGNATURE : 0;
    gcry_mpi_release (result);

    return rc;
}

/* end of rsa.c */
