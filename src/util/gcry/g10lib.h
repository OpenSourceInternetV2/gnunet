/* g10lib.h -  internal defintions for libgcrypt
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 * This header is to be used inside of libgcrypt in place of gcrypt.h.
 * This way we can better distinguish between internal and external
 * usage of gcrypt.h
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#ifndef G10LIB_H
#define G10LIB_H 1

#ifdef _GCRYPT_H
#error  gcrypt.h already included
#endif

#include "types.h"

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define JNLIB_GCC_M_FUNCTION 1
# define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
# define JNLIB_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
# define JNLIB_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
# define GCC_ATTR_NORETURN  __attribute__ ((__noreturn__))
#else
# define JNLIB_GCC_A_NR
# define JNLIB_GCC_A_PRINTF( f, a )
# define JNLIB_GCC_A_NR_PRINTF( f, a )
# define GCC_ATTR_NORETURN 
#endif

#define _(a)  (a)
#define N_(a) (a)


/*-- cipher/pubkey.c --*/

#ifndef DID_MPI_TYPEDEF
 typedef struct gcry_mpi * MPI;
 #define DID_MPI_TYPEDEF
#endif

#ifndef mpi_powm
   #define mpi_powm(w,b,e,m)   gcry_mpi_powm( (w), (b), (e), (m) )
#endif

int string_to_pubkey_algo( const char *string );
const char * pubkey_algo_to_string( int algo );
unsigned pubkey_nbits( int algo, MPI *pkey );

/*-- primegen.c --*/
MPI _gcry_generate_secret_prime (unsigned int nbits,
                                 int (*extra_check)(void*, MPI),
                                 void *extra_check_arg);
MPI _gcry_generate_public_prime (unsigned int nbits,
                                 int (*extra_check)(void*, MPI),
                                 void *extra_check_arg);
MPI _gcry_generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
					   MPI g, MPI **factors );




/* macros used to rename missing functions */
#ifndef HAVE_STRTOUL
  #define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
  #define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_ATEXIT
  #define atexit(a)    (on_exit((a),0))
#endif
#ifndef HAVE_RAISE
  #define raise(a) kill(getpid(), (a))
#endif


/* some handy macros */
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

/* Stack burning.  */

void _gcry_burn_stack (int bytes);

/* Digit predicates.  */

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define octdigitp(p) (*(p) >= '0' && *(p) <= '7')
#define alphap(a)    (   (*(a) >= 'A' && *(a) <= 'Z')  \
                      || (*(a) >= 'a' && *(a) <= 'z'))
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))

/* Management for ciphers/digests/pubkey-ciphers.  */

/* Structure for each registered `module'.  */
struct gcry_module
{
  struct gcry_module *next;     /* List pointers.      */
  struct gcry_module **prevp;
  void *spec;			/* The acctual specs.  */
  int flags;			/* Associated flags.   */
  int counter;			/* Use counter.        */
};

typedef struct gcry_module GcryModule;

/* Flags for the `flags' member of GcryModule.  */
#define FLAG_MODULE_DISABLED 1 << 0

int _gcry_module_add (GcryModule **entries, void *spec,
		      GcryModule **module);

typedef int (*GcryModuleLookup) (void *spec, void *data);

/* Internal function.  Lookup a module specification.  */
GcryModule *_gcry_module_lookup (GcryModule *entries, void *data,
				 GcryModuleLookup func);

/* Public function.  Release a module.  In case the use-counter
   reaches zero, destroy the module.  */
void _gcry_module_release (GcryModule *entry);

/* Public function.  Add a reference to a module.  */
void _gcry_module_use (GcryModule *module);

#endif /* G10LIB_H */
