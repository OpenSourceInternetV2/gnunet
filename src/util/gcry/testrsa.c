/**
 * @file util/gcry/testrsa.c
 * @brief testcase for RSA encryption
 * @author Christian Grothoff
 **/

#include "platform.h"
#include "rsa.h"

#define NBITS 512
#define ITER 100

void check(int i) {
  if (i) {
    fprintf(stderr,
	    "assert failed, aborting\n");
    exit(-1);
  }
}

int testEncryptDecrypt() {
  RSA_secret_key key;
  unsigned char * frame = NULL;
  size_t nframe = (NBITS+7) / 8;
  int i;
  int j;
  MPI val;
  MPI rval;
  MPI rrval;
  int ret = 0;

  frame = malloc(nframe);
  frame[0] = 0x0; /* lowest byte MUST by 0 */
  rsa_generate(&key,
	       NBITS,
	       257 /* e */);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, "."); /* progress */
    for (j=1;j<nframe;j++)
      frame[j] = rand() % 256;
    check(gcry_mpi_scan(&val,
			GCRYMPI_FMT_USG,
			frame,
			&nframe));
    rsa_encrypt(val, &rval, &key);
    check(rsa_decrypt(&rrval, &rval, &key));
    if ( mpi_cmp( val, rrval ) ) {
      size_t size = nframe;
      fprintf(stderr,
	      "rsa_decrypt returned bad result\n");
      fprintf(stderr,
	      "INPUT : ");
      for (j=0;j<nframe;j++)
	fprintf(stderr, "%2x ", frame[j]);
      check(gcry_mpi_print(GCRYMPI_FMT_USG,
			   frame,
			   &size,
			   rrval));	
      fprintf(stderr,
	      "\nOUTPUT: ");
      for (j=0;j<nframe;j++)
	fprintf(stderr, "%2x ", frame[j]);
      ret++;
    }
    gcry_mpi_release (val);
    gcry_mpi_release (rval);
    gcry_mpi_release (rrval);
  }
  if (key.n != NULL)
    gcry_mpi_release(key.n);
  if (key.e != NULL)
    gcry_mpi_release(key.e);
  if (key.p != NULL)
    gcry_mpi_release(key.p);
  if (key.q != NULL)
    gcry_mpi_release(key.q);
  if (key.d != NULL)
    gcry_mpi_release(key.d);
  if (key.u != NULL)
    gcry_mpi_release(key.u);
  free(frame);
  fprintf(stderr, "\n");
  return ret;
  
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  failureCount += testEncryptDecrypt(); 

  if (failureCount == 0) {
    return 0;
  } else {
    fprintf(stderr,
            "\n\n%d TESTS FAILED!\n\n",
	    failureCount);
    return -1;
  }
} /* end of main */
