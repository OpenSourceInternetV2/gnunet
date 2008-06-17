/**
 * @file test/hostkeytest.c
 * @brief testcase for RSA public key crypto (hostkey.h)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL 20
#define ITER 10

static int testEncryptDecrypt() {
  Hostkey hostkey;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok;

  fprintf(stderr, "W");
  hostkey = makeHostkey();
  getPublicKey(hostkey, &pkey);

  ok = 0;
  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    if (SYSERR == encryptHostkey(TESTSTRING,
				 strlen(TESTSTRING)+1,
				 &pkey,
				 &target)) {
      fprintf(stderr, 
	      "encryptHostkey returned SYSERR\n");
      ok++;
      continue;
    }
    if (-1 == decryptHostkey(hostkey,
			     &target, 
			     result,
			     MAX_TESTVAL)) {
     fprintf(stderr, 
	      "decryptHostkey returned SYSERR\n");
      ok++;
      continue;
    }
    if (strncmp(TESTSTRING, result,
		strlen(TESTSTRING)) != 0) {
      printf("%s != %.*s - testEncryptDecrypt failed!\n",
	     TESTSTRING, 
	     MAX_TESTVAL, 
	     result);
      ok++;
      continue;
    }
  }
  printf("%d RSA encrypt/decrypt operations %ds (%d failures)\n", 
	 ITER,
	 (int) (TIME(NULL)-start),
	 ok);
  freeHostkey(hostkey);
  if (ok == 0)
    return OK;
  else
    return SYSERR;
}

static int testSignVerify() {
  Hostkey hostkey;
  Signature sig;
  PublicKey pkey;
  int i;
  TIME_T start;
  int ok = OK;
  
  fprintf(stderr, "W");
  hostkey = makeHostkey();
  getPublicKey(hostkey, &pkey);
  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    if (SYSERR == sign(hostkey, strlen(TESTSTRING), TESTSTRING, &sig)) {
      fprintf(stderr,
	      "sign returned SYSERR\n");
      ok = SYSERR;
      continue;
    }
    if (SYSERR == verifySig(TESTSTRING, strlen(TESTSTRING), &sig, &pkey)) {
      printf("testSignVerify failed!\n");
      ok = SYSERR;
      continue;
    }
  }
  printf("%d RSA sign/verify operations %ds\n", 
	 ITER, 
	 (int) (TIME(NULL)-start));
  freeHostkey(hostkey);
  return ok;
}

static int testHostkeyEncoding() {
  Hostkey hostkey;
  HostKeyEncoded * encoding;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok = OK;

  fprintf(stderr, "W");
  hostkey = makeHostkey();

  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    getPublicKey(hostkey, &pkey);
    if (SYSERR == encryptHostkey(TESTSTRING,
				 strlen(TESTSTRING)+1,
				 &pkey,
				 &target)) {
      fprintf(stderr,
	      "encryptHostkey returned SYSERR\n");
      ok = SYSERR;
      continue;
    }
    encoding = encodeHostkey(hostkey);
    freeHostkey(hostkey);
    if (encoding == NULL) {
      fprintf(stderr,
	      "encodeHostkey returned NULL\n");
      ok = SYSERR;
      continue;
    }
    hostkey = decodeHostkey(encoding);
    FREE(encoding);
    if (SYSERR == decryptHostkey(hostkey, &target, result, MAX_TESTVAL)) {
      fprintf(stderr,
	      "decryptHostkey returned SYSERR\n");
      ok = SYSERR;
      continue;
    }  
    if (strncmp(TESTSTRING, result,
		strlen(TESTSTRING)) != 0) {
      printf("%s != %.*s - testEncryptDecrypt failed!\n",
	     TESTSTRING, 
	     (int) strlen(TESTSTRING), 
	     result);
      ok = SYSERR;
      continue;
    }
  }  
  freeHostkey(hostkey);
  printf("%d RSA encrypt/encode/decode/decrypt operations %ds\n", 
	 ITER, 
	 (int) (TIME(NULL)-start));
  return ok;
}

void initRAND(); /* hostkey_* */
void initStatistics();
void doneStatistics();

#if ! USE_OPENSSL
void initLockingGcrypt();
void doneLockingGcrypt();
#endif

int main(int argc, char * argv[]) {
  int failureCount = 0;

#if USE_GCRYPT
  initLockingGcrypt();
#endif
  initRAND();  
  initStatistics(); 
  if (OK != testEncryptDecrypt())
     failureCount++;
  if (OK != testSignVerify())
    failureCount++;       
  if (OK != testHostkeyEncoding()) 
    failureCount++;
  doneStatistics();
#if USE_GCRYPT
  doneLockingGcrypt();
#endif

  if (failureCount == 0)
    return 0;
  else {
    printf("\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  }
} /* end of main*/
