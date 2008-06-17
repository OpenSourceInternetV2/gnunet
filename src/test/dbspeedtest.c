/*
 * A simple test routine measuring the linear seeking raw
 * file (fd) performance against gdbm when reading and 
 * writing fixed size data to/from random addresses (keys).
 * Also is measured the combination where both are done
 * in sequence (as in gnunets lookup+db combination). 
 *
 * Notes: we include open/close in the timings so that
 * the respective mechanisms couldn't cheat by e.g. delaying the
 * actual write to the close phase (as might be done by gdbm). And
 * that still doesn't rule out the possible cheating by the
 * underlying fs caches etc.
 * 
 */
/*
  Sample result (run by Christian):

gdbm wrote 500000, took 192 s
fd wrote 500000, took 893 s
fd+gdbm wrote 500000, took 2458 s
gdbm read 2000000, took 9395 s
fd read 2000000, took 2923 s
fd+gdbm read 2000000, took 20701 s

*/

#include <stdio.h>
#include <string.h>
#include <gdbm.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "gnunet_util.h"

#define BLOCKSIZE 1024
#define KEYLEN 160/8
#define ENTRIES 500000
#define SEED 1
#define LOOPS 4
#define GDBMOPTS GDBM_WRCREAT
/* #define GDBMOPTS GDBM_WRCREAT|GDBM_SYNC */
#define SHOW_GDBMSCALING 0


int randomi(int i) {
  return (int) (((float)i)*rand()/(RAND_MAX+1.0));
}

int * permute(int n) {
  int * ret;
  int i;
  int tmp;
  int x;    

  ret = malloc(n * sizeof(int));
  for (i=0;i<n;i++)
    ret[i] = i;
  for (i=0;i<n;i++) {
    x = randomi(n);
    tmp = ret[x];
    ret[x] = ret[i];
    ret[i] = tmp;
  }
  return ret;
}


int main(int argc, char *argv[]) {
	int fd, i, j;
	char test[BLOCKSIZE];
	datum key;
	datum data;
	GDBM_FILE gd;
	TIME_T starttime, endtime, now, prev;
	int *perm;

	UNLINK("data.gdbm");
	UNLINK("data.dat");
	
	/* test gdbm write */
	
	srand(SEED);
	perm=permute(ENTRIES);
	TIME(&starttime);
	prev=starttime;
	gd=gdbm_open("data.gdbm", 0, GDBMOPTS, 0664, NULL);
	for(i=0;i<ENTRIES;i++) {
	  memset(test, 0, KEYLEN);
	  sprintf(test, "%d", perm[i]);
	  key.dptr=test;
	  key.dsize=KEYLEN;
	  data.dptr=test;
	  data.dsize=BLOCKSIZE;
	  gdbm_store(gd, key, data, GDBM_REPLACE);
#if SHOW_GDBMSCALING
	  if(i % 10000 == 0) {
	    TIME(&now);
	    printf("gdbm at %d took %ld s\n", i, (int)now-prev);
	    prev=now;
	  }	
#endif
    }
	gdbm_close(gd);
	TIME(&endtime);
	free(perm);
	
	printf("gdbm wrote %d, took %ld s\n", ENTRIES, (int)endtime-starttime);

	/* test fd write */

	srand(SEED);
	perm=permute(ENTRIES);
	TIME(&starttime);
	fd=OPEN("data.dat", O_RDWR|O_CREAT, 0664);
    ftruncate(fd, ENTRIES*BLOCKSIZE);
	for(i=0;i<ENTRIES;i++) {
	  memset(test, 0, KEYLEN);
	  sprintf(test, "%d", perm[i]);
	  lseek(fd, perm[i]*BLOCKSIZE, SEEK_SET);
	  WRITE(fd, test, BLOCKSIZE);
	}
	close(fd);
	TIME(&endtime);
	free(perm);
	
	printf("fd wrote %d, took %ld s\n", ENTRIES, (int)endtime-starttime);
	
	/* test comb write */
	
	UNLINK("data.gdbm");
	UNLINK("data.dat");

	srand(SEED);
	perm=permute(ENTRIES);
	TIME(&starttime);
	gd=gdbm_open("data.gdbm", 0, GDBMOPTS, 0664, NULL);
	fd=OPEN("data.dat", O_RDWR|O_CREAT, 0664);
    ftruncate(fd, ENTRIES*BLOCKSIZE);
	for(i=0;i<ENTRIES;i++) {
	  memset(test, 0, KEYLEN);
	  sprintf(test, "%d", perm[i]);
	  lseek(fd, perm[i]*BLOCKSIZE, SEEK_SET);
	  WRITE(fd, test, BLOCKSIZE);
	  key.dptr=test;
	  key.dsize=KEYLEN;
	  data.dptr=test;
	  data.dsize=BLOCKSIZE;
	  gdbm_store(gd, key, data, GDBM_REPLACE);
    }
	close(fd);
	gdbm_close(gd);
	TIME(&endtime);
	free(perm);
	
	printf("fd+gdbm wrote %d, took %ld s\n", ENTRIES, (int)endtime-starttime);
	
	/* test gdbm read */

	srand(SEED+1);		/* don't read in writing order */
	TIME(&starttime);
	gd=gdbm_open("data.gdbm", 0, GDBMOPTS, 0664, NULL);
	for(j=0;j<LOOPS;j++) {
		perm=permute(ENTRIES);
		for(i=0;i<ENTRIES;i++) {
	      memset(test, 0, KEYLEN);
	      sprintf(test, "%d", perm[i]);
		  key.dptr=test;
		  key.dsize=KEYLEN;
		  data=gdbm_fetch(gd, key);
		  free(data.dptr); 
		}
		free(perm);
	}	
	gdbm_close(gd);
	TIME(&endtime);
		
	printf("gdbm read %d, took %ld s\n", LOOPS*ENTRIES, (int)endtime-starttime);
	
	/* test fd read */
	
	srand(SEED+1);
	TIME(&starttime);
	fd=OPEN("data.dat", O_RDWR|O_CREAT, 0664);
	for(j=0;j<LOOPS;j++) {
		perm=permute(ENTRIES);
		for(i=0;i<ENTRIES;i++) {
	  	  memset(test, 0, KEYLEN);
		  lseek(fd, perm[i]*BLOCKSIZE, SEEK_SET);
		  READ(fd, test, BLOCKSIZE);
		}
		free(perm);
	}
	close(fd);
	TIME(&endtime);
	
	printf("fd read %d, took %ld s\n", LOOPS*ENTRIES, (int)endtime-starttime);

	/* test comb read */
	
	srand(SEED+1);
	TIME(&starttime);
	gd=gdbm_open("data.gdbm", 0, GDBMOPTS, 0664, NULL);
	fd=OPEN("data.dat", O_RDWR|O_CREAT, 0664);
	for(j=0;j<LOOPS;j++) {
		perm=permute(ENTRIES);
		for(i=0;i<ENTRIES;i++) {
		  lseek(fd, perm[i]*BLOCKSIZE, SEEK_SET);
		  READ(fd, test, BLOCKSIZE);
	  	  memset(test, 0, KEYLEN);
		  sprintf(test, "%d", perm[i]);
		  key.dptr=test;
		  key.dsize=KEYLEN;
		  data=gdbm_fetch(gd, key);
		  free(data.dptr); 
		}
		free(perm);
	}
	close(fd);
	gdbm_close(gd);
	TIME(&endtime);
	
	printf("fd+gdbm read %d, took %ld s\n", LOOPS*ENTRIES, (int)endtime-starttime);

	return(0);
}
