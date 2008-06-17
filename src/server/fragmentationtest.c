/*
     This file is part of GNUnet
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/testfragmentation.c
 * @brief test for fragmentation.c
 * @author Christian Grothoff
 */

/**
 * Testcase for defragmentation code.
 * We have testcases for:
 * - 2 fragments, aligned, [0,16),[16,32)
 * - n (50) fragments, [i*16,(i+1)*16)
 * - n (50) fragments, [0,i*16) + [50*16,51*16)
 * - n (100) fragments, inserted in interleaved order (holes in sequence)
 * - holes in sequence
 * - other overlaps
 * - timeouts
 * - multiple entries in hash-list
 * - id collisions in hash-list
 */

/* -- to speed up the testcases -- */
#define DEFRAGMENTATION_TIMEOUT (1 * cronSECONDS)

#include "gnunet_util.h"
#include "fragmentation.c"

static HostIdentity mySender;
static char * myMsg;
static unsigned short myMsgLen;

/* static buffers to avoid lots of malloc/free */
static char masterBuffer[65536];
static char resultBuffer[65536];

void handleHelper(const char * msg,
		  const HostIdentity * sender,
		  const unsigned int len,
		  const int crc) {
  GNUNET_ASSERT(crc32N(msg, len) == crc);
  GNUNET_ASSERT(hostIdentityEquals(sender, &mySender));
  myMsg = resultBuffer;
  memcpy(resultBuffer, msg, len);
  myMsgLen = len;
}

/**
 * Wait long enough to force all fragments to timeout.
 */
static void makeTimeout() {
  gnunet_util_sleep(DEFRAGMENTATION_TIMEOUT*2);
  defragmentationPurgeCron();
}

/**
 * Create a fragment. The data-portion will be filled
 * with a sequence of numbers from start+id to start+len-1+id.
 * 
 * @param pep pointer to the ethernet frame/buffer
 * @param ip pointer to the ip-header
 * @param start starting-offset
 * @param length of the data portion
 * @param id the identity of the fragment
 */
static p2p_HEADER * makeFragment(unsigned short start,
				 unsigned short size,
				 unsigned short tot,
				 int id) {
  FRAGMENT_Message * frag;
  int i;
  
  frag      = (FRAGMENT_Message*) masterBuffer;
  frag->id  = htonl(id);
  frag->off = htons(start);
  frag->len = htons(tot);
  frag->header.size
    = htons(sizeof(FRAGMENT_Message) + size);
  
  for (i=0;i<size;i++) 
    ((FRAGMENT_Message_GENERIC*)frag)->data[i] 
      = (char)i+id+start;
  return &frag->header;
}

/**
 * Check that the packet received is what we expected to
 * get.
 * @param id the expected id
 * @param len the expected length
 */
static void checkPacket(int id, 
			unsigned int len) {
  int i;

  GNUNET_ASSERT(myMsg != NULL);
  GNUNET_ASSERT(myMsgLen == len);
  for (i=0;i<len;i++) 
    GNUNET_ASSERT(myMsg[i] == (char) (i+id));  
  myMsgLen = 0;
  myMsg = NULL;
}


/* **************** actual testcases ***************** */

static void testSimpleFragment() {
  p2p_HEADER * pep;

  pep = makeFragment(0, 16, 32, 42);
  processFragment(&mySender, pep);
  GNUNET_ASSERT(myMsg == NULL);
  pep = makeFragment(16, 16, 32, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 32);
}

static void testSimpleFragmentTimeout() {
  p2p_HEADER * pep;

  pep = makeFragment(0, 16, 32, 42);
  processFragment(&mySender, pep);
  GNUNET_ASSERT(myMsg == NULL);
  makeTimeout();
  pep = makeFragment(16, 16, 32, 42);
  processFragment(&mySender, pep);
  GNUNET_ASSERT(myMsg == NULL);
  pep = makeFragment(0, 16, 32, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 32);
}

static void testSimpleFragmentReverse() {
  p2p_HEADER * pep;
  
  pep = makeFragment(16, 16, 32, 42);
  processFragment(&mySender, pep);
  GNUNET_ASSERT(myMsg == NULL);
  pep = makeFragment(0, 16, 32, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 32);
}

static void testManyFragments() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<50;i++) {
    pep = makeFragment(i*16, 16, 51*16, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(50*16,16, 51*16, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 51*16);
}

static void testManyFragmentsMegaLarge() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<4000;i++) {
    pep = makeFragment(i*16, 16, 4001*16, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(4000*16, 16, 4001*16, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 4001*16);
}

static void testLastFragmentEarly() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<5;i++) {
    pep = makeFragment(i*16, 8, 6*16+8, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(5*16, 24, 6*16+8, 42);
  processFragment(&mySender, pep);
  for (i=0;i<5;i++) {
    pep = makeFragment(i*16+8, 8, 6*16+8, 42);
    processFragment(&mySender, pep);
  }
  checkPacket(42, 6*16+8);
}

static void testManyInterleavedFragments() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<50;i++) {
    pep = makeFragment(i*16, 8, 51*16+8, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  for (i=0;i<50;i++) {
    pep = makeFragment(i*16+8, 8, 51*16+8, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(50*16, 24, 51*16+8, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 51*16+8);
}

static void testManyInterleavedOverlappingFragments() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<50;i++) {
    pep = makeFragment(i*32, 16, 51*32, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  for (i=0;i<50;i++) {
    pep = makeFragment(i*32+8, 24, 51*32, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(50*32, 32, 51*32, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 51*32);
}

static void testManyOverlappingFragments() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<50;i++) {
    pep = makeFragment(0, i*16+16, 51*16, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  pep = makeFragment(50*16,16, 51*16, 42);
  processFragment(&mySender, pep);
  checkPacket(42, 51*16);
}

static void testManyOverlappingFragmentsTimeout() {
  p2p_HEADER * pep;
  int i;

  for (i=0;i<50;i++) {
    pep = makeFragment(0, i*16+16, 51*16+8, 42);
    processFragment(&mySender, pep);
    GNUNET_ASSERT(myMsg == NULL);
  }
  makeTimeout();
  pep = makeFragment(50*16, 24, 51*16+8, 42);
  processFragment(&mySender, pep);
  GNUNET_ASSERT(myMsg == NULL);
  for (i=0;i<50;i++) {
    pep = makeFragment(0, i*16+16, 51*16+8, 42);
    processFragment(&mySender, pep);
  }
  checkPacket(42, 51*16+8);
}

static void testManyFragmentsMultiId() {
  p2p_HEADER * pep;
  int i;
  int id;

  for (i=0;i<50;i++) {
    for (id=0;id<DEFRAG_BUCKET_COUNT;id++) {
      pep = makeFragment(i*16, 16, 51*16, id+5);
      mySender.hashPubKey.a = id;
      processFragment(&mySender, pep);
      GNUNET_ASSERT(myMsg == NULL);
    }
  }
  for (id=0;id<DEFRAG_BUCKET_COUNT;id++) {
    pep = makeFragment(50*16, 16, 51*16, id+5);
    mySender.hashPubKey.a = id;
    processFragment(&mySender, pep);
    checkPacket(id+5, 51*16);
  }
}

static void testManyFragmentsMultiIdCollisions() {
  p2p_HEADER * pep;
  int i;
  int id;

  for (i=0;i<5;i++) {
    for (id=0;id<DEFRAG_BUCKET_COUNT*4;id++) {
      pep = makeFragment(i*16, 16, 6*16, id+5);
      mySender.hashPubKey.a = id;
      processFragment(&mySender, pep);
      GNUNET_ASSERT(myMsg == NULL);
    }
  }
  for (id=0;id<DEFRAG_BUCKET_COUNT*4;id++) {
    pep = makeFragment(5*16, 16, 6*16, id+5);
    mySender.hashPubKey.a = id;
    processFragment(&mySender, pep);
    checkPacket(id+5, 6*16);
  }
}

/* ************* driver ****************** */

int registerp2pHandler(const unsigned short type,
		       MessagePartHandler callback) {
  return OK;
}

int unregisterp2pHandler(const unsigned short type,
			 MessagePartHandler callback) {
  return OK;
}


/**
 * Perform option parsing from the command line. 
 */
static int parser(int argc, 
		  char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  return OK;
}

int main(int argc, char * argv[]){
  if (OK != initUtil(argc, argv, &parser)) 
    return SYSERR;  
  initFragmentation();
  
  testSimpleFragment();
  testSimpleFragmentTimeout();
  testSimpleFragmentReverse();
  testManyFragments();
  testManyFragmentsMegaLarge();
  testManyFragmentsMultiId();

  testManyInterleavedFragments();
  testManyInterleavedOverlappingFragments();
  testManyOverlappingFragments();
  testManyOverlappingFragmentsTimeout();
  testLastFragmentEarly();
  testManyFragmentsMultiIdCollisions();
  
  doneFragmentation();
  doneUtil();
  return 0; /* testcase passed */
}
