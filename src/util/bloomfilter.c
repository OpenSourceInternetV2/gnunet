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
 * @file util/bloomfilter.c
 * @brief data structure used to reduce disk accesses.
 *
 * The idea basically: Create a signature for each element in the
 * database. Add those signatures to a bit array. When doing a lookup,
 * check if the bit array matches the signature of the requested
 * element. If yes, address the disk, otherwise return 'not found'.
 *
 * A property of the bloom filter is that sometimes we will have
 * a match even if the element is not on the disk (then we do
 * an unnecessary disk access), but what's most important is that 
 * we never get a single "false negative".
 *
 * To be able to delete entries from the bloom filter, we maintain
 * a 4 bit counter in the file on the drive (we still use only one
 * bit in memory).
 *
 * @author Igor Wronsky
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

/**
 * Sets a bit active in the bitArray. Increment bit-specific
 * usage counter on disk only if below 4bit max (==15).
 * 
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void setBit(char * bitArray, 
		   unsigned int bitIdx) {
  unsigned int arraySlot;
  unsigned int targetBit;

  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));  
  bitArray[arraySlot] |= targetBit;
}

/**
 * Clears a bit from bitArray. Bit is cleared from the array 
 * only if the respective usage counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to unset
 */
static void clearBit(char * bitArray, 
		     unsigned int bitIdx) {
  unsigned int slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8)); 
  bitArray[slot] = bitArray[slot] & (~targetBit);
}

/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return YES if the bit is set, NO if not.
 */
static int testBit(char * bitArray, 
		   unsigned int bitIdx) {
  unsigned int slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8)); 
  if (bitArray[slot] & targetBit)
    return YES;  
  else
    return NO;
}

/**
 * Sets a bit active in the bitArray and increments
 * bit-specific usage counter on disk (but only if 
 * the counter was below 4 bit max (==15)).
 * 
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fd A file to keep the 4 bit address usage counters in
 */
static void incrementBit(char * bitArray, 
			 unsigned int bitIdx, 
			 int fd) {
  unsigned int fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  setBit(bitArray, bitIdx);
  /* Update the counter file on disk */
  GNUNET_ASSERT(fd != -1);
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;
  
  if (fileSlot != (unsigned int) lseek(fd, fileSlot, SEEK_SET))
    DIE_STRERROR("lseek");
  value = 0;
  READ(fd, 
       &value, 
       1);
  
  low = value & 0xF;
  high = (value & (~0xF)) >> 4;
  
  if (targetLoc == 0) {
    if (low < 0xF)
      low++;
  } else {
    if (high < 0xF)
      high++;
  }
  value = ((high<<4) | low);
  if (fileSlot != (unsigned int) lseek(fd, fileSlot, SEEK_SET))
    DIE_STRERROR("lseek");
  if (1 != WRITE(fd, &value, 1))
    DIE_STRERROR("write");
}

/**
 * Clears a bit from bitArray if the respective usage 
 * counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fd A file to keep the 4bit address usage counters in
 */
static void decrementBit(char * bitArray, 
			 unsigned int bitIdx,
			 int fd) {
  unsigned int fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  GNUNET_ASSERT(fd != -1);
  /* Each char slot in the counter file holds two 4 bit counters */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;
  
  lseek(fd, fileSlot, SEEK_SET);
  value = 0;
  READ(fd, &value, 1);
  
  low  = value & 0xF;
  high = (value & 0xF0) >> 4;
  
  /* decrement, but once we have reached the max, never go back! */
  if (targetLoc == 0) {
    if ( (low > 0) && (low < 0xF) )
      low--;
    if (low == 0) {
       clearBit(bitArray, bitIdx);
    } 
  } else {
    if ( (high > 0) && (high < 0xF) )
      high--;
    if (high == 0) {
      clearBit(bitArray, bitIdx);
    }
  }
  value = ((high<<4) | low);
  lseek(fd, fileSlot, SEEK_SET);
  if (1 != WRITE(fd, &value, 1))
    DIE_STRERROR("write");
}

#define BUFFSIZE 65536

/**
 * Creates a file filled with zeroes
 *
 * @param fd the file handle
 * @param size the size of the file
 * @return OK if created ok, SYSERR otherwise
 */
static int makeEmptyFile(int fd,
			 unsigned int size) {
  char * buffer;
  unsigned int bytesleft=size;
  int res = 0;

  if (fd == -1)
    return SYSERR;
  buffer = (char*)MALLOC(BUFFSIZE);
  memset(buffer, 0, BUFFSIZE);
  lseek(fd, 0, SEEK_SET);

  while (bytesleft > 0) {
    if (bytesleft>BUFFSIZE) {
      res = WRITE(fd, buffer, BUFFSIZE);
      bytesleft -= BUFFSIZE;
    } else {
      res = WRITE(fd, buffer, bytesleft);
      bytesleft = 0;
    }
    if(res == -1) {
      LOG_STRERROR(LOG_WARNING, "write");
      FREE(buffer);
      return SYSERR;
    }
  }
  FREE(buffer);
  return OK;
}

/* ************** Bloomfilter hash iterator ********* */

/**
 * Iterator (callback) method to be called by the
 * bloomfilter iterator on each bit that is to be
 * set or tested for the key.
 *
 * @param bf the filter to manipulate
 * @param bit the current bit
 * @param additional context specific argument
 */
typedef void (*BitIterator)(Bloomfilter * bf,
			    unsigned int bit,
			    void * arg);
			    
/**
 * Call an iterator for each bit that the bloomfilter
 * must test or set for this element.
 *
 * @param bf the filter
 * @param callback the method to call
 * @param arg extra argument to callback
 * @param key the key for which we iterate over the BF bits
 */
static void iterateBits(Bloomfilter * bf,
			BitIterator callback,
			void * arg,
			const HashCode160 * key) {
  HashCode160 tmp[2];
  int bitCount;
  int round;
  unsigned int slot=0;

  bitCount = bf->addressesPerElement;
  memcpy(&tmp[0],
	 key,
	 sizeof(HashCode160));
  round = 0;
  while (bitCount > 0) {
    while (slot < (sizeof(HashCode160)/sizeof(unsigned int))) {
      callback(bf, 
	       (((unsigned int*)&tmp[round&1])[slot]) & ((bf->bitArraySize*8)-1), 
	       arg);
      slot++;
      bitCount--;
      if (bitCount == 0)
	break;
    }
    if (bitCount > 0) {
      hash(&tmp[round & 1],
	   sizeof(HashCode160),
	   &tmp[(round+1) & 1]);
      round++;
      slot = 0;
    }
  }
}

/**
 * Callback: increment bit
 *
 * @param bf the filter to manipulate
 * @param bit the bit to increment
 * @param arg not used
 */
static void incrementBitCallback(Bloomfilter * bf,
				 unsigned int bit,
				 void * arg) {
  incrementBit(bf->bitArray,
	       bit,
	       bf->fd);
}

/**
 * Callback: decrement bit
 *
 * @param bf the filter to manipulate
 * @param bit the bit to decrement
 * @param arg not used
 */
static void decrementBitCallback(Bloomfilter * bf,
				 unsigned int bit,
				 void * arg) {
  decrementBit(bf->bitArray,
	       bit,
	       bf->fd);
}

/**
 * Callback: test if all bits are set
 *
 * @param bf the filter 
 * @param bit the bit to test
 * @param arg pointer set to NO if bit is not set
 */
static void testBitCallback(const Bloomfilter * bf,
			    unsigned int bit,
			    int * arg) {
  if (NO == testBit(bf->bitArray,
		    bit))
    *arg = NO;
}

/* *********************** INTERFACE **************** */

/**
 * Load a bloom-filter from a file.
 *
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
Bloomfilter * loadBloomfilter(const char * filename,
			      unsigned int size,
			      unsigned int k) {
  Bloomfilter * bf;
  char * rbuff;
  unsigned int pos;
  int i;
  unsigned int ui;

  if ( (filename == NULL) || 
       (k==0) || 
       (size==0) )
    return NULL;
  if (size < BUFFSIZE)
    size = BUFFSIZE;
  ui = 1;
  while (ui < size)
    ui*=2;
  size = ui; /* make sure it's a power of 2 */ 

  bf = (Bloomfilter *) MALLOC(sizeof(Bloomfilter));

  /* Try to open a bloomfilter file */
#ifndef _MSC_VER
  bf->fd = OPEN(filename, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
#else
  bf->fd = OPEN(filename, O_WRONLY|O_CREAT, S_IREAD|S_IWRITE);
#endif
  if (-1 == bf->fd) {
    LOG_FILE_STRERROR(LOG_FAILURE, "open", filename);
    FREE(bf);
    return NULL;    
  }

  /* Alloc block */
  MUTEX_CREATE_RECURSIVE(&bf->lock);
  bf->bitArray 
    = (char *) xmalloc_unchecked_(size, __FILE__, __LINE__);
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  memset(bf->bitArray, 
	 0, 
	 bf->bitArraySize);
 
  /* Read from the file what bits we can */
  rbuff = (char*)MALLOC(BUFFSIZE);
  pos = 0;
  while (pos < size*8) {
    int res;
    
    res = READ(bf->fd,
	       rbuff, 
	       BUFFSIZE);
    if (res == 0)
      break; /* is ok! we just did not use that many bits yet */
    for (i=0;i<res;i++) {
      if ( (rbuff[i] & 0x0F) != 0)
	setBit(bf->bitArray,
	       pos + i*2);
      if ( (rbuff[i] & 0xF0) != 0)
	setBit(bf->bitArray,
	       pos + i*2 + 1);
    }     
    if (res < BUFFSIZE)
      break;
    pos += BUFFSIZE * 2; /* 2 bits per byte in the buffer */
  }
  /* find last component of file path */
  for (i=strlen(filename);i>0;i--)
    if (filename[i] == DIR_SEPARATOR) {
      i++;
      break;
    }
  /* create some statistics handles */
#if VERBOSE_STATS
  SNPRINTF(rbuff, 
	   BUFFSIZE,
	   _("# Bloomfilter (%s) hits"),
	   &filename[i]);
  bf->statHandle_hits
    = statHandle(rbuff);
  SNPRINTF(rbuff, 
	   BUFFSIZE,
	   _("# Bloomfilter (%s) misses"), 
	   &filename[i]);
  bf->statHandle_misses
    = statHandle(rbuff);
  SNPRINTF(rbuff, 
	   BUFFSIZE,
	   _("# Bloomfilter (%s) additions"), 
	   &filename[i]);
  bf->statHandle_adds
    = statHandle(rbuff);
  SNPRINTF(rbuff,
	   BUFFSIZE,
	   _("# Bloomfilter (%s) deletions"), 
	   &filename[i]);
  bf->statHandle_dels
    = statHandle(rbuff);
#endif
  FREE(rbuff);
  return bf;
}

/**
 * Free the space associated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 *
 * @param bf the filter
 */
void freeBloomfilter(Bloomfilter * bf) {
  if (NULL == bf)
    return;
  MUTEX_DESTROY(&bf->lock);
#if VERBOSE_STATS
  statSet(bf->statHandle_hits, 0);   /* if we realloc w/ same stat name later */
  statSet(bf->statHandle_misses, 0);
  statSet(bf->statHandle_adds, 0);
  statSet(bf->statHandle_dels, 0);
#endif
  CLOSE(bf->fd);
  FREE(bf->bitArray);
  FREE(bf);
}

/**
 * Reset a bloom filter to empty. Clears the file on disk.
 *
 * @param bf the filter
 */
void resetBloomfilter(Bloomfilter * bf) {
  if (NULL == bf)
    return;

  MUTEX_LOCK(&bf->lock);
  memset(bf->bitArray, 
	 0, 
	 bf->bitArraySize);
  makeEmptyFile(bf->fd,
		bf->bitArraySize * 4);
#if VERBOSE_STATS
  statSet(bf->statHandle_hits, 0);
  statSet(bf->statHandle_misses, 0);
  statSet(bf->statHandle_adds, 0);
  statSet(bf->statHandle_dels, 0);
#endif
  MUTEX_UNLOCK(&bf->lock);
}


/**
 * Test if an element is in the filter.
 *
 * @param e the element
 * @param bf the filter
 * @return YES if the element is in the filter, NO if not
 */
int testBloomfilter(Bloomfilter * bf,
		    const HashCode160 * e) {
  int res;

  if (NULL == bf) 
    return YES;
  MUTEX_LOCK(&bf->lock);
  res = YES;
  iterateBits(bf, 
	      (BitIterator)&testBitCallback,
	      &res,
	      e);
#if VERBOSE_STATS
  if (res == YES)
    statChange(bf->statHandle_hits, 1);
  else
    statChange(bf->statHandle_misses, 1);
#endif
  MUTEX_UNLOCK(&bf->lock);
  return res;
}

/**
 * Add an element to the filter
 *
 * @param bf the filter
 * @param e the element
 */
void addToBloomfilter(Bloomfilter * bf,
		      const HashCode160 * e) {

  if (NULL == bf) 
    return;
  MUTEX_LOCK(&bf->lock);
  iterateBits(bf,
	      &incrementBitCallback,
	      NULL,
	      e);
#if VERBOSE_STATS
  statChange(bf->statHandle_adds, 1);
#endif
  MUTEX_UNLOCK(&bf->lock);
}

/**
 * Remove an element from the filter.
 *
 * @param bf the filter
 * @param e the element to remove
 */
void delFromBloomfilter(Bloomfilter * bf,
			const HashCode160 * e) {
  if(NULL == bf) 
    return;
  MUTEX_LOCK(&bf->lock);
  iterateBits(bf,
	      &decrementBitCallback,
	      NULL,
	      e);
#if VERBOSE_STATS
  statChange(bf->statHandle_dels, 1);
#endif
  MUTEX_UNLOCK(&bf->lock);
}

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_arg argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of hash-function to apply per element
 */
void resizeBloomfilter(Bloomfilter * bf,
		       ElementIterator iterator,
		       void * iterator_arg,
		       unsigned int size,
		       unsigned int k) {
  HashCode160 * e;
  unsigned int i;

  MUTEX_LOCK(&bf->lock);
  FREE(bf->bitArray);
  i = 1;
  while (i < size)
    i*=2;
  size = i; /* make sure it's a power of 2 */ 

  bf->bitArraySize = size;
  bf->bitArray = (char*)MALLOC(size);
  memset(bf->bitArray, 
	 0, 
	 bf->bitArraySize);
  makeEmptyFile(bf->fd,
		bf->bitArraySize * 4);
  e = iterator(iterator_arg);
  while (e != NULL) {
    addToBloomfilter(bf,
		     e);
    FREE(e);
    e = iterator(iterator_arg);
  }
  MUTEX_UNLOCK(&bf->lock);
}

/* ******************** end of bloomfilter.c *********** */
