/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/containers/bloomfilter.c
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

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_containers.h"

typedef struct GNUNET_BloomFilter
{

  /**
   * Concurrency control
   */
  struct GNUNET_Mutex *lock;

  /**
   * The actual bloomfilter bit array
   */
  char *bitArray;

  /**
   * For error handling.
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * Filename of the filter
   */
  char *filename;

  /**
   * The bit counter file on disk
   */
  int fd;

  /**
   * How many bits we set for each stored element
   */
  unsigned int addressesPerElement;

  /**
   * Size of bitArray in bytes
   */
  unsigned int bitArraySize;

} Bloomfilter;


/**
 * Sets a bit active in the bitArray. Increment bit-specific
 * usage counter on disk only if below 4bit max (==15).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void
setBit (char *bitArray, unsigned int bitIdx)
{
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
static void
clearBit (char *bitArray, unsigned int bitIdx)
{
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
 * @return GNUNET_YES if the bit is set, GNUNET_NO if not.
 */
static int
testBit (char *bitArray, unsigned int bitIdx)
{
  unsigned int slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  if (bitArray[slot] & targetBit)
    return GNUNET_YES;
  else
    return GNUNET_NO;
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
static void
incrementBit (char *bitArray, unsigned int bitIdx, int fd)
{
  unsigned int fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  setBit (bitArray, bitIdx);
  if (fd == -1)
    return;
  /* Update the counter file on disk */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;

  if (fileSlot != (unsigned int) LSEEK (fd, fileSlot, SEEK_SET))
    GNUNET_GE_DIE_STRERROR (NULL,
                            GNUNET_GE_ADMIN | GNUNET_GE_USER | GNUNET_GE_FATAL
                            | GNUNET_GE_IMMEDIATE, "lseek");
  value = 0;
  READ (fd, &value, 1);

  low = value & 0xF;
  high = (value & (~0xF)) >> 4;

  if (targetLoc == 0)
    {
      if (low < 0xF)
        low++;
    }
  else
    {
      if (high < 0xF)
        high++;
    }
  value = ((high << 4) | low);
  if (fileSlot != (unsigned int) LSEEK (fd, fileSlot, SEEK_SET))
    GNUNET_GE_DIE_STRERROR (NULL,
                            GNUNET_GE_ADMIN | GNUNET_GE_USER | GNUNET_GE_FATAL
                            | GNUNET_GE_IMMEDIATE, "lseek");
  if (1 != WRITE (fd, &value, 1))
    GNUNET_GE_DIE_STRERROR (NULL,
                            GNUNET_GE_ADMIN | GNUNET_GE_USER | GNUNET_GE_FATAL
                            | GNUNET_GE_IMMEDIATE, "write");

}

/**
 * Clears a bit from bitArray if the respective usage
 * counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fd A file to keep the 4bit address usage counters in
 */
static void
decrementBit (char *bitArray, unsigned int bitIdx, int fd)
{
  unsigned int fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  if (fd == -1)
    return;                     /* cannot decrement! */
  GNUNET_GE_ASSERT (NULL, fd != -1);
  /* Each char slot in the counter file holds two 4 bit counters */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;
  LSEEK (fd, fileSlot, SEEK_SET);
  value = 0;
  READ (fd, &value, 1);

  low = value & 0xF;
  high = (value & 0xF0) >> 4;

  /* decrement, but once we have reached the max, never go back! */
  if (targetLoc == 0)
    {
      if ((low > 0) && (low < 0xF))
        low--;
      if (low == 0)
        {
          clearBit (bitArray, bitIdx);
        }
    }
  else
    {
      if ((high > 0) && (high < 0xF))
        high--;
      if (high == 0)
        {
          clearBit (bitArray, bitIdx);
        }
    }
  value = ((high << 4) | low);
  LSEEK (fd, fileSlot, SEEK_SET);
  if (1 != WRITE (fd, &value, 1))
    GNUNET_GE_DIE_STRERROR (NULL,
                            GNUNET_GE_ADMIN | GNUNET_GE_USER | GNUNET_GE_FATAL
                            | GNUNET_GE_IMMEDIATE, "write");
}

#define BUFFSIZE 65536

/**
 * Creates a file filled with zeroes
 *
 * @param fd the file handle
 * @param size the size of the file
 * @return GNUNET_OK if created ok, GNUNET_SYSERR otherwise
 */
static int
makeEmptyFile (int fd, unsigned int size)
{
  char *buffer;
  unsigned int bytesleft = size;
  int res = 0;

  if (fd == -1)
    return GNUNET_SYSERR;
  buffer = GNUNET_malloc (BUFFSIZE);
  memset (buffer, 0, BUFFSIZE);
  LSEEK (fd, 0, SEEK_SET);

  while (bytesleft > 0)
    {
      if (bytesleft > BUFFSIZE)
        {
          res = WRITE (fd, buffer, BUFFSIZE);
          bytesleft -= BUFFSIZE;
        }
      else
        {
          res = WRITE (fd, buffer, bytesleft);
          bytesleft = 0;
        }
      if (res == -1)
        {
          GNUNET_GE_DIE_STRERROR (NULL,
                                  GNUNET_GE_ADMIN | GNUNET_GE_USER |
                                  GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE,
                                  "write");
          GNUNET_free (buffer);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (buffer);
  return GNUNET_OK;
}

/* ************** GNUNET_BloomFilter GNUNET_hash iterator ********* */

/**
 * Iterator (callback) method to be called by the
 * bloomfilter iterator on each bit that is to be
 * set or tested for the key.
 *
 * @param bf the filter to manipulate
 * @param bit the current bit
 * @param additional context specific argument
 */
typedef void (*BitIterator) (Bloomfilter * bf, unsigned int bit, void *arg);

/**
 * Call an iterator for each bit that the bloomfilter
 * must test or set for this element.
 *
 * @param bf the filter
 * @param callback the method to call
 * @param arg extra argument to callback
 * @param key the key for which we iterate over the BF bits
 */
static void
iterateBits (Bloomfilter * bf,
             BitIterator callback, void *arg, const GNUNET_HashCode * key)
{
  GNUNET_HashCode tmp[2];
  int bitCount;
  int round;
  unsigned int slot = 0;

  bitCount = bf->addressesPerElement;
  memcpy (&tmp[0], key, sizeof (GNUNET_HashCode));
  round = 0;
  while (bitCount > 0)
    {
      while (slot < (sizeof (GNUNET_HashCode) / sizeof (unsigned int)))
        {
          callback (bf,
                    (((unsigned int *) &tmp[round & 1])[slot]) &
                    ((bf->bitArraySize * 8) - 1), arg);
          slot++;
          bitCount--;
          if (bitCount == 0)
            break;
        }
      if (bitCount > 0)
        {
          GNUNET_hash (&tmp[round & 1], sizeof (GNUNET_HashCode),
                       &tmp[(round + 1) & 1]);
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
static void
incrementBitCallback (Bloomfilter * bf, unsigned int bit, void *arg)
{
  incrementBit (bf->bitArray, bit, bf->fd);
}

/**
 * Callback: decrement bit
 *
 * @param bf the filter to manipulate
 * @param bit the bit to decrement
 * @param arg not used
 */
static void
decrementBitCallback (Bloomfilter * bf, unsigned int bit, void *arg)
{
  decrementBit (bf->bitArray, bit, bf->fd);
}

/**
 * Callback: test if all bits are set
 *
 * @param bf the filter
 * @param bit the bit to test
 * @param arg pointer set to GNUNET_NO if bit is not set
 */
static void
testBitCallback (Bloomfilter * bf, unsigned int bit, void *cls)
{
  int *arg = cls;
  if (GNUNET_NO == testBit (bf->bitArray, bit))
    *arg = GNUNET_NO;
}

/* *********************** INTERFACE **************** */

/**
 * Load a bloom-filter from a file.
 *
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of GNUNET_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
Bloomfilter *
GNUNET_bloomfilter_load (struct GNUNET_GE_Context *ectx,
                         const char *filename, unsigned int size,
                         unsigned int k)
{
  Bloomfilter *bf;
  char *rbuff;
  unsigned int pos;
  int i;
  unsigned int ui;

  if ((k == 0) || (size == 0))
    return NULL;
  if (size < BUFFSIZE)
    size = BUFFSIZE;
  ui = 1;
  while (ui < size)
    ui *= 2;
  size = ui;                    /* make sure it's a power of 2 */

  bf = GNUNET_malloc (sizeof (Bloomfilter));
  bf->ectx = ectx;
  /* Try to open a bloomfilter file */
  if (filename != NULL)
    {
#ifndef _MSC_VER
      bf->fd = GNUNET_disk_file_open (ectx,
                                      filename, O_RDWR | O_CREAT,
                                      S_IRUSR | S_IWUSR);
#else
      bf->fd = GNUNET_disk_file_open (ectx,
                                      filename,
                                      O_WRONLY | O_CREAT, S_IREAD | S_IWRITE);
#endif
      if (-1 == bf->fd)
        {
          GNUNET_free (bf);
          return NULL;
        }
      bf->filename = GNUNET_strdup (filename);
    }
  else
    {
      bf->fd = -1;
      bf->filename = NULL;
    }
  /* Alloc block */
  bf->lock = GNUNET_mutex_create (GNUNET_YES);
  bf->bitArray = GNUNET_malloc_large (size);
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  memset (bf->bitArray, 0, bf->bitArraySize);

  if (bf->fd != -1)
    {
      /* Read from the file what bits we can */
      rbuff = GNUNET_malloc (BUFFSIZE);
      pos = 0;
      while (pos < size * 8)
        {
          int res;

          res = READ (bf->fd, rbuff, BUFFSIZE);
          if (res == 0)
            break;              /* is ok! we just did not use that many bits yet */
          for (i = 0; i < res; i++)
            {
              if ((rbuff[i] & 0x0F) != 0)
                setBit (bf->bitArray, pos + i * 2);
              if ((rbuff[i] & 0xF0) != 0)
                setBit (bf->bitArray, pos + i * 2 + 1);
            }
          if (res < BUFFSIZE)
            break;
          pos += BUFFSIZE * 2;  /* 2 bits per byte in the buffer */
        }
      GNUNET_free (rbuff);
    }
  return bf;
}


/**
 * Create a bloom filter from raw bits.
 *
 * @param data the raw bits in memory (maybe NULL,
 *        in which case all bits should be considered
 *        to be zero).
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); also size of data
 *        -- unless data is NULL
 * @param k the number of GNUNET_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_BloomFilter *
GNUNET_bloomfilter_init (struct GNUNET_GE_Context
                         *ectx,
                         const char *data, unsigned int size, unsigned int k)
{
  Bloomfilter *bf;
  unsigned int ui;

  if ((k == 0) || (size == 0))
    return NULL;
  ui = 1;
  while (ui < size)
    ui *= 2;
  size = ui;                    /* make sure it's a power of 2 */

  bf = GNUNET_malloc (sizeof (Bloomfilter));
  bf->ectx = ectx;
  bf->fd = -1;
  bf->filename = NULL;
  bf->lock = GNUNET_mutex_create (GNUNET_YES);
  bf->bitArray = GNUNET_malloc_large (size);
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  memset (bf->bitArray, 0, bf->bitArraySize);
  return bf;
}


/**
 * Copy the raw data of this bloomfilter into
 * the given data array.
 *
 * @param data where to write the data
 * @param size the size of the given data array
 * @return GNUNET_SYSERR if the data array is not big enough
 */
int
GNUNET_bloomfilter_get_raw_data (struct GNUNET_BloomFilter *bf,
                                 char *data, unsigned int size)
{
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  memcpy (data, bf->bitArray, size);
  return GNUNET_OK;
}

/**
 * Free the space associated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 *
 * @param bf the filter
 */
void
GNUNET_bloomfilter_free (Bloomfilter * bf)
{
  if (NULL == bf)
    return;
  GNUNET_mutex_destroy (bf->lock);
  if (bf->fd != -1)
    GNUNET_disk_file_close (bf->ectx, bf->filename, bf->fd);
  GNUNET_free_non_null (bf->filename);
  GNUNET_free (bf->bitArray);
  GNUNET_free (bf);
}

/**
 * Reset a bloom filter to empty. Clears the file on disk.
 *
 * @param bf the filter
 */
void
GNUNET_bloomfilter_clear (Bloomfilter * bf)
{
  if (NULL == bf)
    return;

  GNUNET_mutex_lock (bf->lock);
  memset (bf->bitArray, 0, bf->bitArraySize);
  if (bf->fd != -1)
    makeEmptyFile (bf->fd, bf->bitArraySize * 4);
  GNUNET_mutex_unlock (bf->lock);
}


/**
 * Test if an element is in the filter.
 *
 * @param e the element
 * @param bf the filter
 * @return GNUNET_YES if the element is in the filter, GNUNET_NO if not
 */
int
GNUNET_bloomfilter_test (Bloomfilter * bf, const GNUNET_HashCode * e)
{
  int res;

  if (NULL == bf)
    return GNUNET_YES;
  GNUNET_mutex_lock (bf->lock);
  res = GNUNET_YES;
  iterateBits (bf, &testBitCallback, &res, e);
  GNUNET_mutex_unlock (bf->lock);
  return res;
}

/**
 * Add an element to the filter
 *
 * @param bf the filter
 * @param e the element
 */
void
GNUNET_bloomfilter_add (Bloomfilter * bf, const GNUNET_HashCode * e)
{

  if (NULL == bf)
    return;
  GNUNET_mutex_lock (bf->lock);
  iterateBits (bf, &incrementBitCallback, NULL, e);
  GNUNET_mutex_unlock (bf->lock);
}


/**
 * Or the entries of the given raw data array with the
 * data of the given bloom filter.  Assumes that
 * the size of the data array and the current filter
 * match.
 * @param bf the filter
 */
int
GNUNET_bloomfilter_or (struct GNUNET_BloomFilter *bf,
                       const char *data, unsigned int size)
{
  unsigned int i;

  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  /* FIXME: we could do this 4-8x faster by
     going over int/long arrays */
  for (i = 0; i < size; i++)
    bf->bitArray[i] |= data[i];
  return GNUNET_OK;
}

/**
 * Remove an element from the filter.
 *
 * @param bf the filter
 * @param e the element to remove
 */
void
GNUNET_bloomfilter_remove (Bloomfilter * bf, const GNUNET_HashCode * e)
{
  if (NULL == bf)
    return;
  GNUNET_mutex_lock (bf->lock);
  iterateBits (bf, &decrementBitCallback, NULL, e);
  GNUNET_mutex_unlock (bf->lock);
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
 * @param k the new number of GNUNET_hash-function to apply per element
 */
void
GNUNET_bloomfilter_resize (Bloomfilter * bf,
                           GNUNET_HashCodeIterator iterator,
                           void *iterator_arg, unsigned int size,
                           unsigned int k)
{
  GNUNET_HashCode hc;
  unsigned int i;

  GNUNET_mutex_lock (bf->lock);
  GNUNET_free (bf->bitArray);
  i = 1;
  while (i < size)
    i *= 2;
  size = i;                     /* make sure it's a power of 2 */

  bf->bitArraySize = size;
  bf->bitArray = GNUNET_malloc (size);
  memset (bf->bitArray, 0, bf->bitArraySize);
  if (bf->fd != -1)
    makeEmptyFile (bf->fd, bf->bitArraySize * 4);
  while (GNUNET_YES == iterator (&hc, iterator_arg))
    GNUNET_bloomfilter_add (bf, &hc);
  GNUNET_mutex_unlock (bf->lock);
}

/* ******************** end of bloomfilter.c *********** */
