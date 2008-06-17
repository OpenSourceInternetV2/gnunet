/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file util/xmalloc.c
 * @brief wrapper around malloc/free 
 * @author Christian Grothoff
 **/ 

#include "gnunet_util.h"
#include "platform.h"

#define DEBUG_MALLOC 0
#define STAT_MALLOC 0

#if DEBUG_MALLOC || STAT_MALLOC
static Mutex lock;
#endif
#if STAT_MALLOC
static int statMalloc = -1;
static unsigned long long currentlyAllocated = 0;
#endif


void initXmalloc() {
#if DEBUG_MALLOC || STAT_MALLOC
  MUTEX_CREATE(&lock);
#endif
}

void doneXmalloc() {
#if DEBUG_MALLOC || STAT_MALLOC
  MUTEX_DESTROY(&lock);
#endif
}

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @param size how many bytes of memory to allocate
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return pointer to size bytes of memory
 **/
void * xmalloc_(size_t size, 
		const char * filename,
		const int linenumber) {
  if (size > 1024 * 1024 * 40)
    errexit("FATAL: unexpected very large allocation (%u bytes) at %s:%d!\n",
	    size, filename, linenumber);
  return xmalloc_unchecked_(size, filename, linenumber);
}

void * xmalloc_unchecked_(size_t size, 
			  const char * filename,
			  const int linenumber) {
  void * result;
  
#if STAT_MALLOC
  size += sizeof(long long); /* long long to preserve alignment on 64-bit architectures! */
#endif
  if (size > INT_MAX)
    errexit("FATAL: can not allocate %u bytes (> %u)\n",
	    size, INT_MAX);
  result = malloc(size);
#if STAT_MALLOC
  size -= sizeof(long long);
  ((long long*)result)[0] = size;
  result = &((long long*)result)[1];
#endif

#if DEBUG_MALLOC 
  MUTEX_LOCK(&lock);
  printf("%p malloc %s:%d (%d bytes)\n", 
	 result, 
	 filename,
	 linenumber,
	 size);
  fflush(stdout);
  MUTEX_UNLOCK(&lock);
#endif
  if (result == NULL) {
    errexit("ERROR: out of memory (%d at %s:%d)!\n",
	    size, 
	    filename,
	    linenumber);
  }
  memset(result, 0, size); /* client code should not rely on this, though... */
#if STAT_MALLOC
  if (statMalloc == -1) { /* this is guaranteed to be hit before we have multiple threads... */
    statMalloc = -2;
    statMalloc = statHandle("# memory in use (bytes)");
  }
  MUTEX_LOCK(&lock);
  currentlyAllocated+=size;
  MUTEX_UNLOCK(&lock);
  if (statMalloc >= 0)
    statSet(statMalloc, currentlyAllocated);
#endif
  return result;
}

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.
 *
 * @param ptr the pointer to free
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 **/
void xfree_(void * ptr, 
	    const char * filename,
	    const int linenumber) {
  if (ptr == NULL)
    errexit("FREE called with NULL ptr at %s:%d\n", 
	    filename,
	    linenumber);
#if STAT_MALLOC
  MUTEX_LOCK(&lock);
  currentlyAllocated -= ((long long*)ptr)[-1];
  printf("%p free %s:%d (%lld bytes => %lld allocated) \n", 
	 ptr, 
	 filename,
	 linenumber,
	 ((long long*)ptr)[-1],
	 currentlyAllocated);
  MUTEX_UNLOCK(&lock);
  ptr = &((long long*)ptr)[-1]; 
#else
#if DEBUG_MALLOC 
  MUTEX_LOCK(&lock);
  printf("%p free %s:%d\n", 
	 ptr, 
	 filename,
	 linenumber);
  fflush(stdout);
  MUTEX_UNLOCK(&lock);
#endif
#endif
  free(ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 **/
char * xstrdup_(const char * str,
		const char * filename,
		const int linenumber) {
  char * res;

  if (str == NULL)
    errexit("FATAL: STRDUP called with NULL argument at %s:%d\n",
	    filename, 
	    linenumber);
  res = (char*)xmalloc_(strlen(str)+1,
		         filename,
		         linenumber);
  memcpy(res, str, strlen(str)+1);
  return res;
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 **/
char * xstrndup_(const char * str,
		 const size_t n,
		 const char * filename,
		 const int linenumber) {
  char * res;
  size_t min;

  if (str == NULL)
    errexit("FATAL: strndup called with NULL at %s:%d.\n",
	    filename,
	    linenumber);
  min = 0;
  while ( (min < n) && (str[min] != '\0'))
    min++;
  res = (char*)xmalloc_(min+1,
		         filename,
		         linenumber);
  memcpy(res, str, min);
  res[min] = '\0';
  return res;
}

/**
 * Grow an array.  Grows old by (*oldCount-newCount)*elementSize bytes
 * and sets *oldCount to newCount.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 **/
void xgrow_(void ** old,
	    size_t elementSize,
	    unsigned int * oldCount,
	    unsigned int newCount,
	    char * filename,
	    const int linenumber) {
  void * tmp;
  size_t size;

  if (newCount < 0)
    errexit("FATAL: grow called with newcount<0 at %s:%d\n",
	    filename, linenumber);
  if (INT_MAX / elementSize <= newCount)
    errexit("FATAL: can not allocate %u * %d elements (number too large) at %s:%d.\n",
	    elementSize, newCount, filename, linenumber);
  size = newCount * elementSize;
  if (size == 0) {
    tmp = NULL;
  } else {
    tmp = xmalloc_(size,
		   filename,
		   linenumber);  
    if (tmp == NULL) {
      errexit("ERROR: out of memory (%d at %s:%d)!\n",
	      size, 
	      filename,
	      linenumber);
    }
    memset(tmp, 0, size); /* client code should not rely on this, though... */
    if (*oldCount > newCount)
      *oldCount = newCount; /* shrink is also allowed! */
    memcpy(tmp, 
	   *old, 
	   elementSize * (*oldCount));
  }

  if (*old != NULL) {
    xfree_(*old, 
	   filename,
	   linenumber);
  }
  *old = tmp;
  *oldCount = newCount;
}



/* end of xmalloc.c */
