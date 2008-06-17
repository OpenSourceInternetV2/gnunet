/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/string/xmalloc.c
 * @brief wrapper around malloc/free
 * @author Christian Grothoff
 */

#include "gnunet_util_string.h"
#include "gnunet_util_error.h"
#include "platform.h"

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory, if you are possibly needing a very large chunk use
 *  GNUNET_xmalloc_unchecked_ instead.
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xmalloc_ (size_t size,
                 const char *filename, int linenumber, const char *function)
{
  /* As a security precaution, we generally do not allow very large
     allocations using the default 'GNUNET_malloc' macro */
  GNUNET_GE_ASSERT_FLF (NULL,
                        size <= GNUNET_MAX_GNUNET_malloc_CHECKED, filename,
                        linenumber, function);
  return GNUNET_xmalloc_unchecked_ (size, filename, linenumber, function);
}

void *
GNUNET_xmalloc_unchecked_ (size_t size,
                           const char *filename,
                           int linenumber, const char *function)
{
  void *result;

  GNUNET_GE_ASSERT_FLF (NULL, size < INT_MAX, filename, linenumber, function);
  result = malloc (size);
  if (result == NULL)
    GNUNET_GE_DIE_STRERROR_FLF (NULL,
                                GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                                GNUNET_GE_DEVELOPER | GNUNET_GE_FATAL,
                                "malloc", filename, linenumber, function);
  memset (result, 0, size);     /* client code should not rely on this, though... */
  return result;
}

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @ptr the pointer to reallocate
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory
 * @param filename where in the code was the call to GNUNET_realloc
 * @param linenumber where in the code was the call to GNUNET_realloc
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xrealloc_ (void *ptr,
                  const size_t n,
                  const char *filename, int linenumber, const char *function)
{
  ptr = realloc (ptr, n);

  if (!ptr)
    GNUNET_GE_DIE_STRERROR_FLF (NULL,
                                GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                                GNUNET_GE_DEVELOPER | GNUNET_GE_FATAL,
                                "realloc", filename, linenumber, function);
  return ptr;
}

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.
 *
 * @param ptr the pointer to free
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xfree_ (void *ptr, const char *filename, int linenumber,
               const char *function)
{
  GNUNET_GE_ASSERT_FLF (NULL, ptr != NULL, filename, linenumber, function);
  free (ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return strdup(str)
 */
char *
GNUNET_xstrdup_ (const char *str,
                 const char *filename, int linenumber, const char *function)
{
  char *res;

  GNUNET_GE_ASSERT_FLF (NULL, str != NULL, filename, linenumber, function);
  res =
    (char *) GNUNET_xmalloc_ (strlen (str) + 1, filename, linenumber,
                              function);
  memcpy (res, str, strlen (str) + 1);
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
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xgrow_ (void **old,
               size_t elementSize,
               unsigned int *oldCount,
               unsigned int newCount,
               const char *filename, int linenumber, const char *function)
{
  void *tmp;
  size_t size;

  GNUNET_GE_ASSERT_FLF (NULL,
                        INT_MAX / elementSize > newCount,
                        filename, linenumber, function);
  size = newCount * elementSize;
  if (size == 0)
    {
      tmp = NULL;
    }
  else
    {
      tmp = GNUNET_xmalloc_ (size, filename, linenumber, function);
      GNUNET_GE_ASSERT (NULL, tmp != NULL);
      memset (tmp, 0, size);    /* client code should not rely on this, though... */
      if (*oldCount > newCount)
        *oldCount = newCount;   /* shrink is also allowed! */
      memcpy (tmp, *old, elementSize * (*oldCount));
    }

  if (*old != NULL)
    {
      GNUNET_xfree_ (*old, filename, linenumber, function);
    }
  *old = tmp;
  *oldCount = newCount;
}

/* end of xmalloc.c */
