/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/threads/semaphore.c
 * @brief functions related to threading and synchronization
 *
 * In particular, functions for mutexes, semaphores
 * and thread creation are provided.
 */

#include "platform.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"

#if SOLARIS || GNUNET_freeBSD || OSX
#include <semaphore.h>
#include <sys/file.h>
#endif
#if SOMEBSD
#include <pthread_np.h>
#endif
#if LINUX
#include <sys/sem.h>
#endif
#ifdef _MSC_VER
#include <pthread.h>
#include <semaphore.h>
#endif

/**
 * @brief Internal state of a semaphore.
 */
typedef struct GNUNET_Semaphore
{
  /**
   * Counter
   */
  int v;

  /**
   * Mutex
   */
  pthread_mutex_t mutex;

  /**
   * Wrapper for pthread condition variable.
   */
  pthread_cond_t cond;
} Semaphore;

#ifndef PTHREAD_MUTEX_NORMAL
#ifdef PTHREAD_MUTEX_TIMED_NP
#define PTHREAD_MUTEX_NORMAL PTHREAD_MUTEX_TIMED_NP
#else
#define PTHREAD_MUTEX_NORMAL NULL
#endif
#endif

/**
 * This prototype is somehow missing in various Linux pthread
 * include files. But we need it and it seems to be available
 * on all pthread-systems so far. Odd.
 */
#ifndef _MSC_VER
extern int pthread_mutexattr_setkind_np (pthread_mutexattr_t * attr,
                                         int kind);
#endif

/**
 * function must be called prior to semaphore use -- handles
 * setup and initialization.  semaphore destroy (below) should
 * be called when the semaphore is no longer needed.
 */
Semaphore *
GNUNET_semaphore_create (int value)
{
  Semaphore *s;
  pthread_mutexattr_t attr;
#if WINDOWS
  attr = NULL;
#endif

  pthread_mutexattr_init (&attr);
#if LINUX
  GNUNET_GE_ASSERT (NULL,
                    0 == pthread_mutexattr_setkind_np
                    (&attr, PTHREAD_MUTEX_ERRORCHECK_NP));
#else
  GNUNET_GE_ASSERT (NULL,
                    0 == pthread_mutexattr_settype
                    (&attr, PTHREAD_MUTEX_ERRORCHECK));
#endif
  s = GNUNET_malloc (sizeof (Semaphore));
  s->v = value;
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_init (&s->mutex, &attr));
  GNUNET_GE_ASSERT (NULL, 0 == pthread_cond_init (&s->cond, NULL));
  return s;
}

void
GNUNET_semaphore_destroy (Semaphore * s)
{
  GNUNET_GE_ASSERT (NULL, s != NULL);
  GNUNET_GE_ASSERT (NULL, 0 == pthread_cond_destroy (&s->cond));
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_destroy (&s->mutex));
  GNUNET_free (s);
}

int
GNUNET_semaphore_up (Semaphore * s)
{
  int ret;

  GNUNET_GE_ASSERT (NULL, s != NULL);
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_lock (&s->mutex));
  ret = ++(s->v);
  GNUNET_GE_ASSERT (NULL, 0 == pthread_cond_signal (&s->cond));
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_unlock (&s->mutex));
  return ret;
}

int
GNUNET_semaphore_down_at_file_line_ (Semaphore * s,
                                     int mayblock,
                                     int longwait, const char *file,
                                     unsigned int line)
{
  int ret;
  GNUNET_CronTime start;
  GNUNET_CronTime end;

  GNUNET_GE_ASSERT (NULL, s != NULL);
  start = GNUNET_get_time ();
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_lock (&s->mutex));
  while ((s->v <= 0) && mayblock)
    GNUNET_GE_ASSERT (NULL, 0 == pthread_cond_wait (&s->cond, &s->mutex));
  if (s->v > 0)
    ret = --(s->v);
  else
    ret = GNUNET_SYSERR;
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_unlock (&s->mutex));
  end = GNUNET_get_time ();
  if ((longwait == GNUNET_NO) &&
      (end - start > GNUNET_REALTIME_LIMIT) && (GNUNET_REALTIME_LIMIT != 0))
    {
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_DEVELOPER | GNUNET_GE_WARNING |
                     GNUNET_GE_IMMEDIATE,
                     _("Real-time delay violation (%llu ms) at %s:%u\n"),
                     end - start, file, line);
    }
  return ret;
}

/* end of semaphore.c */
