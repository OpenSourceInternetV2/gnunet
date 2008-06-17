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
 * @file util/semaphore.c
 * @brief functions related to threading and synchronization
 *
 * In particular, functions for mutexes, semaphores 
 * and thread creation are provided.
 **/

#include "gnunet_util.h"
#include "platform.h"

#if SOLARIS
#include <semaphore.h>
#endif
#if FREEBSD
#include <semaphore.h>
#endif
#if SOMEBSD
# include <pthread_np.h>
#endif
#if SOMEBSD || OSX
# include <sys/file.h>
#endif
#if LINUX
# include <sys/ipc.h>
# include <sys/sem.h>
#endif
#ifdef _MSC_VER
#include <pthread.h>
#include <semaphore.h>
#endif
  
#define DEBUG_SEMUPDOWN NO

/**
 * Shall we use error-checking (slow) 
 * mutexes (e.g. for debugging)
 **/
#define USE_CHECKING_MUTEX 1


typedef struct {
#if SOLARIS 
  sem_t * internal;
#elif LINUX
  int internal;
  char * filename;
#elif FREEBSD5
  sem_t * internal;
#elif SOMEBSD || OSX || MINGW
  int initialValue;
  int fd;
  Mutex internalLock;
  char * filename;
#elif _MSC_VER
  int internal; /* KLB_FIX */
  char * filename;
#else
  /* FIXME! */
#endif
} IPC_Semaphore_Internal;




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
 **/
#ifndef _MSC_VER
extern int pthread_mutexattr_setkind_np(pthread_mutexattr_t *attr, int kind);
#endif
/* ********************* public methods ******************* */

void create_mutex_(Mutex * mutex) {
  pthread_mutexattr_t attr;
  pthread_mutex_t * mut;

#if WINDOWS
  attr = NULL;
#endif
  
  pthread_mutexattr_init(&attr);
#if USE_CHECKING_MUTEX
#if LINUX
  pthread_mutexattr_setkind_np(&attr,
			       PTHREAD_MUTEX_ERRORCHECK_NP);  
#endif
#else
  pthread_mutexattr_setkind_np(&attr,
			       (int)PTHREAD_MUTEX_NORMAL);
#endif
  mut = MALLOC(sizeof(pthread_mutex_t));
  mutex->internal = mut;
  if ( pthread_mutex_init(mut, &attr) != 0)
    errexit("FATAL: creation of mutex failed (%s)",
	    STRERROR(errno));
}

void create_recursive_mutex_(Mutex * mutex) {
  pthread_mutexattr_t attr;
  pthread_mutex_t * mut;

  pthread_mutexattr_init(&attr);
#if LINUX
  pthread_mutexattr_setkind_np(&attr,  
			       PTHREAD_MUTEX_RECURSIVE_NP);
#elif SOMEBSD
  pthread_mutexattr_setkind_np(&attr,
			       PTHREAD_MUTEX_RECURSIVE);
#elif SOLARIS
  pthread_mutexattr_settype(&attr,
			    PTHREAD_MUTEX_RECURSIVE);
#elif OSX
  pthread_mutexattr_settype(&attr,
			    PTHREAD_MUTEX_RECURSIVE);
#elif WINDOWS
  pthread_mutexattr_settype(&attr,
			    PTHREAD_MUTEX_RECURSIVE);
#endif
  mut = MALLOC(sizeof(pthread_mutex_t));
  mutex->internal = mut;
  if ( pthread_mutex_init(mut, &attr) != 0)
    errexit("FATAL: creation of recursive mutex failed");
}

void destroy_mutex_(Mutex * mutex) {
  pthread_mutex_t * mut;
  mut = mutex->internal;
  if (mut == NULL) {
    LOG(LOG_ERROR,
	"ERROR: Mutex destroyed twice!\n");
    return;
  }
  mutex->internal = NULL;
  pthread_mutex_destroy(mut);
  FREE(mut);
}

void mutex_lock_(Mutex * mutex,
		 const char * filename,
		 const int line) {
  int return_value;
  pthread_mutex_t * mut;
  mut = mutex->internal;
  if (mut == NULL) {
    LOG(LOG_ERROR,
	"ERROR: Mutex already destroyed on lock at %s:%d!\n",
	filename,
	line);
    return;
  }
  if ((return_value = pthread_mutex_lock(mut)) != 0)
    errexit("FATAL: pthread_mutex_lock returned %d (%s) in %s:%d\n",
	    return_value, 
	    STRERROR(return_value),
	    filename,
	    line);  
}

void mutex_unlock_(Mutex * mutex,
		   const char * filename,
		   const int line) {
  int return_value;
  pthread_mutex_t * mut;
  mut = mutex->internal;
  if (mut == NULL) {
    LOG(LOG_ERROR,
	"ERROR: Mutex already destroyed on unlock at %s:%d!\n",
	filename,
	line);
    return;
  }

  if ((return_value = pthread_mutex_unlock(mut)) != 0)
    errexit("FATAL: pthread_mutex_unlock returned %d (%s) in %s:%d\n",
	    return_value, 
	    STRERROR(return_value),
	    filename,
	    line);  
}

/**
 * function must be called prior to semaphore use -- handles
 * setup and initialization.  semaphore destroy (below) should
 * be called when the semaphore is no longer needed.
 **/
Semaphore * semaphore_new_(int value,
			   const char * filename,
			   const int linenumber) {
  pthread_cond_t * cond;

  Semaphore * s = (Semaphore*)xmalloc_(sizeof(Semaphore),
			                     filename,
			                     linenumber);
  s->v = value;
  MUTEX_CREATE(&(s->mutex));
  cond = MALLOC(sizeof(pthread_cond_t));
  s->cond = cond;
  if (pthread_cond_init(cond, NULL) != 0)
    errexit("FATAL: pthread_cont_init failed in %s:%d\n",
	    filename,
	    linenumber);
  return s;
}

void semaphore_free_(Semaphore * s,
		     const char * filename,
		     const int linenumber) {
  pthread_cond_t * cond;
  MUTEX_DESTROY(&(s->mutex));
  cond = s->cond;
  pthread_cond_destroy(cond);
  FREE(cond);
  xfree_(s,
	 filename,
	 linenumber);
}

/**
 * function increments the semaphore and signals any threads that
 * are blocked waiting a change in the semaphore.
 **/
int semaphore_up_(Semaphore * s,
		  const char * filename,
		  const int linenumber) {
  int value_after_op;
  int return_value;
  pthread_cond_t * cond;

  if (s == NULL)
    errexit("semaphore_up_ called with s == NULL in %s:%d\n",
	    filename, linenumber);
  cond = s->cond;
#if DEBUG_SEMUPDOWN
  LOG(LOG_DEBUG,
      "DEBUG: semaphore_up %d enter at %s:%d\n",
      (int)s,
      filename,
      linenumber);
#endif
  MUTEX_LOCK(&(s->mutex));  
  (s->v)++;
  value_after_op = s->v;  
  MUTEX_UNLOCK(&(s->mutex));
  if ((return_value = pthread_cond_signal(cond) != 0))
      errexit("FATAL: pthread_cond_signal returned %d (%s) in %s:%d\n",
	      return_value, 
	      STRERROR(return_value),
	      filename,
	      linenumber);  
#if DEBUG_SEMUPDOWN
  LOG(LOG_DEBUG,
      "DEBUG: semaphore_up %d exit at %s:%d\n",
      (int)s,
      filename,
      linenumber);
#endif
  return value_after_op;
}

/**
 * function decrements the semaphore and blocks if the semaphore is
 * <= 0 until another thread signals a change.
 **/
int semaphore_down_(Semaphore * s,
		    const char * filename,
		    const int linenumber) {
  int value_after_op;
  int return_value;
  pthread_cond_t * cond;
  
  if (s == NULL)
    errexit("semaphore_down_ called with s == NULL in %s:%d\n",
	    filename, linenumber);
  cond = s->cond;
#if DEBUG_SEMUPDOWN
  LOG(LOG_DEBUG,
      "DEBUG: semaphore_down %d enter at %s:%d\n",
      (int)s,
      filename,
      linenumber);
#endif
  MUTEX_LOCK(&(s->mutex));
  while (s->v <= 0) {
    if ((return_value = pthread_cond_wait(cond,
					  (pthread_mutex_t*)s->mutex.internal)) != 0)
      errexit("FATAL: pthread_cond_wait returned %d (%s) in %s:%d\n",
	      return_value,
	      STRERROR(return_value),
	      filename,
	      linenumber);  	    
  }
  (s->v)--;
  value_after_op = s->v;
  MUTEX_UNLOCK(&(s->mutex));  
#if DEBUG_SEMUPDOWN
  LOG(LOG_DEBUG,
      "DEBUG: semaphore_down %d exit at %s:%d\n",
      (int)s,
      filename,
      linenumber);
#endif
  return value_after_op;
}

/**
 * Function decrements the semaphore. If the semaphore would become
 * negative, the decrement does not happen and the function returns
 * SYSERR. Otherwise OK is returned.
 **/
int semaphore_down_nonblocking_(Semaphore * s,
				const char * filename,
				const int linenumber) {
  if (s == NULL)
    errexit("semaphore_down_nonblocking called with s == NULL in %s:%d\n",
	    filename, linenumber);
  MUTEX_LOCK(&(s->mutex));
  if (s->v <= 0) {
    MUTEX_UNLOCK(&(s->mutex));
    return SYSERR;
  }
  (s->v)--;
  MUTEX_UNLOCK(&(s->mutex));  
  return OK;
}

/**
 * Create a thread. Use this method instead of pthread_create since
 * BSD may only give a 1k stack otherwise.
 *
 * @param handle handle to the pthread (for detaching, join)
 * @param main the main method of the thread
 * @param arg the argument to main
 * @param stackSize the size of the stack of the thread in bytes. 
 *        Note that if the stack overflows, some OSes (seen under BSD) 
 *        will just segfault and gdb will give a messed-up stacktrace.
 * @return see pthread_create 
 **/
int PTHREAD_CREATE(PTHREAD_T * pt,
		   PThreadMain main,
		   void * arg,
		   size_t stackSize) {
  pthread_t * handle;
  pthread_attr_t stack_size_custom_attr;
  int ret;

  handle = MALLOC(sizeof(pthread_t));
#ifdef MINGW
  memset(handle, sizeof(pthread_t), 0);
#endif

  pthread_attr_init(&stack_size_custom_attr);
  pthread_attr_setstacksize(&stack_size_custom_attr,
			    stackSize);
  ret = pthread_create(handle, 
		       &stack_size_custom_attr,
		       main, 
		       arg);			    
  if (ret != 0) {
    FREE(handle);
    pt->internal = NULL;
    return ret;
  }
  pt->internal = handle;
  return ret;
}

void PTHREAD_JOIN(PTHREAD_T * pt,
		  void * ret) {
  int k;
  pthread_t * handle;

  handle = pt->internal;
  if (handle == NULL) {
    errexit("FATAL: PTHREAD_JOIN called on invalid handle.\n");
  }
  switch ((k=pthread_join(*handle, ((void**)ret)))) {
  case 0: 
    FREE(handle);
    pt->internal = NULL;
    return;
  case ESRCH:
    errexit("FATAL: pthread_join failed: ESRCH (%s)\n",
	    STRERROR(errno));
  case EINVAL:
    errexit("FATAL: pthread_join failed: EINVAL (%s)\n",
	    STRERROR(errno));
  case EDEADLK:
    errexit("FATAL: pthread_join failed: EDEADLK (%s)\n",
	    STRERROR(errno));
  default:
    errexit("FATAL: pthread_join failed: %d (%s)\n",
	    k,
	    STRERROR(errno));    
  }
}

void PTHREAD_DETACH(PTHREAD_T * pt) {
  pthread_t * handle;

  handle = pt->internal;
  if (handle == NULL) {
    LOG(LOG_ERROR,
	"ERROR: PTHREAD_DETACH called on invalid handle.\n");
    return;
  }
  if (0 != pthread_detach(*handle)) {
    LOG(LOG_ERROR,
	"ERROR: pthread_detach failed: %s\n",
	strerror(errno));
  }
  pt->internal = NULL;
  FREE(handle);
  return;
}

void PTHREAD_KILL(PTHREAD_T * pt,
		  int signal) {
  pthread_t * handle;

  handle = pt->internal;
  if (handle == NULL) {
    LOG(LOG_ERROR,
	"ERROR: PTHREAD_KILL called on invalid handle.\n");
    return;
  }
  pthread_kill(*handle, signal);
}


/* ********************** IPC ********************* */

#if LINUX
  /* IPC semaphore kludging for linux */

  /* FIXME: ugly. why don't we start at count 0 and increment when opening? */
  #define PROCCOUNT 10000

  /**
   * Implementation for a single semaphore actually uses three : 
   *
   * 0 : actual semaphore value
   * 1 : process counter 
   * 2 : lock
   **/ 

  /* Various operations */
  static struct sembuf op_lock[2] = {
      {2, 0, 0},        /* wait for [2] (lock) to equal 0 */
      {2, 1, SEM_UNDO}  /* then increment [2] to 1 - this locks it */
                        /* UNDO to release the lock if processes exits */                               /* before explicitly unlocking */
  };
  static struct sembuf op_unlock[1] = {
      {2, -1, SEM_UNDO} /* decrement [2] (lock) back to 0 */
  };
  static struct sembuf    op_endcreate[2] = {
      {1, -1, SEM_UNDO},/* decrement [1] (proc counter) with undo on exit */
		        /* UNDO to adjust proc counter if process exits
		           before explicitly calling sem_close() */
      {2, -1, SEM_UNDO} /* then decrement [2] (lock) back to 0 */
  };
  static struct sembuf    op_close[3] = {
      {2, 0, 0},        /* wait for [2] (lock) to equal 0 */
      {2, 1, SEM_UNDO}, /* then increment [2] to 1 - this locks it */
      {1, 1, SEM_UNDO}  /* then increment [1] (proc counter) */
  };
#endif

#if SOMEBSD || OSX || MINGW
static void FLOCK(int fd,
		  int operation) {
  int ret;

  ret = -1;
  while (ret == -1) {
    ret = flock(fd, operation);
    if (ret == -1) {
      if (errno != EINTR) {
	LOG(LOG_ERROR,
	    "ERROR: could not perform flock: %s\n",
	    STRERROR(errno));
	return;
      }
    }
  }
  fsync(fd);
}
static int LSEEK(int fd, off_t pos, int mode) {
  int ret;
  ret = lseek(fd, pos, mode);
  if (ret == -1) {
    LOG(LOG_ERROR,
	"ERROR: could not seek to position %d (%s)\n",
	pos);
  }
  return ret;
}
#endif

IPC_Semaphore * ipc_semaphore_new_(const char * basename,
				   const unsigned int initialValue,
				   const char * filename,
				   const int linenumber) {
#if SOLARIS 
  char * noslashBasename;
  int i;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;
  noslashBasename = STRDUP(basename);
  for (i=strlen(noslashBasename);i>0;i--)
    if (noslashBasename[i] == '/')
      noslashBasename[i] = '.'; /* first character MUST be /, but Solaris
				   forbids it afterwards */
  noslashBasename[0] = '/';  
  ret->internal = sem_open(noslashBasename,
			   O_CREAT,
			   S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, /* 660 */
			   initialValue);
  while ( (SEM_FAILED == ret->internal) &&
	  (errno == ENAMETOOLONG) ) {
    if (strlen(noslashBasename) < 4)
      break; /* definitely OS error... */
    noslashBasename[strlen(noslashBasename)/2] = '\0'; /* cut in half */
    ret->internal = sem_open(noslashBasename,
			     O_CREAT,   
			     S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, /* 660 */
			     initialValue);			     
  }
  FREE(noslashBasename);
  if (ret->internal == SEM_FAILED) 
    errexit("FATAL: creation of IPC semaphore failed: %s at %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);  
  return rret;
#elif LINUX
  union semun {
      int             val;
      struct semid_ds *buf;
      ushort          *array;
  } semctl_arg;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;  
  key_t key;
  FILE * fp;
  int pcount;
 
  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;

  fp = FOPEN(basename, "a+");
  if (NULL == fp) {
    LOG(LOG_FATAL,
	"FATAL: can't open %s for r/w : %s at %s:%d.  Not using IPC locking!\n",
	basename,
	STRERROR(errno),
	filename,
	linenumber);
    FREE(rret);
    FREE(ret);
    return NULL;
  }
  fclose(fp);
  
  key = ftok(basename,'g');

again:

  ret->internal = semget(key, 3, IPC_CREAT|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

  if (ret->internal == -1)
    errexit("FATAL: creation of IPC semaphore failed: %s at %s:%d\n",
            STRERROR(errno),
            filename,
            linenumber);
  if (semop(ret->internal, &op_lock[0], 2) < 0) {
    if (errno == EINVAL)
      goto again;
    else
      errexit("FATAL: can't lock ipc semaphore: %s at %s:%d\n",
	      STRERROR(errno),
	      filename,
	      linenumber);
  }

  /* get process count */
  if ( (pcount = semctl(ret->internal, 1, GETVAL, 0)) < 0) {
      errexit("FATAL: can't read ipc semaphore: %s at %s:%d\n",
	      STRERROR(errno),
	      filename,
	      linenumber);
  }
  if (pcount==0) {
     semctl_arg.val = initialValue;
     if (semctl(ret->internal, 0, SETVAL, semctl_arg) < 0) {
       errexit("FATAL: Can't set initial value: %s at %s:%d\n",
       STRERROR(errno),
       filename,
       linenumber);
     }
     semctl_arg.val = PROCCOUNT;
     if (semctl(ret->internal, 1, SETVAL, semctl_arg) < 0) {
       errexit("FATAL: Can't set initial value: %s at %s:%d\n",
               STRERROR(errno),
               filename,
               linenumber);
     }		
  } 

  if (semop(ret->internal, &op_endcreate[0], 2) < 0) {
     errexit("FATAL: ipc unlocking problem: %s at %s:%d\n",
             STRERROR(errno),
             filename,
             linenumber);
  }
  
  ret->filename = STRDUP(basename);
  return rret;  
#elif FREEBSD5
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;  

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;
  ret->internal = sem_open(basename,
			   O_CREAT,
			   S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, /* 660 */
			   initialValue);
  if (ret->internal == SEM_FAILED) {
    LOG(LOG_ERROR,
	"ERROR: creation of IPC semaphore failed: %s at %s:%d.  Upgrade to FreeBSD >= 5.0.\n",
	STRERROR(errno),
	filename,
	linenumber);
    FREE(ret);
    FREE(rret);
    return NULL;
  } else
    return rret; 
#elif SOMEBSD || OSX || MINGW
  int fd;
  int cnt;  
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;  

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;

#if DEBUG_SEMUPDOWN
  LOG(LOG_DEBUG,
      "DEBUG: creating IPC semaphore\n");
#endif
  MUTEX_CREATE(&ret->internalLock);
  ret->filename = STRDUP(basename);
  fd = -1;
  while (fd == -1) {
    fd = OPEN(basename,
	      O_CREAT|O_RDWR|O_EXCL,
	      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP /* 660 */);
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: exclusive opening result: %d\n",
	fd);
#endif
    if ( (fd == -1) &&
	 (errno == EEXIST) ) {
      /* try without creation */
      fd = OPEN(basename,
		O_RDWR,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP /* 660 */);
#if DEBUG_SEMUPDOWN
      LOG(LOG_DEBUG,
	  "DEBUG: non-exclusive opening result: %d\n", fd);
#endif
      /* possibly the file was deleted in the meantime,
	 then try again with O_CREAT! */
      if ( (fd == -1) &&
	   (errno != ENOENT) )
	break;
    }
  }
  if (fd == -1) {
    LOG(LOG_ERROR,
	"ERROR: could not open IPC locking file %s\n",
	ret->filename);
    MUTEX_DESTROY(&ret->internalLock);
    FREE(ret->filename);
    FREE(ret);
    FREE(rret);
    return NULL;
  }
  FLOCK(fd, LOCK_EX);
  if (sizeof(int) != READ(fd, &cnt, sizeof(int))) {
    cnt = htonl(initialValue);
    LSEEK(fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(fd, &cnt, sizeof(int)))
      LOG(LOG_WARNING,
	  "WARNING: could not write to IPC file %s (%s) at %s:%d\n",
	  basename,
	  STRERROR(errno),
	  __FILE__,
	  __LINE__);
  }
  LSEEK(fd, sizeof(int), SEEK_SET);
  if (sizeof(int) != READ(fd, &cnt, sizeof(int))) 
    cnt = htonl(1);
  else 
    cnt = htonl(ntohl(cnt)+1);
  LSEEK(fd, sizeof(int), SEEK_SET);
  if (sizeof(int) != WRITE(fd, &cnt, sizeof(int)))
    LOG(LOG_WARNING,
	"WARNING: could not update IPC file %s (%s) at %s:%d\n",
	basename,
	STRERROR(errno),
	__FILE__,
	__LINE__);
  FLOCK(fd, LOCK_UN);
  ret->fd = fd;
  ret->initialValue = initialValue;
  return rret;
#else
 #ifndef _MSC_VER
   #warning Port IPC.
   return NULL; 
 #else
   return NULL;
 #endif
#endif  
}

void ipc_semaphore_up_(IPC_Semaphore * rsem,
		       const char * filename,
		       const int linenumber) {
  IPC_Semaphore_Internal * sem;
  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
#if SOLARIS
  if (0 != sem_post(sem->internal))
    LOG(LOG_WARNING,
	"WARNING: sem_post signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif LINUX
  {
    struct sembuf sops = {0,1,SEM_UNDO};
    
    if (0 != semop(sem->internal,&sops,1))
      LOG(LOG_WARNING,
	  "WARNING: semop signaled error: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
  }
#elif FREEBSD5
  if (0 != sem_post(sem->internal))
    LOG(LOG_WARNING,
	"WARNING: sem_post signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif SOMEBSD || OSX || MINGW
  { 
    int cnt;
    
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: up on IPC semaphore\n");
#endif
    MUTEX_LOCK(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != READ(sem->fd, &cnt, sizeof(int))) {
      LOG(LOG_WARNING,
	  "WARNING: could not read IPC semaphore count (%s) at %s:%d!\n",
	  STRERROR(errno),
	  __FILE__,
	  __LINE__);
      MUTEX_UNLOCK(&sem->internalLock);
      return;
    }
    cnt = htonl(ntohl(cnt)+1);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
      LOG(LOG_WARNING,
	  "WARNING: could not write to IPC file %s (%s) at %s:%d\n",
	  sem->filename,
	  STRERROR(errno),
	  __FILE__,
	  __LINE__);
#if DEBUG_SEMUPDOWN
    else
      LOG(LOG_DEBUG,
	  "DEBUG: wrote count %d\n",
	  ntohl(cnt));
#endif
    FLOCK(sem->fd, LOCK_UN);
    MUTEX_UNLOCK(&sem->internalLock);
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: up on IPC semaphore returns\n");
#endif
  }
#else
#endif
}

void ipc_semaphore_down_(IPC_Semaphore * rsem,
			 const char * filename,
			 const int linenumber) {
  IPC_Semaphore_Internal * sem;

  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
#if SOLARIS
  while (0 != sem_wait(sem->internal)) {
    switch(errno) {
    case EINTR:
      break;
    case EINVAL:
      errexit("FATAL: ipc_semaphore_down called on invalid semaphore (in %s:%d)\n",
	      filename,
	      linenumber);
    case EDEADLK:
      errexit("FATAL: ipc_semaphore_down caused deadlock! (in %s:%d)\n",
	      filename,
	      linenumber);
    case EAGAIN:
      LOG(LOG_WARNING,
	  "WARNING: did not expect EAGAIN from sem_wait (in %s:%d).\n",
	  filename,
	  linenumber);
      break;
    default:
      LOG(LOG_ERROR,
	  "ERROR: did not expect %s from sem_wait at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
      break;
    }
  }
#elif LINUX
  {
    struct sembuf sops = {0,-1,SEM_UNDO};
    
    while (0 != semop(sem->internal,&sops,1)) {
      switch(errno) {
      case EINTR:
	break;
      case EINVAL:
	errexit("FATAL: ipc_semaphore_down called on invalid semaphore (in %s:%d)\n",
		filename,
		linenumber);
      case EAGAIN:
	LOG(LOG_WARNING,
	    "WARNING: did not expect EAGAIN from sem_wait (in %s:%d).\n",
	    filename,
	    linenumber);
	break;
      default:
	LOG(LOG_ERROR,
	    "ERROR: did not expect %s from sem_wait at %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
	break;
      }
    }
  }
#elif FREEBSD5
  while (0 != sem_wait(sem->internal)) {
    switch(errno) {
    case EINTR:
      break;
    case EINVAL:
      errexit("FATAL: ipc_semaphore_down called on invalid semaphore (in %s:%d)\n",
	      filename,
	      linenumber);
    case EDEADLK:
      errexit("FATAL: ipc_semaphore_down caused deadlock! (in %s:%d)\n",
	      filename,
	      linenumber);
    case EAGAIN:
      LOG(LOG_WARNING,
	  "WARNING: did not expect EAGAIN from sem_wait (in %s:%d).\n",
	  filename,
	  linenumber);
      break;
    default:
      LOG(LOG_ERROR,
	  "ERROR: did not expect %s from sem_wait at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
      break;
    }
  }
#elif SOMEBSD || OSX || MINGW
  {
    int cnt;
    
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: down on IPC semaphore\n");
#endif
    MUTEX_LOCK(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    cnt = ntohl(0);
    while (htonl(cnt) == 0) {
      LSEEK(sem->fd, 0, SEEK_SET);
      if (sizeof(int) != READ(sem->fd, &cnt, sizeof(int))) {
	LOG(LOG_WARNING,
	    "WARNING: could not read IPC semaphore count (%s) at %s:%d!\n",
	    STRERROR(errno),
	    __FILE__,
	    __LINE__);
	FLOCK(sem->fd, LOCK_UN);
	MUTEX_UNLOCK(&sem->internalLock);
	return;
      }
      if (htonl(cnt) == 0) {
	/* busy wait! */
	FLOCK(sem->fd, LOCK_UN);
	gnunet_util_sleep(50 * cronMILLIS);
#if DEBUG_SEMUPDOWN
	LOG(LOG_DEBUG,
	    "DEBUG: down on IPC semaphore: busy waiting...\n");
#endif
	FLOCK(sem->fd, LOCK_EX);
      }
    }
    
    cnt = htonl(ntohl(cnt)-1);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
      LOG(LOG_WARNING,
	  "WARNING: could not write update to IPC file %s at %s:%d\n",
	  sem->filename,
	  __FILE__,
	  __LINE__); 
    FLOCK(sem->fd, LOCK_UN);
    MUTEX_UNLOCK(&sem->internalLock);
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: down on IPC semaphore returns\n");
#endif
  }
#else
#endif
}

void ipc_semaphore_free_(IPC_Semaphore * rsem,
			 const char * filename,
			 const int linenumber) {
  IPC_Semaphore_Internal * sem;
  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
  FREE(rsem);
#if SOLARIS
  if (0 != sem_close(sem->internal))
    LOG(LOG_WARNING,
	"WARNING: sem_close signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif LINUX
  {
    int pcount;
    
    if (semop(sem->internal, &op_close[0], 3) < 0)
      LOG(LOG_WARNING,
	  "WARNING: semop signaled error: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
    
    if ( (pcount = semctl(sem->internal, 1, GETVAL, 0)) < 0)
      LOG(LOG_WARNING,
	  "WARNING semctl: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
    if (pcount > PROCCOUNT)
      LOG(LOG_WARNING,
	  "WARNING pcount too large at %s:%d\n",
	  filename,
	  linenumber);
    else if (pcount == PROCCOUNT) {
      if (0 != semctl(sem->internal,0,IPC_RMID,0))
	LOG(LOG_WARNING,
	    "WARNING: semctl signaled error: %s at %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
      UNLINK(sem->filename);
    } else {
      if (semop(sem->internal, &op_unlock[0], 1) < 0)
	LOG(LOG_WARNING,
	    "WARNING semop %s %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
    }
    FREE(sem->filename);  
  }
#elif FREEBSD5
  if (0 != sem_close(sem->internal))
    LOG(LOG_WARNING,
	"WARNING: sem_close signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif SOMEBSD || OSX || MINGW
  {
    int cnt;  
    
#if DEBUG_SEMUPDOWN
    LOG(LOG_DEBUG,
	"DEBUG: destroying IPC semaphore\n");
#endif
    MUTEX_DESTROY(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    LSEEK(sem->fd, sizeof(int), SEEK_SET);
    if (sizeof(int) == READ(sem->fd, &cnt, sizeof(int))) {
      cnt = htonl(ntohl(cnt)-1);
      LSEEK(sem->fd, sizeof(int), SEEK_SET);
      if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
	LOG(LOG_WARNING,
	    "WARNING: could not write to IPC file %s at %s:%d\n",
	    sem->filename,
	    __FILE__,
	    __LINE__);
      if (ntohl(cnt) == 0) {
#if DEBUG_SEMUPDOWN
	LOG(LOG_DEBUG,
	    "DEBUG: removing IPC file %s -- last using process is done.\n",
	    sem->filename);
#endif
	UNLINK(sem->filename); 
      }
    } else 
      LOG(LOG_WARNING,
	  "WARNING: could not read process count of IPC %s at %s:%d\n",
	  sem->filename,
	  __FILE__,
	  __LINE__);
    FREE(sem->filename);
    FLOCK(sem->fd, LOCK_UN);
    CLOSE(sem->fd);
  }
#else
#endif
  FREE(sem);
}


/* end of semaphore.c */
