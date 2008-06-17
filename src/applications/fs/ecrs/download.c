/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/download.c
 * @brief Download helper methods (which do the real work).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_identity_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"
#include "tree.h"

#define DEBUG_DOWNLOAD NO

/**
 * Highest TTL allowed? (equivalent of 25-50 HOPS distance!)
 */
#define MAX_TTL (100 * TTL_DECREMENT)

/**
 * After how many retries do we print a warning?
 */
#define MAX_TRIES 500


/* ****************** IO context **************** */

/**
 * @brief IO context for reading-writing file blocks.
 *
 * In GNUnet, files are stored in the form of a balanced tree, not
 * unlike INodes in unix filesystems. When we download files, the
 * inner nodes of the tree are stored under FILENAME.X (where X
 * characterizes the level of the node in the tree). If the download
 * is aborted and resumed later, these .X files can be used to avoid
 * downloading the inner blocks again.  The successfully received leaf
 * nodes in FILENAME (the target file) are of course also not
 * downloaded again.<p>
 *
 * The IOContext struct presents an easy api to access the various
 * dot-files. It uses function pointers to allow implementors to
 * provide a different mechanism (other than files on the drive) to
 * cache the IBlocks.
 */
typedef struct IOContext
{

  struct GE_Context *ectx;

  /**
   * A lock for synchronizing access.
   */
  struct MUTEX *lock;

  /**
   * The file handles for each level in the tree.
   */
  int *handles;

  /**
   * The base-filename
   */
  char *filename;

  /**
   * The depth of the file-tree.
   */
  unsigned int treedepth;

} IOContext;

/**
 * Close the files in the IOContext and free
 * the associated resources. Does NOT free
 * the memory occupied by the IOContext struct
 * itself.
 *
 * @param this reference to the IOContext
 * @param unlinkTreeFiles if YES, the non-level 0 files
 *     are unlinked (removed), set to NO if the download
 *     is not complete and may be resumed later.
 */
static void
freeIOC (IOContext * this, int unlinkTreeFiles)
{
  int i;
  char *fn;

  for (i = 0; i <= this->treedepth; i++)
    {
      if (this->handles[i] != -1)
        {
          CLOSE (this->handles[i]);
          this->handles[i] = -1;
        }
    }
  MUTEX_DESTROY (this->lock);
  if (YES == unlinkTreeFiles)
    {
      for (i = 1; i <= this->treedepth; i++)
        {
          fn = MALLOC (strlen (this->filename) + 3);
          strcpy (fn, this->filename);
          strcat (fn, ".A");
          fn[strlen (fn) - 1] += i;
          if (0 != UNLINK (fn))
            GE_LOG (this->ectx,
                    GE_WARNING | GE_BULK | GE_USER,
                    _("Could not unlink temporary file `%s': %s\n"),
                    fn, STRERROR (errno));
          FREE (fn);
        }
    }
  FREE (this->filename);
  FREE (this->handles);
}

/**
 * Initialize an IOContext.
 *
 * @param this the context to initialize
 * @param no_temporaries disallow creation of temp files
 * @param filesize the size of the file
 * @param filename the name of the level-0 file
 * @return OK on success, SYSERR on failure
 */
static int
createIOContext (struct GE_Context *ectx,
                 IOContext * this,
                 int no_temporaries,
                 unsigned long long filesize, const char *filename)
{
  int i;
  char *fn;
  struct stat st;

  this->ectx = ectx;
  GE_ASSERT (ectx, filename != NULL);
  this->treedepth = computeDepth (filesize);
  this->lock = MUTEX_CREATE (NO);
  this->handles = MALLOC (sizeof (int) * (this->treedepth + 1));
  this->filename = STRDUP (filename);

  if ((0 == STAT (filename, &st)) && ((size_t) st.st_size > filesize))
    {
      /* if exists and oversized, truncate */
      if (truncate (filename, filesize) != 0)
        {
          GE_LOG_STRERROR_FILE (ectx,
                                GE_ERROR | GE_ADMIN | GE_BULK,
                                "truncate", filename);
          return SYSERR;
        }
    }
  for (i = 0; i <= this->treedepth; i++)
    this->handles[i] = -1;

  for (i = 0; i <= this->treedepth; i++)
    {
      if ((i == 0) || (no_temporaries != YES))
        {
          fn = MALLOC (strlen (filename) + 3);
          strcpy (fn, filename);
          if (i > 0)
            {
              strcat (fn, ".A");
              fn[strlen (fn) - 1] += i;
            }
          this->handles[i] = disk_file_open (ectx,
                                             fn,
                                             O_CREAT | O_RDWR,
                                             S_IRUSR | S_IWUSR);
          if (this->handles[i] < 0)
            {
              freeIOC (this, YES);
              FREE (fn);
              return SYSERR;
            }
          FREE (fn);
        }
    }
  return OK;
}

/**
 * Read method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to read/write at
 * @param pos position where to read or write
 * @param buf where to read from or write to
 * @param len how many bytes to read or write
 * @return number of bytes read, SYSERR on error
 */
int
readFromIOC (IOContext * this,
             unsigned int level,
             unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  MUTEX_LOCK (this->lock);
  if (this->handles[level] == -1)
    {
      MUTEX_UNLOCK (this->lock);
      return SYSERR;
    }
  lseek (this->handles[level], pos, SEEK_SET);
  ret = READ (this->handles[level], buf, len);
  MUTEX_UNLOCK (this->lock);
#if DEBUG_DOWNLOAD
  GE_LOG (this->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "IOC read at level %u offset %llu wanted %u got %d\n",
          level, pos, len, ret);
#endif
  return ret;
}

/**
 * Write method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to write to
 * @param pos position where to  write
 * @param buf where to write to
 * @param len how many bytes to write
 * @return number of bytes written, SYSERR on error
 */
int
writeToIOC (IOContext * this,
            unsigned int level,
            unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  MUTEX_LOCK (this->lock);
  if ((this->handles[level] == -1) && (level > 0))
    {
      MUTEX_UNLOCK (this->lock);
      return len;               /* lie -- no temps allowed... */
    }
  lseek (this->handles[level], pos, SEEK_SET);
  ret = WRITE (this->handles[level], buf, len);
  if (ret != len)
    {
      GE_LOG (this->ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("Write(%d, %p, %d) failed: %s\n"),
              this->handles[level], buf, len, STRERROR (errno));
    }
  MUTEX_UNLOCK (this->lock);
#if DEBUG_DOWNLOAD
  GE_LOG (this->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "IOC write at level %u offset %llu writes %u\n", level, pos, len);
#endif
  return ret;
}

/* ********************* request manager **************** */

/**
 * Node-specific data (not shared, keep small!). 56 bytes.
 */
typedef struct
{
  /**
   * Pointer to shared data between all nodes (request manager,
   * progress data, etc.).
   */
  struct CommonCtx *ctx;

  /**
   * What is the CHK for this block?
   */
  CHK chk;

  /**
   * At what offset (on the respective level!) is this
   * block?
   */
  unsigned long long offset;

  /**
   * 0 for dblocks, >0 for iblocks.
   */
  unsigned int level;
} NodeClosure;

/**
 * @brief Format of a request as tracked by the RequestManager.
 *
 * This structure together with the NodeContext determine the memory
 * requirements, so try keeping it as small as possible!  (currently
 * 32 bytes, plus 56 in the NodeContext => roughly 88 byte per block!)
 *
 * Estimate: max ~12 MB memory for a 4 GB file in the end (assuming
 * maximum parallelism, which is likely, so we are really going to use
 * about 12 MB, but that should be acceptable).
 *
 * Design question: why not union RequestEntry and NodeClosure (would
 * save yet another 4 bytes / entry)?
 */
typedef struct RequestEntry
{

  /**
   * The node for which this entry keeps data.
   */
  NodeClosure *node;

  /**
   * Search handle of the last request (NULL if never
   * requested).
   */
  struct FS_SEARCH_HANDLE *searchHandle;

  /**
   * Last time the query was send.
   */
  cron_t lasttime;

  /**
   * Timeout used for the last search (ttl in request is
   * = lastTimeout - lasttime modulo corrections in gap
   * with respect to priority cap).
   */
  cron_t lastTimeout;

  /**
   * How long have we been actively trying this one?
   */
  unsigned int tries;

  /**
   * Priority used for the last request.
   */
  unsigned int lastPriority;

} RequestEntry;

/**
 * @brief structure that keeps track of currently pending requests for
 *        a download
 *
 * Handle to the state of a request manager.  Here we keep track of
 * which queries went out with which priorities and which nodes in
 * the merkle-tree are waiting for the replies.
 */
typedef struct RequestManager
{

  /**
   * Mutex for synchronizing access to this struct
   */
  struct MUTEX *lock;

  /**
   * Current list of all pending requests
   */
  RequestEntry **requestList;

  struct FS_SEARCH_CONTEXT *sctx;

  struct PTHREAD *requestThread;

  struct GE_Context *ectx;

  struct GC_Configuration *cfg;

  PeerIdentity target;

  /**
   * Number of pending requests (highest used index)
   */
  unsigned int requestListIndex;

  /**
   * Number of entries allocated for requestList
   */
  unsigned int requestListSize;

  /**
   * Current "good" TTL (initial) [64s].  In HOST byte order.
   */
  unsigned int initialTTL;

  /**
   * Congestion window.  How many messages
   * should be pending concurrently?
   */
  unsigned int congestionWindow;

  /**
   * Slow-start threshold (see RFC 2001)
   */
  unsigned int ssthresh;

  /**
   * What was the last time we updated ssthresh?
   */
  TIME_T lastDET;

  /**
   * Abort?  Flag that can be set at any time
   * to abort the RM as soon as possible.
   */
  int abortFlag;

  /**
   * Is the request manager being destroyed?
   * (if so, accessing the request list is illegal!)
   */
  int shutdown;

  /**
   * Do we have a specific peer from which we download
   * from?
   */
  int have_target;

} RequestManager;

/**
 * Create a request manager.  Will create the request manager
 * datastructures. Use destroyRequestManager to abort and/or to free
 * resources after the download is complete.
 *
 * @return NULL on error
 */
static RequestManager *
createRequestManager (struct GE_Context *ectx, struct GC_Configuration *cfg)
{
  RequestManager *rm;

  rm = MALLOC (sizeof (RequestManager));
  rm->shutdown = NO;
  rm->lock = MUTEX_CREATE (YES);
  rm->sctx = FS_SEARCH_makeContext (ectx, cfg, rm->lock);
  if (rm->sctx == NULL)
    {
      MUTEX_DESTROY (rm->lock);
      FREE (rm);
      return NULL;
    }
  rm->ectx = ectx;
  rm->cfg = cfg;
  rm->requestThread = PTHREAD_GET_SELF ();
  rm->abortFlag = NO;
  rm->lastDET = 0;
  rm->requestListIndex = 0;
  rm->requestListSize = 0;
  rm->requestList = NULL;
  rm->have_target = NO;
  GROW (rm->requestList, rm->requestListSize, 256);
  rm->initialTTL = 5 * cronSECONDS;
  /* RFC 2001 suggests to use 1 segment size initially;
     Given 1500 octets per message in GNUnet, we would
     have 2-3 queries of maximum size (552); but since
     we are multi-casting to many peers at the same
     time AND since queries can be much smaller,
     we do WHAT??? */
  rm->congestionWindow = 1;     /* RSS is 1 */
  rm->ssthresh = 65535;
#if DEBUG_DOWNLOAD
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "created request manager %p\n", rm);
#endif
  return rm;
}

/**
 * Destroy the resources associated with a request manager.
 * Invoke this method to abort the download or to clean up
 * after the download is complete.
 *
 * @param rm the request manager struct from createRequestManager
 */
static void
destroyRequestManager (RequestManager * rm)
{
  int i;

#if DEBUG_DOWNLOAD
  GE_LOG (rm->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "destroying request manager %p\n", rm);
#endif
  MUTEX_LOCK (rm->lock);
  /* cannot hold lock during shutdown since
     fslib may have to aquire it; but we can
     flag that we are in the shutdown process
     and start to ignore fslib events! */
  rm->shutdown = YES;
  MUTEX_UNLOCK (rm->lock);
  for (i = 0; i < rm->requestListIndex; i++)
    {
      if (rm->requestList[i]->searchHandle != NULL)
        FS_stop_search (rm->sctx, rm->requestList[i]->searchHandle);
      FREE (rm->requestList[i]->node);
      FREE (rm->requestList[i]);
    }
  GROW (rm->requestList, rm->requestListSize, 0);
  FS_SEARCH_destroyContext (rm->sctx);
  rm->sctx = NULL;
  MUTEX_DESTROY (rm->lock);
  PTHREAD_REL_SELF (rm->requestThread);
  FREE (rm);
}

/**
 * We are approaching the end of the download.  Cut
 * all TTLs in half.
 */
static void
requestManagerEndgame (RequestManager * rm)
{
  int i;

  MUTEX_LOCK (rm->lock);
  if (rm->shutdown == NO)
    {
      for (i = 0; i < rm->requestListIndex; i++)
        {
          RequestEntry *entry = rm->requestList[i];
          /* cut TTL in half */
          entry->lasttime += (entry->lasttime + entry->lastTimeout) / 2;
        }
    }
  MUTEX_UNLOCK (rm->lock);
}

/**
 * Queue a request for execution.
 *
 * @param rm the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 */
static void
addRequest (RequestManager * rm, NodeClosure * node)
{
  RequestEntry *entry;
#if DEBUG_DOWNLOAD
  EncName enc;

  IF_GELOG (rm->ectx,
            GE_DEBUG | GE_REQUEST | GE_USER,
            hash2enc (&node->chk.query, &enc));
  GE_LOG (rm->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Queuing request (query: %s)\n", &enc);
#endif

  GE_ASSERT (rm->ectx, node != NULL);
  entry = MALLOC (sizeof (RequestEntry));
  entry->node = node;
  entry->lasttime = 0;          /* never sent */
  entry->lastTimeout = 0;
  entry->tries = 0;             /* not tried so far */
  entry->lastPriority = 0;
  entry->searchHandle = NULL;
  MUTEX_LOCK (rm->lock);
  if (rm->shutdown == NO)
    {
      GE_ASSERT (rm->ectx, rm->requestListSize > 0);
      if (rm->requestListSize == rm->requestListIndex)
        GROW (rm->requestList, rm->requestListSize, rm->requestListSize * 2);
      rm->requestList[rm->requestListIndex++] = entry;
    }
  else
    {
      GE_BREAK (rm->ectx, 0);
      FREE (entry);
    }
  MUTEX_UNLOCK (rm->lock);
}


/**
 * Cancel a request.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is canceled
 */
static void
delRequest (RequestManager * rm, NodeClosure * node)
{
  int i;
  RequestEntry *re;

  MUTEX_LOCK (rm->lock);
  if (rm->shutdown == NO)
    {
      for (i = 0; i < rm->requestListIndex; i++)
        {
          re = rm->requestList[i];
          if (re->node == node)
            {
              rm->requestList[i] = rm->requestList[--rm->requestListIndex];
              rm->requestList[rm->requestListIndex] = NULL;
              MUTEX_UNLOCK (rm->lock);
              if (NULL != re->searchHandle)
                FS_stop_search (rm->sctx, re->searchHandle);
              FREE (re);
              return;
            }
        }
    }
  MUTEX_UNLOCK (rm->lock);
  GE_BREAK (rm->ectx, 0);       /* uh uh - at least a memory leak... */
}


/* ****************** tree nodes ***************** */

/**
 * Data shared between all tree nodes.
 * Design Question: integrate with IOContext?
 */
typedef struct CommonCtx
{
  unsigned long long total;
  unsigned long long completed;
  unsigned long long offset;
  unsigned long long length;
  cron_t startTime;
  cron_t TTL_DECREMENT;
  RequestManager *rm;
  IOContext *ioc;
  ECRS_DownloadProgressCallback dpcb;
  void *dpcbClosure;
  unsigned int anonymityLevel;
} CommonCtx;

/**
 * Compute how many bytes of data are stored in
 * this node.
 */
static unsigned int
getNodeSize (const NodeClosure * node)
{
  unsigned int i;
  unsigned int ret;
  unsigned long long rsize;
  unsigned long long spos;
  unsigned long long epos;

  GE_ASSERT (node->ctx->rm->ectx, node->offset < node->ctx->total);
  if (node->level == 0)
    {
      ret = DBLOCK_SIZE;
      if (node->offset + (unsigned long long) ret > node->ctx->total)
        ret = (unsigned int) (node->ctx->total - node->offset);
#if DEBUG_DOWNLOAD
      GE_LOG (node->ctx->rm->ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Node at offset %llu and level %d has size %u\n",
              node->offset, node->level, ret);
#endif
      return ret;
    }
  rsize = DBLOCK_SIZE;
  for (i = 0; i < node->level - 1; i++)
    rsize *= CHK_PER_INODE;
  spos = rsize * (node->offset / sizeof (CHK));
  epos = spos + rsize * CHK_PER_INODE;
  if (epos > node->ctx->total)
    epos = node->ctx->total;
  ret = (epos - spos) / rsize;
  if (ret * rsize < epos - spos)
    ret++;                      /* need to round up! */
#if DEBUG_DOWNLOAD
  GE_LOG (node->ctx->rm->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Node at offset %llu and level %d has size %u\n",
          node->offset, node->level, ret * sizeof (CHK));
#endif
  return ret * sizeof (CHK);
}

/**
 * Update progress information. Also updates
 * request manager structures, like ttl.
 */
static void
updateProgress (const NodeClosure * node, const char *data, unsigned int size)
{
  RequestManager *rm;
  RequestEntry *entry;
  int pos;
  int i;

  /* locking? */
  if (node->level == 0)
    {
      cron_t eta;

      node->ctx->completed += size;
      eta = get_time ();
      if (node->ctx->completed > 0)
        {
          eta = (cron_t) (node->ctx->startTime +
                          (((double) (eta - node->ctx->startTime) /
                            (double) node->ctx->completed)) *
                          (double) node->ctx->length);
        }
      if (node->ctx->dpcb != NULL)
        {
          node->ctx->dpcb (node->ctx->length,
                           node->ctx->completed,
                           eta,
                           node->offset, data, size, node->ctx->dpcbClosure);
        }
    }
  rm = node->ctx->rm;
  MUTEX_LOCK (rm->lock);
  if (rm->shutdown == YES)
    {
      MUTEX_UNLOCK (rm->lock);
      return;
    }

  /* check type of reply msg, fill in query */
  pos = -1;
  /* find which query matches the reply, call the callback
     and recycle the slot */
  for (i = 0; i < rm->requestListIndex; i++)
    if (rm->requestList[i]->node == node)
      pos = i;
  if (pos == -1)
    {
      /* GE_BREAK(ectx, 0); *//* should never happen */
      MUTEX_UNLOCK (rm->lock);
      return;
    }
  entry = rm->requestList[pos];

  if ((entry->lasttime < get_time ()) && (entry->lasttime != 0))
    {
      unsigned int weight = 15;
      unsigned int ettl = entry->lastTimeout - entry->lasttime;
      if ((ettl > 4 * rm->initialTTL) &&
          ((get_time () - entry->lasttime) < rm->initialTTL))
        {
          weight = 127;
          /* eTTL is MUCH bigger than what we currently expect AND the time
             between the last query and the reply was in the range of the
             expected TTL => don't take ettl too much into account! */
        }
      rm->initialTTL = ((rm->initialTTL) * weight + ettl) / (weight + 1);

      /* RFC 2001: increase cwnd; note that we can't really discriminate between
         slow-start and cong. control mode since our RSS is too small... */
      if (rm->congestionWindow < rm->ssthresh)
        rm->congestionWindow += 2;      /* slow start */
      else
        rm->congestionWindow += 1;      /* slower start :-) */
    }
  if (entry->tries > 1)
    {
      TIME_T nowTT;

      TIME (&nowTT);
      if ((nowTT - rm->initialTTL) > rm->lastDET)
        {
          /* only consider congestion control every
             "average" TTL seconds, otherwise the system
             reacts to events that are far too old! */
          /* we performed retransmission, treat as congestion (RFC 2001) */
          rm->ssthresh = rm->congestionWindow / 2;
          if (rm->ssthresh < 2)
            rm->ssthresh = 2;
          rm->congestionWindow = rm->ssthresh + 1;
          rm->lastDET = nowTT;
        }
    }
  MUTEX_UNLOCK (rm->lock);
}


/**
 * Download children of this IBlock.
 *
 * @param rm the node that should downloaded
 */
static void iblock_download_children (NodeClosure * node,
                                      char *data, unsigned int size);

/**
 * Check if this block is already present on the drive.  If the block
 * is a dblock and present, the ProgressModel is notified. If the
 * block is present and it is an iblock, downloading the children is
 * triggered.
 *
 * Also checks if the block is within the range of blocks
 * that we are supposed to download.  If not, the method
 * returns as if the block is present but does NOT signal
 * progress.
 *
 * @param node that is checked for presence
 * @return YES if present, NO if not.
 */
static int
checkPresent (NodeClosure * node)
{
  int res;
  int ret;
  char *data;
  unsigned int size;
  HashCode512 hc;

  size = getNodeSize (node);

  /* first check if node is within range.
     For now, keeping it simple, we only do
     this for level-0 nodes */
  if ((node->level == 0) &&
      ((node->offset + size < node->ctx->offset) ||
       (node->offset >= node->ctx->offset + node->ctx->length)))
    return YES;

  data = MALLOC (size);
  res = readFromIOC (node->ctx->ioc, node->level, node->offset, data, size);
  if (res == size)
    {
      hash (data, size, &hc);
      if (equalsHashCode512 (&hc, &node->chk.key))
        {
          updateProgress (node, data, size);
          if (node->level > 0)
            iblock_download_children (node, data, size);

          ret = YES;
        }
      else
        ret = NO;
    }
  else
    ret = NO;
  FREE (data);
#if DEBUG_DOWNLOAD
  GE_LOG (node->ctx->rm->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Checked presence of block at %llu level %u.  Result: %s\n",
          node->offset, node->level, ret == YES ? "YES" : "NO");
#endif

  return ret;
}

/**
 * Download children of this IBlock.
 *
 * @param this the node that should downloaded
 */
static void
iblock_download_children (NodeClosure * node, char *data, unsigned int size)
{
  struct GE_Context *ectx = node->ctx->rm->ectx;
  int i;
  NodeClosure *child;
  unsigned int childcount;
  CHK *chks;
  unsigned int levelSize;
  unsigned long long baseOffset;

  GE_ASSERT (ectx, node->level > 0);
  childcount = size / sizeof (CHK);
  if (size != childcount * sizeof (CHK))
    {
      GE_BREAK (ectx, 0);
      return;
    }
  if (node->level == 1)
    {
      levelSize = DBLOCK_SIZE;
      baseOffset = node->offset / sizeof (CHK) * DBLOCK_SIZE;
    }
  else
    {
      levelSize = sizeof (CHK) * CHK_PER_INODE;
      baseOffset = node->offset * CHK_PER_INODE;
    }
  chks = (CHK *) data;
  for (i = 0; i < childcount; i++)
    {
      child = MALLOC (sizeof (NodeClosure));
      child->ctx = node->ctx;
      child->chk = chks[i];
      child->offset = baseOffset + i * levelSize;
      GE_ASSERT (ectx, child->offset < node->ctx->total);
      child->level = node->level - 1;
      GE_ASSERT (ectx, (child->level != 0) ||
                 ((child->offset % DBLOCK_SIZE) == 0));
      if (NO == checkPresent (child))
        addRequest (node->ctx->rm, child);
      else
        FREE (child);           /* done already! */
    }
}


/**
 * Decrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
static int
decryptContent (const char *data,
                unsigned int size, const HashCode512 * hashcode, char *result)
{
  INITVECTOR iv;
  SESSIONKEY skey;

  GE_ASSERT (NULL, (data != NULL) && (hashcode != NULL) && (result != NULL));
  /* get key and init value from the hash code */
  hashToKey (hashcode, &skey, &iv);
  return decryptBlock (&skey, data, size, &iv, result);
}


/**
 * We received a CHK reply for a block. Decrypt.  Note
 * that the caller (fslib) has already aquired the
 * RM lock (we sometimes aquire it again in callees,
 * mostly because our callees could be also be theoretically
 * called from elsewhere).
 *
 * @param node the node for which the reply is given, freed in
 *        this function!
 * @param query the query for which reply is the answer
 * @param reply the reply
 * @return OK if the reply was valid, SYSERR on error
 */
static int
nodeReceive (const HashCode512 * query,
             const Datastore_Value * reply, void *cls, unsigned long long uid)
{
  NodeClosure *node = cls;
  struct GE_Context *ectx = node->ctx->rm->ectx;
  HashCode512 hc;
  unsigned int size;
  int i;
  char *data;
#if DEBUG_DOWNLOAD
  EncName enc;

  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Receiving reply to query `%s'\n", &enc);
#endif
  GE_ASSERT (ectx, equalsHashCode512 (query, &node->chk.query));
  size = ntohl (reply->size) - sizeof (Datastore_Value);
  if ((size <= sizeof (DBlock)) ||
      (size - sizeof (DBlock) != getNodeSize (node)))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;            /* invalid size! */
    }
  size -= sizeof (DBlock);
  data = MALLOC (size);
  if (SYSERR == decryptContent ((char *) &((DBlock *) & reply[1])[1],
                                size, &node->chk.key, data))
    GE_ASSERT (ectx, 0);
  hash (data, size, &hc);
  if (!equalsHashCode512 (&hc, &node->chk.key))
    {
      delRequest (node->ctx->rm, node);
      FREE (data);
      GE_BREAK (ectx, 0);
      GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
              _("Decrypted content does not match key. "
                "This is either a bug or a maliciously inserted "
                "file. Download aborted.\n"));
      node->ctx->rm->abortFlag = YES;
      return SYSERR;
    }
  if (size != writeToIOC (node->ctx->ioc,
                          node->level, node->offset, data, size))
    {
      GE_LOG_STRERROR (ectx,
                       GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "WRITE");
      node->ctx->rm->abortFlag = YES;
      return SYSERR;
    }
  updateProgress (node, data, size);
  if (node->level > 0)
    iblock_download_children (node, data, size);
  /* request satisfied, stop requesting! */
  delRequest (node->ctx->rm, node);

  for (i = 0; i < 10; i++)
    {
      if ((node->ctx->completed * 10000L >
           node->ctx->length * (10000L - (1024 >> i))) &&
          ((node->ctx->completed - size) * 10000L <=
           node->ctx->length * (10000L - (1024 >> i))))
        {
          /* end-game boundary crossed, slaughter TTLs */
          requestManagerEndgame (node->ctx->rm);
        }
    }
  GE_ASSERT (node->ctx->rm->ectx, node->ctx->rm->requestThread != NULL);
  PTHREAD_STOP_SLEEP (node->ctx->rm->requestThread);
  FREE (data);
  FREE (node);
  return OK;
}


/**
 * Send the request from the requestList[requestIndex] out onto
 * the network.
 *
 * @param this the RequestManager
 * @param requestIndex the index of the Request to issue
 */
static void
issueRequest (RequestManager * rm, int requestIndex)
{
  static unsigned int lastmpriority;
  static cron_t lastmpritime;
  RequestEntry *entry;
  cron_t now;
  unsigned int priority;
  unsigned int mpriority;
  cron_t timeout;
  unsigned int ttl;
  int TTL_DECREMENT;
#if DEBUG_DOWNLOAD
  EncName enc;
#endif

  now = get_time ();
  entry = rm->requestList[requestIndex];

  /* compute priority */
  if (lastmpritime + 10 * cronSECONDS < now)
    {
      /* only update avg. priority at most every
         10 seconds */
      struct ClientServerConnection *sock;

      sock = client_connection_create (rm->ectx, rm->cfg);
      lastmpriority = FS_getAveragePriority (sock);
      lastmpritime = now;
      connection_destroy (sock);
    }
  mpriority = lastmpriority;
  priority = entry->lastPriority + weak_randomi (1 + entry->tries);
  if (priority > mpriority)
    {
      /* mpriority is (2 * (current average priority + 2)) and
         is used as the maximum priority that we use; if the
         calculated tpriority is above it, we reduce tpriority
         to random value between the average (mpriority/2) but
         bounded by mpriority */
      priority = 1 + mpriority / 2 + (weak_randomi (2 + mpriority / 2));
    }
  if (priority > 0x0FFFFFF)
    priority = weak_randomi (0xFFFFFF); /* bound! */

  /* compute TTL */

  TTL_DECREMENT = entry->node->ctx->TTL_DECREMENT;

  if (entry->lastTimeout + TTL_DECREMENT > now)
    GE_BREAK (rm->ectx, 0);
  if (entry->lasttime == 0)
    {
      timeout = now + rm->initialTTL;
    }
  else
    {
      ttl = entry->lastTimeout - entry->lasttime;
      if (ttl > MAX_TTL)
        {
          ttl = MAX_TTL + weak_randomi (2 * TTL_DECREMENT);
        }
      else if (ttl > rm->initialTTL)
        {
          /* switch to slow back-off */
          unsigned int rd;
          if (rm->initialTTL == 0)
            rd = ttl;
          else
            rd = ttl / rm->initialTTL;
          if (rd == 0)
            rd = 1;             /* how? */
          rd = TTL_DECREMENT / rd;
          if (rd == 0)
            rd = 1;
          ttl += weak_randomi (50 * cronMILLIS + rd);
          /* rd == TTL_DECREMENT / (con->ttl / rm->initialTTL) + saveguards
             50ms: minimum increment */
        }
      else
        {
          ttl += weak_randomi (ttl + 2 * TTL_DECREMENT);        /* exponential backoff with random factor */
        }
      if (ttl > (priority + 8) * TTL_DECREMENT)
        ttl = (priority + 8) * TTL_DECREMENT;   /* see adjustTTL in gap */
      timeout = now + ttl;
    }

#if DEBUG_DOWNLOAD
  IF_GELOG (ectx,
            GE_DEBUG | GE_REQUEST | GE_USER,
            hash2enc (&entry->node->chk.query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Starting FS search for %s:%llu:%u `%s'\n",
          entry->node->ctx->ioc->filename,
          entry->node->offset, entry->node->level, &enc);
#endif

  if (entry->searchHandle != NULL)
    FS_stop_search (rm->sctx, entry->searchHandle);
  entry->searchHandle
    = FS_start_search (rm->sctx,
                       rm->have_target == NO ? NULL : &rm->target,
                       D_BLOCK,
                       1,
                       &entry->node->chk.query,
                       entry->node->ctx->anonymityLevel,
                       priority, timeout, &nodeReceive, entry->node);
  if (entry->searchHandle != NULL)
    {
      entry->lastPriority = priority;
      entry->lastTimeout = timeout;
      entry->lasttime = now + 2 * TTL_DECREMENT;
      if (weak_randomi (1 + entry->tries) > 1)
        {
          /* do linear (in tries) extra back-off (in addition to ttl)
             to avoid repeatedly tie-ing with other peers; rm is somewhat
             equivalent to what ethernet is doing, only that 'tries' is our
             (rough) indicator for collisions.  For ethernet back-off, see:
             http://www.industrialethernetuniversity.com/courses/101_4.htm
           */
          entry->lasttime +=
            weak_randomi (TTL_DECREMENT * (1 + entry->tries));
        }
      entry->tries++;
    }
  /* warn if number of attempts goes too high */
  if ((0 == (entry->tries % MAX_TRIES)) && (entry->tries > 0))
    {
      EncName enc;
      IF_GELOG (rm->ectx,
                GE_WARNING | GE_BULK | GE_USER,
                hash2enc (&entry->node->chk.key, &enc));
      GE_LOG (rm->ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _
              ("Content `%s' seems to be not available on the network (tried %u times).\n"),
              &enc, entry->tries);
    }
}

/**
 * Cron job that re-issues requests. Should compute how long to sleep
 * (min ttl until next job is ready) and re-schedule itself
 * accordingly!
 */
static cron_t
processRequests (RequestManager * rm)
{
  cron_t minSleep;
  cron_t now;
  cron_t delta;
  int i;
  unsigned int pending;
  int *perm;
  unsigned int TTL_DECREMENT;

  MUTEX_LOCK (rm->lock);
  if ((rm->shutdown == YES) || (rm->requestListIndex == 0))
    {
      MUTEX_UNLOCK (rm->lock);
      return 0;
    }
  now = get_time ();
  pending = 0;
  TTL_DECREMENT = 0;
  if (rm->requestListIndex > 0)
    TTL_DECREMENT = rm->requestList[0]->node->ctx->TTL_DECREMENT;

  for (i = 0; i < rm->requestListIndex; i++)
    {
      if (rm->requestList[i]->lastTimeout >= now - TTL_DECREMENT)
        {
          pending++;
        }
      else if (rm->requestList[i]->searchHandle != NULL)
        {
          FS_stop_search (rm->sctx, rm->requestList[i]->searchHandle);
          rm->requestList[i]->searchHandle = NULL;
        }
    }

  minSleep = 5000 * cronMILLIS; /* max-sleep! */
  perm = permute (WEAK, rm->requestListIndex);
  for (i = 0; i < rm->requestListIndex; i++)
    {
      int j = perm[i];
      if (rm->requestList[j]->lastTimeout + TTL_DECREMENT < now)
        {
          int pOCWCubed;
          int pendingOverCWin = pending - rm->congestionWindow;
          if (pendingOverCWin <= 0)
            pendingOverCWin = -1;       /* avoid 0! */
          pOCWCubed = pendingOverCWin * pendingOverCWin * pendingOverCWin;
          if ((pOCWCubed <= 0) ||
              (pOCWCubed * rm->requestListIndex <= 0) /* see #642 */  ||
              /* avoid no-start: override congestionWindow occasionally... */
              (0 == weak_randomi (rm->requestListIndex * pOCWCubed)))
            {
              issueRequest (rm, j);
              delta = (rm->requestList[j]->lastTimeout - now) + TTL_DECREMENT;
              pending++;
            }
          else
            {
              delta = 0;
            }
        }
      else
        {
          delta = (rm->requestList[j]->lastTimeout + TTL_DECREMENT - now);
        }
      if (delta < minSleep)
        minSleep = delta;
    }
  FREE (perm);
  if (minSleep < cronMILLIS * 100)
    minSleep = cronMILLIS * 100;        /* maximum resolution: 100ms */
  MUTEX_UNLOCK (rm->lock);
  return minSleep;
}



/* ***************** main method **************** */

/**
 * Download a file.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 */
int
ECRS_downloadFile (struct GE_Context *ectx,
                   struct GC_Configuration *cfg,
                   const struct ECRS_URI *uri,
                   const char *filename,
                   unsigned int anonymityLevel,
                   ECRS_DownloadProgressCallback dpcb,
                   void *dpcbClosure, ECRS_TestTerminate tt, void *ttClosure)
{
  return ECRS_downloadPartialFile (ectx,
                                   cfg,
                                   uri,
                                   filename,
                                   0,
                                   ECRS_fileSize (uri),
                                   anonymityLevel,
                                   NO, dpcb, dpcbClosure, tt, ttClosure);
}


/**
 * Download parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.
 * Also, the download is still using the blocking of the
 * underlying ECRS encoding.  As a result, the download
 * may *write* outside of the given boundaries (if offset
 * and length do not match the 32k ECRS block boundaries).
 * <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 * @param no_temporaries set to YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
int
ECRS_downloadPartialFile (struct GE_Context *ectx,
                          struct GC_Configuration *cfg,
                          const struct ECRS_URI *uri,
                          const char *filename,
                          unsigned long long offset,
                          unsigned long long length,
                          unsigned int anonymityLevel,
                          int no_temporaries,
                          ECRS_DownloadProgressCallback dpcb,
                          void *dpcbClosure,
                          ECRS_TestTerminate tt, void *ttClosure)
{
  IOContext ioc;
  RequestManager *rm;
  int ret;
  CommonCtx ctx;
  NodeClosure *top;
  FileIdentifier fid;
  cron_t minSleep;
  char *realFN;
  char *path;
  char *pos;
  struct stat buf;

#if DEBUG_DOWNLOAD
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' running for file `%s'\n", __FUNCTION__, filename);
#endif
  GE_ASSERT (ectx, filename != NULL);
  if ((filename[strlen (filename) - 1] == '/') ||
      (filename[strlen (filename) - 1] == '\\'))
    {
      realFN = MALLOC (strlen (filename) + strlen (GNUNET_DIRECTORY_EXT));
      strcpy (realFN, filename);
      realFN[strlen (filename) - 1] = '\0';
      strcat (realFN, GNUNET_DIRECTORY_EXT);
    }
  else
    {
      realFN = STRDUP (filename);
    }
  path = MALLOC (strlen (realFN) * strlen (GNUNET_DIRECTORY_EXT) + 1);
  strcpy (path, realFN);
  pos = path;
  while (*pos != '\0')
    {
      if (*pos == DIR_SEPARATOR)
        {
          *pos = '\0';
          if ((0 == STAT (path, &buf)) && (!S_ISDIR (buf.st_mode)))
            {
              *pos = DIR_SEPARATOR;
              memmove (pos + strlen (GNUNET_DIRECTORY_EXT),
                       pos, strlen (pos));
              memcpy (pos,
                      GNUNET_DIRECTORY_EXT, strlen (GNUNET_DIRECTORY_EXT));
              pos += strlen (GNUNET_DIRECTORY_EXT);
            }
          else
            {
              *pos = DIR_SEPARATOR;
            }
        }
      pos++;
    }
  FREE (realFN);
  realFN = path;

  if (SYSERR == disk_directory_create_for_file (ectx, realFN))
    {
      FREE (realFN);
      return SYSERR;
    }
  if (0 == ECRS_fileSize (uri))
    {
      ret = disk_file_open (ectx,
                            realFN,
                            O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
      FREE (realFN);
      if (ret == -1)
        return SYSERR;
      CLOSE (ret);
      dpcb (0, 0, get_time (), 0, NULL, 0, dpcbClosure);
      return OK;
    }
  fid = uri->data.fi;

  if ((!ECRS_isFileUri (uri)) && (!ECRS_isLocationUri (uri)))
    {
      GE_BREAK (ectx, 0);
      FREE (realFN);
      return SYSERR;
    }

  if (OK != createIOContext (ectx,
                             &ioc,
                             no_temporaries,
                             ntohll (fid.file_length), realFN))
    {
#if DEBUG_DOWNLOAD
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "`%s' aborted for file `%s'\n", __FUNCTION__, realFN);
#endif
      FREE (realFN);
      return SYSERR;
    }
  rm = createRequestManager (ectx, cfg);
  if (rm == NULL)
    {
      freeIOC (&ioc, YES);
      FREE (realFN);
      return SYSERR;
    }
  if (ECRS_isLocationUri (uri))
    {
      hash (&uri->data.loc.peer, sizeof (PublicKey), &rm->target.hashPubKey);
      rm->have_target = YES;
    }

  ctx.startTime = get_time ();
  ctx.anonymityLevel = anonymityLevel;
  ctx.offset = offset;
  ctx.length = length;
  ctx.TTL_DECREMENT = 5 * cronSECONDS;  /* HACK! */
  ctx.rm = rm;
  ctx.ioc = &ioc;
  ctx.dpcb = dpcb;
  ctx.dpcbClosure = dpcbClosure;
  ctx.total = ntohll (fid.file_length);
  ctx.completed = 0;
  top = MALLOC (sizeof (NodeClosure));
  top->ctx = &ctx;
  top->chk = fid.chk;
  top->offset = 0;
  top->level = computeDepth (ctx.total);
  if (NO == checkPresent (top))
    addRequest (rm, top);
  else
    FREE (top);
  while ((OK == tt (ttClosure)) &&
         (rm->abortFlag == NO) && (rm->requestListIndex != 0))
    {
      minSleep = processRequests (rm);
      if ((OK == tt (ttClosure)) &&
          (rm->abortFlag == NO) && (rm->requestListIndex != 0))
        PTHREAD_SLEEP (minSleep);
    }

  if ((rm->requestListIndex == 0) &&
      ((ctx.completed == ctx.total) ||
       ((ctx.total != ctx.length) &&
        (ctx.completed >= ctx.length))) && (rm->abortFlag == NO))
    {
      ret = OK;
    }
  else
    {
#if 0
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              "Download ends prematurely: %d %llu == %llu %d TT: %d\n",
              rm->requestListIndex,
              ctx.completed, ctx.total, rm->abortFlag, tt (ttClosure));
#endif
      ret = SYSERR;
    }
  destroyRequestManager (rm);
  if (ret == OK)
    {
      freeIOC (&ioc, YES);
    }
  else if (tt (ttClosure) == SYSERR)
    {
      freeIOC (&ioc, YES);
      if (0 != UNLINK (realFN))
        {
          GE_LOG_STRERROR_FILE (ectx,
                                GE_WARNING | GE_USER | GE_BULK,
                                "unlink", realFN);
        }
      else
        {                       /* delete empty directories */
          char *rdir;
          int len;

          rdir = STRDUP (realFN);
          len = strlen (rdir);
          do
            {
              while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
                len--;
              rdir[len] = '\0';
            }
          while ((len > 0) && (0 == rmdir (rdir)));
          FREE (rdir);
        }
    }
  else
    {
      freeIOC (&ioc, NO);       /* aborted */
    }
#if DEBUG_DOWNLOAD
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' terminating for file `%s' with result %s\n",
          __FUNCTION__, filename, ret == OK ? "SUCCESS" : "INCOMPLETE");
#endif
  FREE (realFN);
  return ret;
}

/* end of download.c */
