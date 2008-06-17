/*
     This file is part of GNUnet.
     (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/dstore/dstore.c
 * @brief SQLite based implementation of the dstore service
 * @author Christian Grothoff
 * @todo Indexes, statistics
 *
 * Database: SQLite
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dstore_service.h"
#include "gnunet_stats_service.h"
#include <sqlite3.h>

#define DEBUG_DSTORE GNUNET_NO

/**
 * Maximum size for an individual item.
 */
#define MAX_CONTENT_SIZE 65536

/**
 * Bytes used
 */
static unsigned long long payload;

/**
 * Maximum bytes available
 */
static unsigned long long quota;

/**
 * Filename of this database
 */
static char *fn;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *lock;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static unsigned int stat_dstore_size;

/**
 * Estimate of the per-entry overhead (including indices).
 */
#define OVERHEAD ((4+4+8+8*2+sizeof(GNUNET_HashCode)*2+32))

struct GNUNET_BloomFilter *bloom;

static char *bloom_name;

/**
 * @brief Prepare a SQL statement
 */
static int
sq_prepare (sqlite3 * dbh, const char *zSql,    /* SQL statement, UTF-8 encoded */
            sqlite3_stmt ** ppStmt)
{                               /* OUT: Statement handle */
  char *dummy;
  return sqlite3_prepare (dbh,
                          zSql,
                          strlen (zSql), ppStmt, (const char **) &dummy);
}

#define SQLITE3_EXEC(db, cmd) do { if (SQLITE_OK != sqlite3_exec(db, cmd, NULL, NULL, &emsg)) { GNUNET_GE_LOG(coreAPI->ectx, GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK, _("`%s' failed at %s:%d with error: %s\n"), "sqlite3_exec", __FILE__, __LINE__, emsg); sqlite3_free(emsg); } } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_GE_LOG(coreAPI->ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db)); } while(0)

static void
db_init (sqlite3 * dbh)
{
  char *emsg;

  SQLITE3_EXEC (dbh, "PRAGMA temp_store=MEMORY");
  SQLITE3_EXEC (dbh, "PRAGMA synchronous=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA count_changes=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA page_size=4092");
  SQLITE3_EXEC (dbh,
                "CREATE TABLE ds071 ("
                "  size INTEGER NOT NULL DEFAULT 0,"
                "  type INTEGER NOT NULL DEFAULT 0,"
                "  puttime INTEGER NOT NULL DEFAULT 0,"
                "  expire INTEGER NOT NULL DEFAULT 0,"
                "  key TEXT NOT NULL DEFAULT '',"
                "  value BLOB NOT NULL DEFAULT '')");
  SQLITE3_EXEC (dbh, "CREATE INDEX idx_key ON ds071 (key)");
  SQLITE3_EXEC (dbh, "CREATE INDEX idx_puttime ON ds071 (puttime)");
}

static int
db_reset ()
{
  int fd;
  sqlite3 *dbh;
  char *tmpl;

  if (fn != NULL)
    {
      UNLINK (fn);
      GNUNET_free (fn);
    }
  tmpl = "/tmp/dstoreXXXXXX";

#ifdef MINGW
  fn = (char *) GNUNET_malloc (MAX_PATH + 1);
  plibc_conv_to_win_path (tmpl, fn);
#else
  fn = GNUNET_strdup (tmpl);
#endif
  fd = mkstemp (fn);
  if (fd == -1)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (fn);
      fn = NULL;
      return GNUNET_SYSERR;
    }
  CLOSE (fd);
  if (SQLITE_OK != sqlite3_open (fn, &dbh))
    return GNUNET_SYSERR;
  db_init (dbh);
  sqlite3_close (dbh);
  return GNUNET_OK;
}

/**
 * Check that we are within quota.
 * @return GNUNET_OK if we are.
 */
static int
checkQuota (sqlite3 * dbh)
{
  GNUNET_HashCode dkey;
  unsigned int dsize;
  unsigned int dtype;
  GNUNET_CronTime dputtime;
  GNUNET_CronTime dexpire;
  char *dcontent;
  sqlite3_stmt *stmt;
  sqlite3_stmt *dstmt;
  int err;

  if (payload * 10 <= quota * 9)
    return GNUNET_OK;           /* we seem to be about 10% off */
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "DStore above qutoa (have %llu, allowed %llu), will delete some data.\n",
                 payload, quota);
#endif
  stmt = NULL;
  dstmt = NULL;
  if ((sq_prepare (dbh,
                   "SELECT size, type, puttime, expire, key, value FROM ds071 ORDER BY puttime ASC",
                   &stmt) != SQLITE_OK) ||
      (sq_prepare (dbh,
                   "DELETE FROM ds071 "
                   "WHERE size = ? AND type = ? AND puttime = ? AND expire = ? AND key = ? AND value = ?",
                   &dstmt) != SQLITE_OK))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (dbh));
      GNUNET_GE_BREAK (NULL, 0);
      if (dstmt != NULL)
        sqlite3_finalize (dstmt);
      if (stmt != NULL)
        sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  dcontent = GNUNET_malloc (MAX_CONTENT_SIZE);
  err = SQLITE_DONE;
  while ((payload * 10 > quota * 9) &&  /* we seem to be about 10% off */
         ((err = sqlite3_step (stmt)) == SQLITE_ROW))
    {
      dsize = sqlite3_column_int (stmt, 0);
      dtype = sqlite3_column_int (stmt, 1);
      dputtime = sqlite3_column_int64 (stmt, 2);
      dexpire = sqlite3_column_int64 (stmt, 3);
      GNUNET_GE_BREAK (NULL,
                       sqlite3_column_bytes (stmt,
                                             4) == sizeof (GNUNET_HashCode));
      GNUNET_GE_BREAK (NULL, dsize == sqlite3_column_bytes (stmt, 5));
      memcpy (&dkey, sqlite3_column_blob (stmt, 4), sizeof (GNUNET_HashCode));
      if (dsize >= MAX_CONTENT_SIZE)
        {
          GNUNET_GE_BREAK (NULL, 0);
          dsize = MAX_CONTENT_SIZE;
        }
      memcpy (dcontent, sqlite3_column_blob (stmt, 5), dsize);
      sqlite3_reset (stmt);
      sqlite3_bind_int (dstmt, 1, dsize);
      sqlite3_bind_int (dstmt, 2, dtype);
      sqlite3_bind_int64 (dstmt, 3, dputtime);
      sqlite3_bind_int64 (dstmt, 4, dexpire);
      sqlite3_bind_blob (dstmt,
                         5, &dkey, sizeof (GNUNET_HashCode),
                         SQLITE_TRANSIENT);
      sqlite3_bind_blob (dstmt, 6, dcontent, dsize, SQLITE_TRANSIENT);
      if ((err = sqlite3_step (dstmt)) != SQLITE_DONE)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                         _("`%s' failed at %s:%d with error: %s\n"),
                         "sqlite3_step", __FILE__, __LINE__,
                         sqlite3_errmsg (dbh));
          sqlite3_reset (dstmt);
          GNUNET_GE_BREAK (NULL, 0);    /* should delete but cannot!? */
          break;
        }
      payload -= (dsize + OVERHEAD);
#if DEBUG_DSTORE
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Deleting %u bytes decreases DStore payload to %llu out of %llu\n",
                     dsize, payload, quota);
#endif
      sqlite3_reset (dstmt);
    }
  if (err != SQLITE_DONE)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sqlite3_step", __FILE__, __LINE__,
                     sqlite3_errmsg (dbh));
    }
  GNUNET_free (dcontent);
  sqlite3_finalize (dstmt);
  sqlite3_finalize (stmt);
  if (payload * 10 > quota * 9)
    {
      /* we seem to be about 10% off */
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                     "Failed to delete content to drop below quota (bug?).\n",
                     payload, quota);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Store an item in the datastore.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
d_put (const GNUNET_HashCode * key,
       unsigned int type,
       GNUNET_CronTime discard_time, unsigned int size, const char *data)
{
  sqlite3 *dbh;
  sqlite3_stmt *stmt;
  int ret;

  if (size > MAX_CONTENT_SIZE)
    return GNUNET_SYSERR;
  GNUNET_mutex_lock (lock);
  if ((fn == NULL) || (SQLITE_OK != sqlite3_open (fn, &dbh)))
    {
      db_reset (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "dstore processes put `%.*s\n", size, data);
#endif

  /* first try UPDATE */
  if (sq_prepare (dbh,
                  "UPDATE ds071 SET puttime=?, expire=? "
                  "WHERE key=? AND type=? AND size=? AND value=?",
                  &stmt) != SQLITE_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (dbh));
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if ((SQLITE_OK != sqlite3_bind_int64 (stmt, 1, GNUNET_get_time ())) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, discard_time)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 3, key, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT))
      || (SQLITE_OK != sqlite3_bind_int (stmt, 4, type))
      || (SQLITE_OK != sqlite3_bind_int (stmt, 5, size))
      || (SQLITE_OK !=
          sqlite3_bind_blob (stmt, 6, data, size, SQLITE_TRANSIENT)))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sqlite3_bind_xxx", __FILE__, __LINE__,
                     sqlite3_errmsg (dbh));
      sqlite3_finalize (stmt);
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (SQLITE_DONE != sqlite3_step (stmt))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sqlite3_step", __FILE__, __LINE__,
                     sqlite3_errmsg (dbh));
      sqlite3_finalize (stmt);
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  ret = sqlite3_changes (dbh);
  sqlite3_finalize (stmt);
  if (ret > 0)
    {
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  if (bloom != NULL)
    GNUNET_bloomfilter_add (bloom, key);

  if (GNUNET_OK != checkQuota (dbh))
    {
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (sq_prepare (dbh,
                  "INSERT INTO ds071 "
                  "(size, type, puttime, expire, key, value) "
                  "VALUES (?, ?, ?, ?, ?, ?)", &stmt) != SQLITE_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (dbh));
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if ((SQLITE_OK == sqlite3_bind_int (stmt, 1, size)) &&
      (SQLITE_OK == sqlite3_bind_int (stmt, 2, type)) &&
      (SQLITE_OK == sqlite3_bind_int64 (stmt, 3, GNUNET_get_time ())) &&
      (SQLITE_OK == sqlite3_bind_int64 (stmt, 4, discard_time)) &&
      (SQLITE_OK ==
       sqlite3_bind_blob (stmt, 5, key, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT))
      && (SQLITE_OK ==
          sqlite3_bind_blob (stmt, 6, data, size, SQLITE_TRANSIENT)))
    {
      if (SQLITE_DONE != sqlite3_step (stmt))
        LOG_SQLITE (dbh,
                    GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER | GNUNET_GE_ADMIN |
                    GNUNET_GE_BULK, "sqlite3_step");
      else
        payload += size + OVERHEAD;
      if (SQLITE_OK != sqlite3_finalize (stmt))
        LOG_SQLITE (dbh,
                    GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER | GNUNET_GE_ADMIN |
                    GNUNET_GE_BULK, "sqlite3_finalize");
    }
  else
    {
      LOG_SQLITE (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER | GNUNET_GE_ADMIN |
                  GNUNET_GE_BULK, "sqlite3_bind_xxx");
    }
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Storing %u bytes increases DStore payload to %llu out of %llu\n",
                 size, payload, quota);
#endif
  checkQuota (dbh);
  sqlite3_close (dbh);
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->set (stat_dstore_size, payload);
  return GNUNET_OK;
}

/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
d_get (const GNUNET_HashCode * key,
       unsigned int type, GNUNET_ResultProcessor handler, void *closure)
{
  sqlite3 *dbh;
  sqlite3_stmt *stmt;
  GNUNET_CronTime now;
  unsigned int size;
  const char *dat;
  unsigned int cnt;

  GNUNET_mutex_lock (lock);
  if ((bloom != NULL) && (GNUNET_NO == GNUNET_bloomfilter_test (bloom, key)))
    {
      GNUNET_mutex_unlock (lock);
      return 0;
    }
  if ((fn == NULL) || (SQLITE_OK != sqlite3_open (fn, &dbh)))
    {
      db_reset (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "dstore processes get\n");
#endif
  now = GNUNET_get_time ();
  if (sq_prepare (dbh,
                  "SELECT size, value FROM ds071 WHERE key=? AND type=? AND expire >= ?",
                  &stmt) != SQLITE_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (dbh));
      sqlite3_close (dbh);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  sqlite3_bind_blob (stmt, 1, key, sizeof (GNUNET_HashCode),
                     SQLITE_TRANSIENT);
  sqlite3_bind_int (stmt, 2, type);
  sqlite3_bind_int (stmt, 3, now);
  cnt = 0;
  while (sqlite3_step (stmt) == SQLITE_ROW)
    {
      size = sqlite3_column_int (stmt, 0);
      if (size != sqlite3_column_bytes (stmt, 1))
        {
          GNUNET_GE_BREAK (NULL, 0);
          continue;
        }
      dat = sqlite3_column_blob (stmt, 1);
      handler (key, type, size, dat, closure);
      cnt++;
    }
  sqlite3_finalize (stmt);
  sqlite3_close (dbh);
  GNUNET_mutex_unlock (lock);
  return cnt;
}

GNUNET_Dstore_ServiceAPI *
provide_module_dstore_sqlite (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Dstore_ServiceAPI api;
  int fd;

#if DEBUG_SQLITE
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite Dstore: initializing database\n");
#endif
  if (GNUNET_OK != db_reset ())
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);


  coreAPI = capi;
  api.get = &d_get;
  api.put = &d_put;
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DSTORE", "QUOTA", 1, 1024, 1,
                                            &quota);
  if (quota == 0)               /* error */
    quota = 1;
  quota *= 1024 * 1024;

  bloom_name = GNUNET_strdup ("/tmp/dbloomXXXXXX");
  fd = mkstemp (bloom_name);
  if (fd != -1)
    {
      bloom = GNUNET_bloomfilter_load (coreAPI->ectx, bloom_name, quota / (OVERHEAD + 1024),    /* 8 bit per entry in DB, expect 1k entries */
                                       5);
      CLOSE (fd);
    }
  stats = capi->request_service ("stats");
  if (stats != NULL)
    stat_dstore_size = stats->create (gettext_noop ("# bytes in dstore"));
  return &api;
}

/**
 * Shutdown the module.
 */
void
release_module_dstore_sqlite ()
{
  UNLINK (fn);
  GNUNET_free (fn);
  fn = NULL;
  if (bloom != NULL)
    {
      GNUNET_bloomfilter_free (bloom);
      bloom = NULL;
    }
  UNLINK (bloom_name);
  GNUNET_free (bloom_name);
  bloom_name = NULL;
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
#if DEBUG_SQLITE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite Dstore: database shutdown\n");
#endif
  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of dstore.c */