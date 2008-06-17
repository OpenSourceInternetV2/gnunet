/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
/*
 * @file applications/sqstore_sqlite/sqlitetest.c
 * @brief Test for the sqstore implementations.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static cron_t now;

static Datastore_Value *
initValue (int i)
{
  Datastore_Value *value;

  value = MALLOC (sizeof (Datastore_Value) + 8 * i);
  value->size = htonl (sizeof (Datastore_Value) + 8 * i);
  value->type = htonl (i);
  value->prio = htonl (i + 1);
  value->anonymityLevel = htonl (i);
  value->expirationTime = htonll (now - i * cronSECONDS);
  memset (&value[1], i, 8 * i);
  return value;
}

static int
checkValue (const HashCode512 * key,
            const Datastore_Value * val, void *closure,
            unsigned long long uid)
{
  int i;
  int ret;
  Datastore_Value *value;

  i = *(int *) closure;
  value = initValue (i);
  if ((value->size == val->size) &&
      (0 == memcmp (val, value, ntohl (val->size))))
    ret = OK;
  else
    {
      /*
         printf("Wanted: %u, %llu; got %u, %llu - %d\n",
         ntohl(value->size), ntohll(value->expirationTime),
         ntohl(val->size), ntohll(val->expirationTime),
         memcmp(val, value, ntohl(val->size))); */
      ret = SYSERR;
    }
  FREE (value);
  return ret;
}

static int
iterateUp (const HashCode512 * key, const Datastore_Value * val, int *closure,
           unsigned long long uid)
{
  int ret;

  ret = checkValue (key, val, closure, uid);
  (*closure) += 2;
  return ret;
}

static int
iterateDown (const HashCode512 * key,
             const Datastore_Value * val, int *closure,
             unsigned long long uid)
{
  int ret;

  (*closure) -= 2;
  ret = checkValue (key, val, closure, uid);
  return ret;
}

static int
iterateDelete (const HashCode512 * key,
               const Datastore_Value * val, void *closure,
               unsigned long long uid)
{
  return NO;
}

static int
iteratePriority (const HashCode512 * key,
                 const Datastore_Value * val, SQstore_ServiceAPI * api,
                 unsigned long long uid)
{
  api->update (uid, 4, 0);
  return OK;
}

static int
priorityCheck (const HashCode512 * key,
               const Datastore_Value * val, int *closure,
               unsigned long long uid)
{
  int id;

  id = (*closure);
  if (id + 1 == ntohl (val->prio))
    return OK;
  else
    return SYSERR;
}

static int
multipleCheck (const HashCode512 * key,
               const Datastore_Value * val, Datastore_Value ** last,
               unsigned long long uid)
{
  if (*last != NULL)
    {
      if (((*last)->size == val->size) &&
          (0 == memcmp (*last, val, ntohl (val->size))))
        return SYSERR;          /* duplicate! */
      FREE (*last);
    }
  *last = MALLOC (ntohl (val->size));
  memcpy (*last, val, ntohl (val->size));
  return OK;
}


/**
 * Add testcode here!
 */
static int
test (SQstore_ServiceAPI * api)
{
  Datastore_Value *value;
  HashCode512 key;
  unsigned long long oldSize;
  int i;

  now = 1000000;
  oldSize = api->getSize ();
  for (i = 0; i < 256; i++)
    {
      value = initValue (i);
      memset (&key, 256 - i, sizeof (HashCode512));
      ASSERT (OK == api->put (&key, value));
      FREE (value);
    }
  ASSERT (oldSize < api->getSize ());
  ASSERT (256 == api->iterateLowPriority (ANY_BLOCK, NULL, NULL));
  ASSERT (256 == api->iterateExpirationTime (ANY_BLOCK, NULL, NULL));
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (HashCode512));
      ASSERT (1 == api->get (&key, i, &checkValue, (void *) &i));
    }

  oldSize = api->getSize ();
  for (i = 255; i >= 0; i -= 2)
    {
      memset (&key, 256 - i, sizeof (HashCode512));
      value = initValue (i);
      ASSERT (1 == api->get (&key, 0, &iterateDelete, NULL));
      FREE (value);
    }
  ASSERT (oldSize > api->getSize ());
  i = 0;
  ASSERT (128 == api->iterateLowPriority (ANY_BLOCK,
                                          (Datum_Iterator) & iterateUp, &i));
  ASSERT (256 == i);
  ASSERT (128 == api->iterateExpirationTime (ANY_BLOCK,
                                             (Datum_Iterator) & iterateDown,
                                             &i));
  ASSERT (0 == i);
  ASSERT (128 == api->iterateExpirationTime (ANY_BLOCK,
                                             (Datum_Iterator) & iterateDelete,
                                             api));
  ASSERT (0 == api->iterateExpirationTime (ANY_BLOCK,
                                           (Datum_Iterator) & iterateDown,
                                           &i));

  i = 42;
  value = initValue (i);
  memset (&key, 256 - i, sizeof (HashCode512));
  api->put (&key, value);
  ASSERT (1 == api->iterateExpirationTime (ANY_BLOCK,
                                           (Datum_Iterator) & priorityCheck,
                                           &i));
  ASSERT (1 == api->iterateAllNow ((Datum_Iterator) & iteratePriority, api));
  i += 4;
  ASSERT (1 == api->iterateExpirationTime (ANY_BLOCK,
                                           (Datum_Iterator) & priorityCheck,
                                           &i));
  FREE (value);

  /* test multiple results */
  value = initValue (i + 1);
  api->put (&key, value);
  FREE (value);

  value = NULL;
  ASSERT (2 == api->iterateExpirationTime (ANY_BLOCK,
                                           (Datum_Iterator) & multipleCheck,
                                           &value));
  FREE (value);
  ASSERT (2 == api->iterateAllNow ((Datum_Iterator) & iterateDelete, api));
  ASSERT (0 == api->iterateExpirationTime (ANY_BLOCK, NULL, NULL));
  api->drop ();

  return OK;

FAILURE:
  api->drop ();
  return SYSERR;
}

int
main (int argc, char *argv[])
{
  SQstore_ServiceAPI *api;
  int ok;
  struct GC_Configuration *cfg;
  struct CronManager *cron;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  cron = cron_create (NULL);
  initCore (NULL, cfg, cron, NULL);
  api = requestService ("sqstore");
  if (api != NULL)
    {
      ok = test (api);
      releaseService (api);
    }
  else
    ok = SYSERR;
  doneCore ();
  cron_destroy (cron);
  GC_free (cfg);
  if (ok == SYSERR)
    return 1;
  return 0;
}

/* end of sqlitetest.c */
