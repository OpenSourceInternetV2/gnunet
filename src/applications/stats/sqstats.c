/*
     This file is part of GNUnet
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file sqstats.c
 * @brief get statistics from sqstore datastore
 * @author Christian Grothoff
 */

#include "gnunet_sqstore_service.h"
#include "gnunet_protocols.h"

static SQstore_ServiceAPI *sq;

/* block types */
static int stat_block[8];
/* expiration */
static int stat_expire[5];
/* priorities */
static int stat_prio[6];
/* anonymity */
static int stat_anon[3];

struct CD
{
  /* block types */
  unsigned long long stat_block[8];
  /* expiration */
  unsigned long long stat_expire[5];
  /* priorities */
  unsigned long long stat_prio[6];
  /* anonymity */
  unsigned long long stat_anon[3];
};

static int
iter (const HashCode512 * key, const Datastore_Value * value, void *cls)
{
  struct CD *data = cls;
  cron_t expire;
  cron_t now;

  switch (ntohl (value->type))
    {
    case ANY_BLOCK:
      data->stat_block[0]++;
      break;
    case D_BLOCK:
      data->stat_block[1]++;
      break;
    case S_BLOCK:
      data->stat_block[2]++;
      break;
    case K_BLOCK:
      data->stat_block[3]++;
      break;
    case N_BLOCK:
      data->stat_block[4]++;
      break;
    case KN_BLOCK:
      data->stat_block[5]++;
      break;
    case ONDEMAND_BLOCK:
      data->stat_block[6]++;
      break;
    default:
      data->stat_block[7]++;
      break;
    }
  switch (ntohl (value->anonymityLevel))
    {
    case 0:
      data->stat_anon[0]++;
      break;
    case 1:
      data->stat_anon[1]++;
      break;
    default:
      data->stat_anon[2]++;
      break;
    }
  switch (ntohl (value->prio))
    {
    case 0:
      data->stat_prio[0]++;
      break;
    case 1:
      data->stat_prio[1]++;
      break;
    default:
      data->stat_prio[2]++;
      break;
    }
  expire = ntohll (value->expirationTime);
  now = get_time ();
  if (expire <= now)
    data->stat_expire[0]++;
  else if (expire <= now + 1 * cronHOURS)
    data->stat_expire[1]++;
  else if (expire <= now + 1 * cronDAYS)
    data->stat_expire[2]++;
  else if (expire <= now + 1 * cronWEEKS)
    data->stat_expire[3]++;
  else if (expire <= now + 1 * cronMONTHS)
    data->stat_expire[4]++;
  return OK;
}

static void
update_sqstore_stats ()
{
  struct CD data;
  int i;

  memset (&data, 0, sizeof (struct CD));
  sq->iterateAllNow (&iter, &data);
  for (i = 0; i < 8; i++)
    stats->set (stat_block[i], data.stat_block[i]);
  for (i = 0; i < 5; i++)
    stats->set (stat_expire[i], data.stat_expire[i]);
  for (i = 0; i < 6; i++)
    stats->set (stat_prio[i], data.stat_prio[i]);
  for (i = 0; i < 3; i++)
    stats->set (stat_anon[i], data.stat_anon[i]);
}

static int
init_sqstore_stats ()
{
  sq = myCoreAPI->requestService ("sqstore");
  if (sq == NULL)
    return SYSERR;
  stat_block[0] = stats->create (gettext_noop ("# Any-Blocks"));
  stat_block[1] = stats->create (gettext_noop ("# DBlocks"));
  stat_block[2] = stats->create (gettext_noop ("# SBlocks"));
  stat_block[3] = stats->create (gettext_noop ("# KBlocks"));
  stat_block[4] = stats->create (gettext_noop ("# NBlocks"));
  stat_block[5] = stats->create (gettext_noop ("# KNBlocks"));
  stat_block[6] = stats->create (gettext_noop ("# OnDemand-Blocks"));
  stat_block[7] = stats->create (gettext_noop ("# Unknown-Blocks"));
  stat_expire[0] = stats->create (gettext_noop ("# expired"));
  stat_expire[1] = stats->create (gettext_noop ("# expire in 1h"));
  stat_expire[2] = stats->create (gettext_noop ("# expire in 24h"));
  stat_expire[3] = stats->create (gettext_noop ("# expire in 1 week"));
  stat_expire[4] = stats->create (gettext_noop ("# expire in 1 month"));
  stat_prio[0] = stats->create (gettext_noop ("# zero priority"));
  stat_prio[1] = stats->create (gettext_noop ("# priority one"));
  stat_prio[2] = stats->create (gettext_noop ("# priority larger than one"));
  stat_anon[3] = stats->create (gettext_noop ("# no anonymity"));
  stat_anon[1] = stats->create (gettext_noop ("# anonymity one"));
  stat_anon[2] = stats->create (gettext_noop ("# anonymity larger than one"));
  return OK;
}

static void
done_sqstore_stats ()
{
  if (sq == NULL)
    return;
  myCoreAPI->releaseService (sq);
  sq = NULL;
}
