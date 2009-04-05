/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/config/configtest.c
 * @brief Test that the configuration module works.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"
#include "gnunet_util_config.h"
#include "gnunet_util_error_loggers.h"

static struct GNUNET_GC_Configuration *cfg;

static int
testConfig ()
{
  char *c;
  unsigned long long l;

  if (0 !=
      GNUNET_GC_get_configuration_value_string (cfg, "test", "b", NULL, &c))
    return 1;
  if (0 != strcmp ("b", c))
    {
      GNUNET_free (c);
      return 2;
    }
  GNUNET_free (c);
  if (0 != GNUNET_GC_get_configuration_value_number (cfg,
                                                     "test", "five", 0, 10, 9,
                                                     &l))
    return 3;
  if (5 != l)
    return 4;
  GNUNET_GC_set_configuration_value_string (cfg, NULL, "more", "c", "YES");
  if (GNUNET_NO ==
      GNUNET_GC_get_configuration_value_yesno (cfg, "more", "c", GNUNET_NO))
    return 5;
  return 0;
}

static const char *want[] = {
  "/Hello",
  "/File Name",
  "/World",
  NULL,
  NULL,
};

static int
check (void *data, const char *fn)
{
  int *idx = data;

  if (0 == strcmp (want[*idx], fn))
    {
      (*idx)++;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

static int
testConfigFilenames ()
{
  int idx;

  idx = 0;
  if (3 != GNUNET_GC_iterate_configuration_value_filenames (cfg,
                                                            "FILENAMES",
                                                            "test",
                                                            &check, &idx))
    return 8;
  if (idx != 3)
    return 16;
  if (GNUNET_OK !=
      GNUNET_GC_remove_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/File Name"))
    return 24;

  if (GNUNET_NO !=
      GNUNET_GC_remove_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/File Name"))
    return 32;
  if (GNUNET_NO !=
      GNUNET_GC_remove_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "Stuff"))
    return 40;

  if (GNUNET_NO !=
      GNUNET_GC_append_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/Hello"))
    return 48;
  if (GNUNET_NO !=
      GNUNET_GC_append_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/World"))
    return 56;

  if (GNUNET_YES !=
      GNUNET_GC_append_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/File 1"))
    return 64;

  if (GNUNET_YES !=
      GNUNET_GC_append_configuration_value_filename (cfg,
                                                     NULL,
                                                     "FILENAMES",
                                                     "test", "/File 2"))
    return 72;

  idx = 0;
  want[1] = "/World";
  want[2] = "/File 1";
  want[3] = "/File 2";
  if (4 != GNUNET_GC_iterate_configuration_value_filenames (cfg,
                                                            "FILENAMES",
                                                            "test",
                                                            &check, &idx))
    return 80;
  if (idx != 4)
    return 88;
  return 0;
}

int
main (int argc, char *argv[])
{
  struct GNUNET_GE_Context *ectx;
  int failureCount = 0;

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                          | GNUNET_GE_FATAL | GNUNET_GE_USER |
                                          GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (ectx);
  cfg = GNUNET_GC_create ();
  if (0 != GNUNET_GC_parse_configuration (cfg, "testconfig.conf"))
    {
      fprintf (stderr, "Failed to parse configuration file\n");
      return 1;
    }
  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  GNUNET_os_init (ectx);
  failureCount += testConfig ();
  failureCount += testConfigFilenames ();

  if (failureCount != 0)
    {
      fprintf (stderr, "Test failed: %u\n", failureCount);
      return 1;
    }
  return 0;
}
