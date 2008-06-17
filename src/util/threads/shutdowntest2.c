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
 * @file util/threads/shutdowntest2.c
 * @brief testcase for util/threads/shutdown.c
 */

#include "gnunet_util.h"
#include "platform.h"

static int
check ()
{
  if (GNUNET_SHUTDOWN_TEST () != NO)
    return 1;
#ifndef MINGW
  kill (getpid (), SIGINT);
#else
  GenerateConsoleCtrlEvent (CTRL_C_EVENT, 0);
#endif
  if (GNUNET_SHUTDOWN_TEST () != YES)
    return 2;
  GNUNET_SHUTDOWN_WAITFOR ();
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of shutdowntest2.c */
