/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @brief GNUnet Setup in Cocoa
 * @file setup/cocoa/config_cocoa.c
 * @author Heikki Lindholm
 */

#ifndef GNUNET_SETUP_COCOA_H
#define GNUNET_SETUP_COCOA_H

int config_cocoa_mainsetup_cocoa (int argc, const char **argv,
                                  struct GNUNET_PluginHandle *selfHandle,
                                  struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg,
                                  struct GNUNET_GNS_Context *gns,
                                  const char *filename, int is_daemon);

#endif
