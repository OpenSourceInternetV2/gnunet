/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file setup/lib/wizard_util.h
 * @brief Common helper functions
 * @author Nils Durner
 */

#ifndef WIZARD_UTIL_H_
#define WIZARD_UTIL_H_

#define GNUNET_SERVICE_TYPE_GNUNETD 1
#define GNUNET_SERVICE_TYPE_AUTOSHARE 2

int GNUNET_GNS_wiz_is_nic_default (struct GNUNET_GC_Configuration *cfg,
                                   const char *name, int suggestion);
int GNUNET_GNS_wiz_autostart_service (struct GNUNET_GE_Context *ectx,
                                      int serviceType, int doAutoStart,
                                      char *username, char *groupname);
int GNUNET_GNS_wiz_create_group_user (char *group_name, char *user_name);


#endif /*WIZARD_UTIL_H_ */
