/*
     This file is part of GNUnet.
     (C) 2001 - 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/win/bdb_dll_wrapper.c
 * @brief Wrapper for the Berkeley DB DLL
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include <db.h>

static HINSTANCE hBDB = 0;
static int counter = 0;

typedef int WINAPI (*Tdb_env_create) (DB_ENV **, u_int32_t);
typedef char *WINAPI (*Tdb_strerror) (int);
typedef int WINAPI (*Tdb_create) (DB **, DB_ENV *, u_int32_t);

Tdb_env_create GNdb_env_create;
Tdb_strerror GNdb_strerror;
Tdb_create GNdb_create;

/**
 * Load the shared BDB lib dynamically
 * @return 1 on success, 0 on error
 */
int LoadBDB()
{
  if (! hBDB)
  {
    hBDB = LoadLibraryA("libdb.dll");
    if (! hBDB)    
      return 0;

    GNdb_env_create = (Tdb_env_create)
        GetProcAddress(hBDB, "db_env_create");
    GNdb_strerror = (Tdb_strerror)
        GetProcAddress(hBDB, "db_strerror");
    GNdb_create = (Tdb_create)
        GetProcAddress(hBDB, "db_create");
  }
  
  counter++;
 
  return 1; 
}

/**
 * Release the shared BDB lib
 */
void UnloadBDB()
{
  counter--;
  
  if (hBDB && counter <= 0)
  {
    FreeLibrary(hBDB);
    hBDB = 0;
  }
}

int db_env_create(DB_ENV **dbenvpp, u_int32_t flags)
{
  if (!hBDB)
    return ELIBACC;
    
  return GNdb_env_create(dbenvpp, flags);
}

char *db_strerror(int error)
{
  if (!hBDB)
    return STRERROR(error);

  return GNdb_strerror(error);    
}

int db_create(DB **dbpp, DB_ENV *dbenv, u_int32_t flags)
{
  if (!hBDB)
    return ELIBACC;

  return GNdb_create(dbpp, dbenv, flags);
}
