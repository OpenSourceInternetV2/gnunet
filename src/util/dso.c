/*
     This file is part of GNUnet

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
 * @file util/dso.c
 * @brief Methods to access dynamic shared objects (DSOs).
 * @author Christian Grothoff
 **/

#include "gnunet_util.h"
#include "platform.h"

static char * buildLibName(char * prefix,
			   char * dso) {
  char * libname;

  libname = MALLOC(strlen(dso) +
		   strlen(prefix) + 1);
  libname[0] = '\0';
  strcat(libname, prefix);
  strcat(libname, dso);
  return libname;
}

void * loadDynamicLibrary(char * libprefix,
			  char * dsoname) {
  void * libhandle;
  char * libname;
  static int once = 0;

  if (0 != lt_dlinit()) 
    errexit("Could not initialize ltdl (%s)\n",
	    lt_dlerror());  

  /* add default search paths */
  if (once == 0) {
    char * env;

    once = 1;
    
    if (lt_dlgetsearchpath() == NULL)
      lt_dladdsearchdir("/usr/lib");
    else
      if ( strstr(lt_dlgetsearchpath(), "/usr/lib") == NULL ) 
	lt_dladdsearchdir("/usr/lib");
    if ( strstr(lt_dlgetsearchpath(), "/usr/local/lib") == NULL ) 
      lt_dladdsearchdir("/usr/local/lib");   
#ifdef LTDL_SYSSEARCHPATH
    if ( strstr(lt_dlgetsearchpath(), LTDL_SYSSEARCHPATH) == NULL)
      lt_dladdsearchdir(LTDL_SYSSEARCHPATH);
#endif 
#ifdef ELIBDIR
    if ( strstr(lt_dlgetsearchpath(), ELIBDIR) == NULL)
      lt_dladdsearchdir(ELIBDIR);
#endif
#ifdef PLUGIN_PATH
    if ( strstr(lt_dlgetsearchpath(), PLUGIN_PATH) == NULL)
      lt_dladdsearchdir(PLUGIN_PATH);
#endif
#ifdef LTDL_SHLIBPATH_VAR
    env = getenv(LTDL_SHLIBPATH_VAR);
    if (env != NULL)
      if ( strstr(lt_dlgetsearchpath(), env) == NULL)
	lt_dladdsearchdir(env);
#endif
  }

  /* finally, load the library */
  libname = buildLibName(libprefix,
			 dsoname);
  libhandle = lt_dlopenext(libname); 
  if (libhandle == NULL) {
    LOG(LOG_ERROR,
	"ERROR: Could not open library %s (%s)!\n",
	libname,
	lt_dlerror());
  }
  FREE(libname);
  return libhandle;
}

void unloadDynamicLibrary(void * libhandle) {  
  lt_dlclose(libhandle);
  if (0 != lt_dlexit())
    LOG(LOG_WARNING,
	"WARNING: lt_dlexit failed (%s)\n",
	lt_dlerror());
}

void * bindDynamicMethod(void * libhandle,
			 char * methodprefix,
			 char * dsoname) {
  char * initName;
  void * mptr;

  initName = MALLOC(strlen(dsoname) +
		    strlen(methodprefix) + 2);
  initName[0] = '\0';
  strcat(initName, methodprefix);
  strcat(initName, dsoname);
  mptr = lt_dlsym(libhandle, initName);
  if (mptr == NULL) {
    /* try again with "_" prefix; some systems use that
       variant. */
    initName[0] = '\0';
    strcat(initName, "_");
    strcat(initName, methodprefix);
    strcat(initName, dsoname);
    mptr = lt_dlsym(libhandle, initName);
    if (mptr == NULL)
      LOG(LOG_ERROR,
	  "ERROR: Could not resolve method %s (%s)!\n",
	  initName,
	  lt_dlerror());
  }
  FREE(initName);
  return mptr;
}

/* end of dso.c */			
