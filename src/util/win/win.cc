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
 * @file util/win.cc
 * @brief Helper functions for MS Windows in C++
 * @author Nils Durner
 **/

#ifndef _WIN_CC
#define _WIN_CC

#include "winproc.h"

extern "C" {

BOOL CreateShortcut(const char *pszSrc, const char *pszDest)
{
  /* CreateHardLink requires XP or 2000 */
  if (!(GNCreateHardLink && GNCreateHardLink(pszDest, pszSrc, NULL)))
  {
    /* Create shortcut */
    IShellLink *pLink;
    IPersistFile *pFile;
    WCHAR *pwszDest;
    char *pszFileLnk;
    
    if ((strlen(pszSrc) > _MAX_PATH) || (strlen(pszDest) + 4 > _MAX_PATH))
      return FALSE;
    
    /* Create Shortcut-Object */
    if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
        IID_IShellLink, (void **) &pLink) != S_OK)
      return FALSE;
  
    /* Set target path */
    pLink->SetPath(pszSrc);
  
    /* Get File-Object */
    if (pLink->QueryInterface(IID_IPersistFile, (void **) &pFile) != S_OK)
    {
      free(pwszDest);
      pLink->Release();
      
      return FALSE;
    }

    /* shortcuts have the extension .lnk */
    pszFileLnk = (char *) malloc(strlen(pszDest) + 5);
    sprintf(pszFileLnk, "%s.lnk", pszDest);
  
    /* Turn filename into widechars */
    pwszDest = (WCHAR *) malloc((_MAX_PATH + 5) * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, pszFileLnk, -1, pwszDest, _MAX_PATH);
    
    free(pszFileLnk);
    
    /* Save shortcut */
    if (pFile->Save((LPCOLESTR) pwszDest, TRUE) != S_OK)
    {
      free(pwszDest);
      pLink->Release();
      pFile->Release();
  
      return FALSE;
    }
  
    free(pwszDest);
    
    pFile->Release();
    pLink->Release();
      
    return TRUE;
  }
  else
    return TRUE;
}

BOOL DereferenceShortcut(char *pszShortcut)
{
  IShellLink *pLink;
  IPersistFile *pFile;
  WCHAR *pwszShortcut;
  char *pszLnk;
  int iErr, iLen;
  
  /* Create Shortcut-Object */
  if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
      IID_IShellLink, (void **) &pLink) != S_OK)
    return FALSE;

  /* Get File-Object */
  if (pLink->QueryInterface(IID_IPersistFile, (void **) &pFile) != S_OK)
  {
    pLink->Release();
    
    return FALSE;
  }

  pwszShortcut = (WCHAR *) malloc((_MAX_PATH + 1) * sizeof(WCHAR));

  /* Shortcuts have the extension .lnk
     If it isn't there, append it */
  iLen = strlen(pszShortcut);
  if (iLen > 4 && (strcmp(pszShortcut + iLen - 4, ".lnk") != 0))
  {
    pszLnk = (char *) malloc(iLen + 5);
    sprintf(pszLnk, "%s.lnk", pszShortcut);
  }
  else
    pszLnk = strdup(pszShortcut);

  MultiByteToWideChar(CP_ACP, 0, pszLnk, -1, pwszShortcut, _MAX_PATH);
  
  free(pszLnk);
  
  /* Open shortcut */
  if (pFile->Load((LPCOLESTR) pwszShortcut, STGM_READ) != S_OK)
  {
    pLink->Release();
    pFile->Release();
    free(pwszShortcut);
    
    return FALSE;
  }
  
  free(pwszShortcut);
  
  /* Get target file */
  if (pLink->GetPath(pszShortcut, _MAX_PATH, NULL, 0) != S_OK)
  {
    pLink->Release();
    pFile->Release();

    return FALSE;
  }

  pFile->Release();
  pLink->Release();
 
  return TRUE;
}

}

#endif
