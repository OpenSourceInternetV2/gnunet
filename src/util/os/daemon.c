/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file src/util/os/daemon.c
 * @brief code for client-gnunetd interaction (start, stop, waitpid)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_string.h"

#if LINUX || OSX || SOLARIS || SOMEBSD || MINGW
/**
 * Fork a gnunetd process
 *
 * @param daemonize GNUNET_YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
static pid_t
launchWithExec (struct GNUNET_GE_Context *ectx, const char *cfgFile,
                int daemonize)
{
  pid_t pid;

#ifndef MINGW
  pid = fork ();
  if (pid == 0)
#endif
    {
      const char *args[6];
      char *path;
      char *cp;
      int i;

      path = NULL;
      cp = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);
      i = strlen (cp);
      path = GNUNET_malloc (i + 2 + strlen ("gnunetd.exe"));
      strcpy (path, cp);
      strcat (path, "gnunetd");
#ifdef MINGW
      strcat (path, ".exe");
#endif
      if (ACCESS (path, X_OK) == 0)
        {
          args[0] = path;
        }
      else
        {
          GNUNET_free (path);
          path = NULL;
          args[0] = "gnunetd";
        }
      GNUNET_free (cp);
      if (cfgFile != NULL)
        {
          args[1] = "-c";
          args[2] = cfgFile;
          if (GNUNET_NO == daemonize)
            {
              args[3] = "-d";
              args[4] = NULL;
            }
          else
            args[3] = NULL;
        }
      else
        {
          if (GNUNET_NO == daemonize)
            {
              args[1] = "-d";
              args[2] = NULL;
            }
          else
            args[1] = NULL;
        }
      errno = 0;
#ifndef MINGW
      nice (10);                /* return value is not well-defined */
      if (errno != 0)
        GNUNET_GE_LOG_STRERROR (ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_USER |
                                GNUNET_GE_BULK, "nice");

      if (path != NULL)
        i = execv (path, (char **) args);
      else
        i = execvp ("gnunetd", (char **) args);
#else
      if (path != NULL)
        pid = i = spawnv (_P_NOWAIT, path, (const char *const *) args);
      else
        pid = i = spawnvp (_P_NOWAIT, "gnunetd", (const char *const *) args);
#endif
      if (i == -1)
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_USER |
                                     GNUNET_GE_BULK, "exec",
                                     path == NULL ? "gnunetd" : path);
      GNUNET_free_non_null (path);
#ifndef MINGW
      _exit (-1);
#endif
    }
#ifndef MINGW
  else if (daemonize)
    {
      pid_t ret;
      int status;

      do
        {
          ret = waitpid (pid, &status, 0);
        }
      while ((errno == EINTR) && (GNUNET_shutdown_test () == GNUNET_NO));
      if (ret == -1)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_USER |
                                  GNUNET_GE_BULK, "waitpid");
          return GNUNET_SYSERR;
        }
      if ((WIFEXITED (status) && (0 != WEXITSTATUS (status))))
        {
          return GNUNET_SYSERR;
        }
#ifdef WCOREDUMP
      if (WCOREDUMP (status))
        {
          return GNUNET_SYSERR;
        }
#endif
      if (WIFSIGNALED (status) || WTERMSIG (status))
        {
          return GNUNET_SYSERR;
        }
      return 0;
    }
#endif /* MINGW */
  return pid;
}
#endif

/**
 * Start gnunetd process
 *
 * @param daemonize GNUNET_YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
int
GNUNET_daemon_start (struct GNUNET_GE_Context *ectx,
                     struct GNUNET_GC_Configuration *cfg,
                     const char *cfgFile, int daemonize)
{
#if LINUX || OSX || SOLARIS || SOMEBSD || MINGW
  return launchWithExec (ectx, cfgFile, daemonize);
#else
  /* any system out there that does not support THIS!? */
  if (-1 == system ("gnunetd")) /* we may not have nice,
                                   so let's be minimalistic here. */
    return -1;
  return 0;
#endif
}

static int
termProcess (int pid)
{
#ifndef MINGW
  return kill (pid, SIGTERM) == 0;
#else
  int ret;
  DWORD dwExitCode = 0;

  HANDLE hProc = OpenProcess (1, 0, pid);
  GenerateConsoleCtrlEvent (CTRL_C_EVENT, pid);

  WaitForSingleObject (hProc, 3000);

  GetExitCodeProcess (hProc, &dwExitCode);
  if (dwExitCode == STILL_ACTIVE)
    {
      ret = TerminateProcess (hProc, 0);
    }
  else
    ret = 1;

  CloseHandle (hProc);

  return ret;
#endif
}



/**
 * Wait until the gnunet daemon (or any other CHILD process for that
 * matter) with the given PID has terminated.  Assumes that
 * the daemon was started with startGNUnetDaemon in no-daemonize mode.
 * On arbitrary PIDs, this function may fail unexpectedly.
 *
 * @return GNUNET_YES if gnunetd shutdown with
 *  return value 0, GNUNET_SYSERR if waitpid
 *  failed, GNUNET_NO if gnunetd shutdown with
 *  some error
 */
int
GNUNET_daemon_stop (struct GNUNET_GE_Context *ectx, int pid)
{
  pid_t p;
  int status;

  termProcess (pid);
  p = pid;
  if (p != WAITPID (p, &status, 0))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_USER |
                              GNUNET_GE_BULK, "waitpid");
      return GNUNET_SYSERR;
    }
  if (WEXITSTATUS (status) == 0)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}

/* end of daemon.c */
