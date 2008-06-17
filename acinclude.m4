# See: http://gcc.gnu.org/ml/gcc/2000-05/msg01141.html
AC_DEFUN([CHECK_PTHREAD],
[
	AC_CHECK_LIB(pthread,pthread_create,
	[
		PTHREAD_CPPFLAGS=
		PTHREAD_LDFLAGS=
		PTHREAD_LIBS=-lpthread
	],[
		AC_MSG_CHECKING(if compiler supports -pthread)
		save_CPPFLAGS="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS -pthread"
		AC_TRY_LINK(
		[
			#include <pthread.h>
		],[
			pthread_create(0,0,0,0);
		],[
			AC_MSG_RESULT(yes)
			PTHREAD_CPPFLAGS=-pthread
			PTHREAD_LDFLAGS=-pthread
			PTHREAD_LIBS=
		],[
			AC_MSG_RESULT(no)
			AC_MSG_CHECKING(if compiler supports -pthreads)
			save_CPPFLAGS="$CPPFLAGS"
			CPPFLAGS="$save_CPPFLAGS -pthreads"
			AC_TRY_LINK(
			[
				#include <pthread.h>
			],[
				pthread_create(0,0,0,0);
			],[
				AC_MSG_RESULT(yes)
				PTHREAD_CPPFLAGS=-pthreads
				PTHREAD_LDFLAGS=-pthreads
				PTHREAD_LIBS=
			],[
				AC_MSG_RESULT(no)
				AC_MSG_CHECKING(if compiler supports -threads)
				save_CPPFLAGS="$CPPFLAGS"
				CPPFLAGS="$save_CPPFLAGS -threads"
				AC_TRY_LINK(
				[
					#include <pthread.h>
				],[
					pthread_create(0,0,0,0);
				],[
					AC_MSG_RESULT(yes)
					PTHREAD_CPPFLAGS=-threads
					PTHREAD_LDFLAGS=-threads
					PTHREAD_LIBS=
				],[
					AC_MSG_ERROR([Your system is not supporting pthreads!])
				])
			])
		])
		CPPFLAGS="$save_CPPFLAGS"
	])
])


AC_DEFUN([AM_GNUNET_SSL_VERSION], [
  AC_PATH_PROG(SSL_CONF, openssl, no)
  if test "x$SSL_CONF" = "xno"; then
    AC_MSG_ERROR(GNUnet require a working installation of OpenSSL or gcrypt)
  else
    ssl_major_version=`$SSL_CONF version | \
         $ac_cv_prog_AWK '{print $[2]}' | \
         $ac_cv_prog_AWK -F. '{print $[1]}'`
    ssl_minor_version=`$SSL_CONF version | \
        $ac_cv_prog_AWK '{print $[2]}' | \
        $ac_cv_prog_AWK -F. '{print $[2]}'`
    ssl_micro_version=`$SSL_CONF version | \
        $ac_cv_prog_AWK '{print $[2]}' | \
        $ac_cv_prog_AWK -F. '{print $[3]}' | \
        sed 's/[[^0-9]]//g'`
    AC_DEFINE_UNQUOTED(SSL_MAJOR, $ssl_major_version, [OpenSSL Major Version])
    AC_DEFINE_UNQUOTED(SSL_MINOR, $ssl_minor_version, [OpenSSL Minor Version])
    AC_DEFINE_UNQUOTED(SSL_MICRO, $ssl_micro_version, [OpenSSL Micro Version])
  fi
])

dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN([GNUPG_CHECK_TYPEDEF],
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(gnupg_cv_typedef_$1,
    [AC_TRY_COMPILE([#define _GNU_SOURCE 1
    #include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], gnupg_cv_typedef_$1=yes, gnupg_cv_typedef_$1=no )])
    AC_MSG_RESULT($gnupg_cv_typedef_$1)
    if test "$gnupg_cv_typedef_$1" = yes; then
        AC_DEFINE($2,1,[Defined if a `]$1[' is typedef'd])
    fi
  ])

dnl GNUPG_CHECK_ENDIAN
dnl define either LITTLE_ENDIAN_HOST or BIG_ENDIAN_HOST
dnl
define(GNUPG_CHECK_ENDIAN,
  [ if test "$cross_compiling" = yes; then
        AC_MSG_WARN(cross compiling; assuming big endianess)
    fi
    AC_MSG_CHECKING(endianess)
    AC_CACHE_VAL(gnupg_cv_c_endian,
      [ gnupg_cv_c_endian=unknown
        # See if sys/param.h defines the BYTE_ORDER macro.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
         bogus endian macros
        #endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if BYTE_ORDER != BIG_ENDIAN
         not big endian
        #endif], gnupg_cv_c_endian=big, gnupg_cv_c_endian=little)])
        if test "$gnupg_cv_c_endian" = unknown; then
            AC_TRY_RUN([main () {
              /* Are we little or big endian?  From Harbison&Steele.  */
              union
              {
                long l;
                char c[sizeof (long)];
              } u;
              u.l = 1;
              exit (u.c[sizeof (long) - 1] == 1);
              }],
              gnupg_cv_c_endian=little,
              gnupg_cv_c_endian=big,
              gnupg_cv_c_endian=big
            )
        fi
      ])
    AC_MSG_RESULT([$gnupg_cv_c_endian])
    if test "$gnupg_cv_c_endian" = little; then
      AC_DEFINE(LITTLE_ENDIAN_HOST,1,
                [Defined if the host has little endian byte ordering])
    else
      AC_DEFINE(BIG_ENDIAN_HOST,1,
                [Defined if the host has big endian byte ordering])
    fi
  ])

dnl LIST_MEMER()
dnl Check wether an element ist contained in a list.  Set `found' to
dnl `1' if the element is found in the list, to `0' otherwise.
AC_DEFUN([LIST_MEMBER],
[
name=$1
list=$2
found=0
                                                                           
for n in $list; do
  if test "x$name" = "x$n"; then
    found=1
  fi
done
])





AC_DEFUN([AM_GNUNET_PATH_GLIB], [
AC_ARG_WITH(glib-prefix,[  --with-glib-prefix=PFX   Prefix where GLIB is installed (optional)],
            glib_config_prefix="$withval", glib_config_prefix="")
AC_ARG_WITH(glib-exec-prefix,[  --with-glib-exec-prefix=PFX Exec prefix where GLIB is installed (optional)],
            glib_config_exec_prefix="$withval", glib_config_exec_prefix="")
AC_ARG_ENABLE(glibtest, [  --disable-glibtest       Do not try to compile and run a test GLIB program],
		    , enable_glibtest=yes)

  if test x$glib_config_exec_prefix != x ; then
     glib_config_args="$glib_config_args --exec-prefix=$glib_config_exec_prefix"
     if test x${GLIB_CONFIG+set} != xset ; then
        GLIB_CONFIG=$glib_config_exec_prefix/bin/glib-config
     fi
  fi
  if test x$glib_config_prefix != x ; then
     glib_config_args="$glib_config_args --prefix=$glib_config_prefix"
     if test x${GLIB_CONFIG+set} != xset ; then
        GLIB_CONFIG=$glib_config_prefix/bin/glib-config
     fi
  fi

  for module in . $4
  do
      case "$module" in
         gmodule)
             glib_config_args="$glib_config_args gmodule"
         ;;
         gthread)
             glib_config_args="$glib_config_args gthread"
         ;;
      esac
  done

  AC_PATH_PROG(GLIB_CONFIG, glib-config, no)
  min_glib_version=ifelse([$1], ,0.99.7,$1)
  AC_MSG_CHECKING(for GLIB - version >= $min_glib_version)
  no_glib=""
  if test "$GLIB_CONFIG" = "no" ; then
    no_glib=yes
  else
    GLIB_CFLAGS=`$GLIB_CONFIG $glib_config_args --cflags`
    GLIB_LIBS=`$GLIB_CONFIG $glib_config_args --libs`
    glib_config_major_version=`$GLIB_CONFIG $glib_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    glib_config_minor_version=`$GLIB_CONFIG $glib_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    glib_config_micro_version=`$GLIB_CONFIG $glib_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_glibtest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GLIB_CFLAGS"
      LIBS="$GLIB_LIBS $LIBS"
      rm -f conf.glibtest
      AC_TRY_RUN([
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

int
main ()
{
  int major, minor, micro;
  char *tmp_version;

  system ("touch conf.glibtest");

  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = g_strdup("$min_glib_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_glib_version");
     exit(1);
   }

  if ((glib_major_version != $glib_config_major_version) ||
      (glib_minor_version != $glib_config_minor_version) ||
      (glib_micro_version != $glib_config_micro_version))
    {
      printf("\n*** 'glib-config --version' returned %d.%d.%d, but GLIB (%d.%d.%d)\n",
             $glib_config_major_version, $glib_config_minor_version, $glib_config_micro_version,
             glib_major_version, glib_minor_version, glib_micro_version);
      printf ("*** was found! If glib-config was correct, then it is best\n");
      printf ("*** to remove the old version of GLIB. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If glib-config was wrong, set the environment variable GLIB_CONFIG\n");
      printf("*** to point to the correct copy of glib-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
  else if ((glib_major_version != GLIB_MAJOR_VERSION) ||
	   (glib_minor_version != GLIB_MINOR_VERSION) ||
           (glib_micro_version != GLIB_MICRO_VERSION))
    {
      printf("*** GLIB header files (version %d.%d.%d) do not match\n",
	     GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION);
      printf("*** library (version %d.%d.%d)\n",
	     glib_major_version, glib_minor_version, glib_micro_version);
    }
  else
    {
      if ((glib_major_version > major) ||
        ((glib_major_version == major) && (glib_minor_version > minor)) ||
        ((glib_major_version == major) && (glib_minor_version == minor) && (glib_micro_version >= micro)))
      {
        return 0;
       }
     else
      {
        printf("\n*** An old version of GLIB (%d.%d.%d) was found.\n",
               glib_major_version, glib_minor_version, glib_micro_version);
        printf("*** You need a version of GLIB newer than %d.%d.%d. The latest version of\n",
	       major, minor, micro);
        printf("*** GLIB is always available from ftp://ftp.gtk.org.\n");
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the glib-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of GLIB, but you can also set the GLIB_CONFIG environment to point to the\n");
        printf("*** correct copy of glib-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_glib=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_glib" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$GLIB_CONFIG" = "no" ; then
       echo "*** The glib-config script installed by GLIB could not be found"
       echo "*** If GLIB was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the GLIB_CONFIG environment variable to the"
       echo "*** full path to glib-config."
     else
       if test -f conf.glibtest ; then
        :
       else
          echo "*** Could not run GLIB test program, checking why..."
          CFLAGS="$CFLAGS $GLIB_CFLAGS"
          LIBS="$LIBS $GLIB_LIBS"
          AC_TRY_LINK([
#include <glib.h>
#include <stdio.h>
],      [ return ((glib_major_version) || (glib_minor_version) || (glib_micro_version)); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding GLIB or finding the wrong"
          echo "*** version of GLIB. If it is not finding GLIB, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
	  echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***"
          echo "*** If you have a RedHat 5.0 system, you should remove the GTK package that"
          echo "*** came with the system with the command"
          echo "***"
          echo "***    rpm --erase --nodeps gtk gtk-devel" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means GLIB was incorrectly installed"
          echo "*** or that you have moved GLIB since it was installed. In the latter case, you"
          echo "*** may want to edit the glib-config script: $GLIB_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     GLIB_CFLAGS=""
     GLIB_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GLIB_CFLAGS)
  AC_SUBST(GLIB_LIBS)
  rm -f conf.glibtest
])




AC_DEFUN([AM_GNUNET_PATH_GTK], [
AC_ARG_WITH(gtk-prefix,[  --with-gtk-prefix=PFX   Prefix where GTK is installed (optional)],
            gtk_config_prefix="$withval", gtk_config_prefix="")
AC_ARG_WITH(gtk-exec-prefix,[  --with-gtk-exec-prefix=PFX Exec prefix where GTK is installed (optional)],
            gtk_config_exec_prefix="$withval", gtk_config_exec_prefix="")
AC_ARG_ENABLE(gtktest, [  --disable-gtktest       Do not try to compile and run a test GTK program],
		    , enable_gtktest=yes)

  for module in . $4
  do
      case "$module" in
         gthread)
             gtk_config_args="$gtk_config_args gthread"
         ;;
      esac
  done

  if test x$gtk_config_exec_prefix != x ; then
     gtk_config_args="$gtk_config_args --exec-prefix=$gtk_config_exec_prefix"
     if test x${GTK_CONFIG+set} != xset ; then
        GTK_CONFIG=$gtk_config_exec_prefix/bin/gtk-config
     fi
  fi
  if test x$gtk_config_prefix != x ; then
     gtk_config_args="$gtk_config_args --prefix=$gtk_config_prefix"
     if test x${GTK_CONFIG+set} != xset ; then
        GTK_CONFIG=$gtk_config_prefix/bin/gtk-config
     fi
  fi

  AC_PATH_PROG(GTK_CONFIG, gtk-config, no)
  min_gtk_version=ifelse([$1], ,0.99.7,$1)
  AC_MSG_CHECKING(for GTK - version >= $min_gtk_version)
  no_gtk=""
  if test "$GTK_CONFIG" = "no" ; then
    no_gtk=yes
  else
    GTK_CFLAGS=`$GTK_CONFIG $gtk_config_args --cflags`
    GTK_LIBS=`$GTK_CONFIG $gtk_config_args --libs`
    gtk_config_major_version=`$GTK_CONFIG $gtk_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    gtk_config_minor_version=`$GTK_CONFIG $gtk_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    gtk_config_micro_version=`$GTK_CONFIG $gtk_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_gtktest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GTK_CFLAGS"
      LIBS="$GTK_LIBS $LIBS"
dnl
dnl Now check if the installed GTK is sufficiently new. (Also sanity
dnl checks the results of gtk-config to some extent
dnl
      rm -f conf.gtktest
      AC_TRY_RUN([
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>

int 
main ()
{
  int major, minor, micro;
  char *tmp_version;

  system ("touch conf.gtktest");

  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = g_strdup("$min_gtk_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_gtk_version");
     exit(1);
   }

  if ((gtk_major_version != $gtk_config_major_version) ||
      (gtk_minor_version != $gtk_config_minor_version) ||
      (gtk_micro_version != $gtk_config_micro_version))
    {
      printf("\n*** 'gtk-config --version' returned %d.%d.%d, but GTK+ (%d.%d.%d)\n", 
             $gtk_config_major_version, $gtk_config_minor_version, $gtk_config_micro_version,
             gtk_major_version, gtk_minor_version, gtk_micro_version);
      printf ("*** was found! If gtk-config was correct, then it is best\n");
      printf ("*** to remove the old version of GTK+. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If gtk-config was wrong, set the environment variable GTK_CONFIG\n");
      printf("*** to point to the correct copy of gtk-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    } 
#if defined (GTK_MAJOR_VERSION) && defined (GTK_MINOR_VERSION) && defined (GTK_MICRO_VERSION)
  else if ((gtk_major_version != GTK_MAJOR_VERSION) ||
	   (gtk_minor_version != GTK_MINOR_VERSION) ||
           (gtk_micro_version != GTK_MICRO_VERSION))
    {
      printf("*** GTK+ header files (version %d.%d.%d) do not match\n",
	     GTK_MAJOR_VERSION, GTK_MINOR_VERSION, GTK_MICRO_VERSION);
      printf("*** library (version %d.%d.%d)\n",
	     gtk_major_version, gtk_minor_version, gtk_micro_version);
    }
#endif /* defined (GTK_MAJOR_VERSION) ... */
  else
    {
      if ((gtk_major_version > major) ||
        ((gtk_major_version == major) && (gtk_minor_version > minor)) ||
        ((gtk_major_version == major) && (gtk_minor_version == minor) && (gtk_micro_version >= micro)))
      {
        return 0;
       }
     else
      {
        printf("\n*** An old version of GTK+ (%d.%d.%d) was found.\n",
               gtk_major_version, gtk_minor_version, gtk_micro_version);
        printf("*** You need a version of GTK+ newer than %d.%d.%d. The latest version of\n",
	       major, minor, micro);
        printf("*** GTK+ is always available from ftp://ftp.gtk.org.\n");
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the gtk-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of GTK+, but you can also set the GTK_CONFIG environment to point to the\n");
        printf("*** correct copy of gtk-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_gtk=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_gtk" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])     
  else
     AC_MSG_RESULT(no)
     if test "$GTK_CONFIG" = "no" ; then
       echo "*** The gtk-config script installed by GTK could not be found"
       echo "*** If GTK was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the GTK_CONFIG environment variable to the"
       echo "*** full path to gtk-config."
     else
       if test -f conf.gtktest ; then
        :
       else
          echo "*** Could not run GTK test program, checking why..."
          CFLAGS="$CFLAGS $GTK_CFLAGS"
          LIBS="$LIBS $GTK_LIBS"
          AC_TRY_LINK([
#include <gtk/gtk.h>
#include <stdio.h>
],      [ return ((gtk_major_version) || (gtk_minor_version) || (gtk_micro_version)); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding GTK or finding the wrong"
          echo "*** version of GTK. If it is not finding GTK, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
	  echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***"
          echo "*** If you have a RedHat 5.0 system, you should remove the GTK package that"
          echo "*** came with the system with the command"
          echo "***"
          echo "***    rpm --erase --nodeps gtk gtk-devel" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means GTK was incorrectly installed"
          echo "*** or that you have moved GTK since it was installed. In the latter case, you"
          echo "*** may want to edit the gtk-config script: $GTK_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     GTK_CFLAGS=""
     GTK_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GTK_CFLAGS)
  AC_SUBST(GTK_LIBS)
  rm -f conf.gtktest
])

dnl AM_PATH_LIBGCRYPT([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for liblibgcrypt and define LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS
dnl
AC_DEFUN([AM_PATH_LIBGCRYPT],
[ AC_ARG_WITH(gcrypt,
            AC_HELP_STRING([--with-gcrypt=PFX],
                           [prefix where LIBGCRYPT is installed (optional)]),
     libgcrypt_config_prefix="$withval", libgcrypt_config_prefix="")
  if test x$libgcrypt_config_prefix != x ; then
     if test x${LIBGCRYPT_CONFIG+set} != xset ; then
        LIBGCRYPT_CONFIG=$libgcrypt_config_prefix/bin/libgcrypt-config
     fi
  fi
 
  AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  min_libgcrypt_version=ifelse([$1], ,0.4.4,$1)
  AC_MSG_CHECKING(for LIBGCRYPT - version >= $min_libgcrypt_version)
  ok=no
  if test "$LIBGCRYPT_CONFIG" != "no" ; then
    req_major=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libgcrypt_config_version=`$LIBGCRYPT_CONFIG --version`
    major=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$major" -eq "$req_major"; then
            if test "$minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$minor" -eq "$req_minor"; then
                   if test "$micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LIBGCRYPT_CFLAGS=""
    LIBGCRYPT_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBGCRYPT_CFLAGS)
  AC_SUBST(LIBGCRYPT_LIBS)
])
## Autoconf macros for working with Guile.
##
##   Copyright (C) 1998,2001 Free Software Foundation, Inc.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this software; see the file COPYING.  If not, write to
## the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
## Boston, MA 02111-1307 USA
##
## As a special exception, the Free Software Foundation gives permission
## for additional uses of the text contained in its release of GUILE.
##
## The exception is that, if you link the GUILE library with other files
## to produce an executable, this does not by itself cause the
## resulting executable to be covered by the GNU General Public License.
## Your use of that executable is in no way restricted on account of
## linking the GUILE library code into it.
##
## This exception does not however invalidate any other reasons why
## the executable file might be covered by the GNU General Public License.
##
## This exception applies only to the code released by the
## Free Software Foundation under the name GUILE.  If you copy
## code from other Free Software Foundation releases into a copy of
## GUILE, as the General Public License permits, the exception does
## not apply to the code that you add in this way.  To avoid misleading
## anyone as to the status of such modified files, you must delete
## this exception notice from them.
##
## If you write modifications of your own for GUILE, it is your choice
## whether to permit this exception to apply to your modifications.
## If you do not wish that, delete this exception notice.

## Index
## -----
##
## GUILE_PROGS -- set paths to Guile interpreter, config and tool programs
## GUILE_FLAGS -- set flags for compiling and linking with Guile
## GUILE_SITE_DIR -- find path to Guile "site" directory
## GUILE_CHECK -- evaluate Guile Scheme code and capture the return value
## GUILE_MODULE_CHECK -- check feature of a Guile Scheme module
## GUILE_MODULE_AVAILABLE -- check availability of a Guile Scheme module
## GUILE_MODULE_REQUIRED -- fail if a Guile Scheme module is unavailable
## GUILE_MODULE_EXPORTS -- check if a module exports a variable
## GUILE_MODULE_REQUIRED_EXPORT -- fail if a module doesn't export a variable

## Code
## ----

## NOTE: Comments preceding an AC_DEFUN (starting from "Usage:") are massaged
## into doc/ref/autoconf-macros.texi (see Makefile.am in that directory).

# GUILE_PROGS -- set paths to Guile interpreter, config and tool programs
#
# Usage: GUILE_PROGS
#
# This macro looks for programs @code{guile}, @code{guile-config} and
# @code{guile-tools}, and sets variables @var{GUILE}, @var{GUILE_CONFIG} and
# @var{GUILE_TOOLS}, to their paths, respectively.  If either of the first two
# is not found, signal error.
#
# The variables are marked for substitution, as by @code{AC_SUBST}.
#
AC_DEFUN([GUILE_PROGS],
 [AC_PATH_PROG(GUILE,guile)
  if test "$GUILE" = "" ; then
      AC_MSG_WARN([guile required but not found])
  fi
  AC_SUBST(GUILE)
  AC_PATH_PROG(GUILE_CONFIG,guile-config)
  if test "$GUILE_CONFIG" = "" ; then
      AC_MSG_WARN([guile-config required but not found])
  fi
  AC_SUBST(GUILE_CONFIG)
  AC_PATH_PROG(GUILE_TOOLS,guile-tools)
  AC_SUBST(GUILE_TOOLS)
 ])

# GUILE_FLAGS -- set flags for compiling and linking with Guile
#
# Usage: GUILE_FLAGS
#
# This macro runs the @code{guile-config} script, installed with Guile, to
# find out where Guile's header files and libraries are installed.  It sets
# two variables, @var{GUILE_CFLAGS} and @var{GUILE_LDFLAGS}.
#
# @var{GUILE_CFLAGS}: flags to pass to a C or C++ compiler to build code that
# uses Guile header files.  This is almost always just a @code{-I} flag.
#
# @var{GUILE_LDFLAGS}: flags to pass to the linker to link a program against
# Guile.  This includes @code{-lguile} for the Guile library itself, any
# libraries that Guile itself requires (like -lqthreads), and so on.  It may
# also include a @code{-L} flag to tell the compiler where to find the
# libraries.
#
# The variables are marked for substitution, as by @code{AC_SUBST}.
#
AC_DEFUN([GUILE_FLAGS],
 [AC_REQUIRE([GUILE_PROGS])dnl
  AC_MSG_CHECKING([libguile compile flags])
  GUILE_CFLAGS="`$GUILE_CONFIG compile`"
  AC_MSG_RESULT([$GUILE_CFLAGS])
  AC_MSG_CHECKING([libguile link flags])
  GUILE_LDFLAGS="`$GUILE_CONFIG link`"
  AC_MSG_RESULT([$GUILE_LDFLAGS])
  AC_SUBST(GUILE_CFLAGS)
  AC_SUBST(GUILE_LDFLAGS)
 ])

# GUILE_SITE_DIR -- find path to Guile "site" directory
#
# Usage: GUILE_SITE_DIR
#
# This looks for Guile's "site" directory, usually something like
# PREFIX/share/guile/site, and sets var @var{GUILE_SITE} to the path.
# Note that the var name is different from the macro name.
#
# The variable is marked for substitution, as by @code{AC_SUBST}.
#
AC_DEFUN([GUILE_SITE_DIR],
 [AC_REQUIRE([GUILE_PROGS])dnl
  AC_MSG_CHECKING(for Guile site directory)
  GUILE_SITE=`[$GUILE_CONFIG] info pkgdatadir`/site
  AC_MSG_RESULT($GUILE_SITE)
  AC_SUBST(GUILE_SITE)
 ])

# GUILE_CHECK -- evaluate Guile Scheme code and capture the return value
#
# Usage: GUILE_CHECK_RETVAL(var,check)
#
# @var{var} is a shell variable name to be set to the return value.
# @var{check} is a Guile Scheme expression, evaluated with "$GUILE -c", and
#    returning either 0 or non-#f to indicate the check passed.
#    Non-0 number or #f indicates failure.
#    Avoid using the character "#" since that confuses autoconf.
#
AC_DEFUN([GUILE_CHECK],
 [AC_REQUIRE([GUILE_PROGS])
  $GUILE -c "$2" > /dev/null 2>&1
  $1=$?
 ])

# GUILE_MODULE_CHECK -- check feature of a Guile Scheme module
#
# Usage: GUILE_MODULE_CHECK(var,module,featuretest,description)
#
# @var{var} is a shell variable name to be set to "yes" or "no".
# @var{module} is a list of symbols, like: (ice-9 common-list).
# @var{featuretest} is an expression acceptable to GUILE_CHECK, q.v.
# @var{description} is a present-tense verb phrase (passed to AC_MSG_CHECKING).
#
AC_DEFUN([GUILE_MODULE_CHECK],
         [AC_MSG_CHECKING([if $2 $4])
	  GUILE_CHECK($1,(use-modules $2) (exit ((lambda () $3))))
	  if test "$$1" = "0" ; then $1=yes ; else $1=no ; fi
          AC_MSG_RESULT($$1)
         ])

# GUILE_MODULE_AVAILABLE -- check availability of a Guile Scheme module
#
# Usage: GUILE_MODULE_AVAILABLE(var,module)
#
# @var{var} is a shell variable name to be set to "yes" or "no".
# @var{module} is a list of symbols, like: (ice-9 common-list).
#
AC_DEFUN([GUILE_MODULE_AVAILABLE],
         [GUILE_MODULE_CHECK($1,$2,0,is available)
         ])

# GUILE_MODULE_REQUIRED -- fail if a Guile Scheme module is unavailable
#
# Usage: GUILE_MODULE_REQUIRED(symlist)
#
# @var{symlist} is a list of symbols, WITHOUT surrounding parens,
# like: ice-9 common-list.
#
AC_DEFUN([GUILE_MODULE_REQUIRED],
         [GUILE_MODULE_AVAILABLE(ac_guile_module_required, ($1))
          if test "$ac_guile_module_required" = "no" ; then
              AC_MSG_ERROR([required guile module not found: ($1)])
          fi
         ])

# GUILE_MODULE_EXPORTS -- check if a module exports a variable
#
# Usage: GUILE_MODULE_EXPORTS(var,module,modvar)
#
# @var{var} is a shell variable to be set to "yes" or "no".
# @var{module} is a list of symbols, like: (ice-9 common-list).
# @var{modvar} is the Guile Scheme variable to check.
#
AC_DEFUN([GUILE_MODULE_EXPORTS],
 [GUILE_MODULE_CHECK($1,$2,$3,exports `$3')
 ])

# GUILE_MODULE_REQUIRED_EXPORT -- fail if a module doesn't export a variable
#
# Usage: GUILE_MODULE_REQUIRED_EXPORT(module,modvar)
#
# @var{module} is a list of symbols, like: (ice-9 common-list).
# @var{modvar} is the Guile Scheme variable to check.
#
AC_DEFUN([GUILE_MODULE_REQUIRED_EXPORT],
 [GUILE_MODULE_EXPORTS(guile_module_required_export,$1,$2)
  if test "$guile_module_required_export" = "no" ; then
      AC_MSG_ERROR([module $1 does not export $2; required])
  fi
 ])

## guile.m4 ends here
