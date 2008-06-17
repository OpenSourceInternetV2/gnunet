# This file is part of GNUnet.
# (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ(2.57)
AC_INIT([GNUnet], [0.6.2b],[bug-gnunet@gnu.org])
AM_INIT_AUTOMAKE([GNUnet], [0.6.2b])
AM_CONFIG_HEADER([config.h])

AH_TOP([#define _GNU_SOURCE  1])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LIBTOOL_WIN32_DLL
AC_CANONICAL_HOST


# dynamic libraries/plugins
AC_LIBTOOL_DLOPEN
AC_LIBLTDL_INSTALLABLE
AC_SUBST(LTDLINCL)
AC_SUBST(LIBLTDL)
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_LIB_LTDL
AC_CONFIG_SUBDIRS(libltdl)

if test "$enable_shared" = "no"
then
 AC_MSG_ERROR([GNUnet only works with shared libraries. Sorry.])
fi

CFLAGS="-Wall $CFLAGS"
# use '-fno-strict-aliasing', but only if the compiler can take it
if gcc -fno-strict-aliasing -S -o /dev/null -xc /dev/null >/dev/null 2>&1; 
then
 CFLAGS="-fno-strict-aliasing $CFLAGS"
fi


# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(OSX,1,[This is an OS X system])
     CFLAGS="-no-cpp-precomp $CFLAGS"
     LDFLAGS="-flat_namespace -undefined suppress $LDFLAGS"
     NAME_OF_DEV_RANDOM="/dev/urandom"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     NAME_OF_DEV_RANDOM="/dev/urandom"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     NAME_OF_DEV_RANDOM="/dev/urandom"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"     
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     NAME_OF_DEV_RANDOM="/dev/urandom"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AC_CHECK_LIB(resolv, res_init)
     AC_CHECK_LIB(rt, nanosleep)
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/random"
     random_modules="rndlinux"
     build_target="solaris"
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined"
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndw32"
     build_target="cygwin"
     AC_PROG_CXX
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined -Wl,--export-all-symbols -lws2_32"
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndw32"
     build_target="mingw"
     AC_PROG_CXX
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
     NAME_OF_DEV_RANDOM="/dev/random"
     NAME_OF_DEV_URANDOM="/dev/urandom"
     random_modules="rndlinux"
;;
esac

CHECK_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CPPFLAGS="$PTHREAD_CPPFLAGS $CPPFLAGS $LTDLINCL"
LDFLAGS="$PTHREAD_LDFLAGS $LDFLAGS"


AC_MSG_CHECKING([for build target])
AM_CONDITIONAL(CYGWIN, test "$build_target" = "cygwin")
AM_CONDITIONAL(MINGW, test "$build_target" = "mingw")
AM_CONDITIONAL(SOLARIS, test "$build_target" = "solaris")
AC_MSG_RESULT([$build_target])

# We have three choices for the crypto stuff.  
# 1) We use OpenSSL if it is present and the user specified
#    --with-crypto or we're building Windows executables.
# 2) We use libgcrypt if it is present and the user specified
#    --with-gcrypt.
# 3) If 1) and 2)  are wrong, we use our NEW, build-in crypto
#    code (which was adapted from libgcrypt).

# gcrypt
gcrypt=0
AC_MSG_CHECKING(for libgcrypt) 
if test "x$with_gcrypt" != "x"
then
	AM_PATH_LIBGCRYPT(1.1.43, gcrypt=1)
	if test "x$LIBGCRYPT_LIBS" != "x"
	then
   	      LDFLAGS="$LDFLAGS $LIBGCRYPT_LIBS"
	fi
	if test "x$LIBGCRYPT_CFLAGS" != "x"
	then
		CPPFLAGS="$CPPFLAGS $LIBGCRYPT_CFLAGS"
	fi
fi
AM_CONDITIONAL(USE_GCRYPT, test x$gcrypt = x1)
AC_DEFINE_UNQUOTED(USE_GCRYPT, $gcrypt, [gcrypt available])

# openssl
AC_MSG_CHECKING(for openssl)
if test "$build_target" = "mingw" -o "$build_target" = "cygwin"
then
  check_openssl=1
  AC_MSG_RESULT([yes])
else
  AC_ARG_WITH(crypto, 
     [  --with-crypto=PFX       Base of OpenSSL installation],
     [AC_MSG_RESULT("$with_crypto")
      case $with_crypto in
      no) check_openssl=0
          ;;
      *) check_openssl=1
          ;;
      esac],
     [AC_MSG_RESULT([--with-crypto not specified, not using openssl])])   
fi

openssl=0
if test "$check_openssl" = "1"
then
  case $with_crypto in
  no) openssl=0
      ;;
  yes) AC_CHECK_LIB([crypto], [RSA_generate_key],
        [AC_CHECK_HEADERS([openssl/rsa.h openssl/blowfish.h],
         [AM_GNUNET_SSL_VERSION
          openssl=1])])
      ;;
  *) LDFLAGS="$LDFLAGS -L$with_crypto/lib"
     CPPFLAGS="$CPPFLAGS -I$with_crypto/include"
     AC_CHECK_LIB([crypto], [RSA_generate_key],
      [AC_CHECK_HEADERS([openssl/rsa.h openssl/blowfish.h], openssl=1)])
      ;;
  esac
fi
AM_CONDITIONAL(USE_OPENSSL, test x$openssl = x1)
AC_DEFINE_UNQUOTED(USE_OPENSSL, $openssl, [openssl available])

# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])


# test for libextractor
extractor=0
AC_MSG_CHECKING(for libextractor)
AC_ARG_WITH(extractor,
   [  --with-extractor=PFX    Base of libextractor Directory],
   [AC_MSG_RESULT("$with_extractor")
    case $with_extractor in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
            EXT_LIB_PATH="-L$with_extractor/lib $EXT_LIB_PATH"
            extractor=1))
        ;;
      *)
        LDFLAGS="-L$with_extractor/lib $LDFLAGS"
        CPPFLAGS="-I$with_extractor/include $CPPFLAGS"
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
            EXT_LIB_PATH="-L$with_extractor/lib $EXT_LIB_PATH"
            extractor=1))
        ;;
    esac
   ],     
   [AC_MSG_RESULT([--with-extractor not specified])
    AC_CHECK_HEADERS(extractor.h,
     AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
      extractor=1))])
AM_CONDITIONAL(USE_LIBEXTRACTOR, test x$extractor = x1)
AC_DEFINE_UNQUOTED(USE_LIBEXTRACTOR, $extractor, [libextractor available])



# test for gdbm
gdb=false
AC_MSG_CHECKING(for gdbm)
AC_ARG_WITH(gdbm,
  [  --with-gdbm=PFX   Base of gdbm installation],
  [AC_MSG_RESULT("$with_gdbm")
   if test "$with_gdbm" != "no"
   then
    LDFLAGS="-L$with_gdbm/lib $LDFLAGS"
    CPPFLAGS="-I$with_gdbm/include $CPPFLAGS"
    AC_CHECK_HEADERS(gdbm.h,
     AC_CHECK_LIB(gdbm, gdbm_open,
      EXT_LIB_PATH="-L$with_gdbm/lib $EXT_LIB_PATH"
      gdb=true))
   fi
  ],
  [AC_MSG_RESULT([--with-gdbm not specified])
   AC_CHECK_LIB(gdbm, gdbm_open,
    [AC_CHECK_HEADERS(gdbm.h, gdb=true)])])
AM_CONDITIONAL(HAVE_GDBM, test x$gdb = xtrue)

# test for tdb
tdb=false
AC_MSG_CHECKING(for tdb)
AC_ARG_WITH(tdb,
  [  --with-tdb=PFX   Base of tdb installation],
  [AC_MSG_RESULT("$with_tdb")
   if test "$with_tdb" != "no"
   then
    LDFLAGS="-L$with_tdb/lib $LDFLAGS"
    CPPFLAGS="-I$with_tdb/include $CPPFLAGS"
    AC_CHECK_HEADERS(tdb.h,
     AC_CHECK_LIB(tdb, tdb_open,
      EXT_LIB_PATH="-L$with_tdb/lib $EXT_LIB_PATH"
      tdb=true))
   fi
  ],
  [AC_MSG_RESULT([--with-tdb not specified])
   AC_CHECK_LIB(tdb, tdb_open,
    [AC_CHECK_HEADERS(tdb.h, tdb=true)])])
AM_CONDITIONAL(HAVE_TDB, test x$tdb = xtrue)



# test for bdb
bdb=false
AC_MSG_CHECKING(for bdb)
AC_ARG_WITH(bdb,
  [  --with-bdb=PFX   Base of bdb installation],
  [AC_MSG_RESULT("$with_bdb")
   if test "$with_bdb" != "no"
   then
    LDFLAGS="-L$with_bdb/lib $LDFLAGS"
    CPPFLAGS="-I$with_bdb/include $CPPFLAGS"
    AC_CHECK_HEADERS(db.h,
      EXT_LIB_PATH="-L$with_bdb/lib $EXT_LIB_PATH"
      bdb=true)
   fi
  ],
  [AC_MSG_RESULT([--with-bdb not specified])
   AC_CHECK_HEADERS(db.h, bdb=true)])
AM_CONDITIONAL(HAVE_BDB, test x$bdb = xtrue)



# test for mysql
mysql=false
mysqlfail=false
AC_MSG_CHECKING(for mysql)
AC_ARG_WITH(mysql,
  [  --with-mysql=PFX   Base of mysql installation],
  [AC_MSG_RESULT("$with_mysql")
   if test "$with_mysql" != "no"
   then
    LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS"
    CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
    AC_CHECK_HEADERS(mysql/mysql.h,
     AC_CHECK_LIB(mysqlclient, mysql_init,
      EXT_LIB_PATH="-L$with_mysql/lib -L$with_mysql/lib/mysql"
      mysql=true))
   fi
  ],
  [AC_MSG_RESULT([--with-mysql not specified])
   AC_CHECK_LIB(mysqlclient, mysql_init,
    [AC_CHECK_HEADERS(mysql/mysql.h,mysql=true)])])

# additional version check for mysql
if test "$mysql" = "true"
then
  AC_MSG_CHECKING(mysql version)
  AC_RUN_IFELSE([AC_LANG_PROGRAM(
    [[#include <mysql/mysql.h>]],
    [[if (MYSQL_VERSION_ID < 32356)
        return(-1);
      else
        return(0);
    ]])
    ],mysql=true,mysql=false)
  if test "$mysql" = "false"
  then
    mysqlfail=true
    AC_MSG_RESULT([fail, >= 3.23.56 required])
  else
    AC_MSG_RESULT(ok)
  fi
fi
AM_CONDITIONAL(HAVE_MYSQL, test x$mysql = xtrue)



# always build directory
AM_CONDITIONAL(HAVE_DIRECTORY, test xtrue = xtrue)


# GNUnet Setup
curses=1
AC_CHECK_HEADER([ncurses.h], [AC_DEFINE([CURSES_LOC], [<ncurses.h>], [Curses location])],
 [AC_CHECK_HEADER([ncurses/ncurses.h], AC_DEFINE([CURSES_LOC], [<ncurses/ncurses.h>]),
 [AC_CHECK_HEADER([curses.h], AC_DEFINE([CURSES_LOC], [<curses.h>]),
 [AC_CHECK_HEADER([ncurses/curses.h], AC_DEFINE([CURSES_LOC], [<ncurses/curses.h>]),
 curses=0)])])])
saveLIBS=$LIBS
AC_CHECK_LIB(ncurses, scrollok,,curses=0)
LIBS=$saveLIBS
AC_DEFINE_UNQUOTED([HAVE_CURSES], $curses, [We have curses])
AM_CONDITIONAL(HAVE_CURSES, test x$curses = x1)

# some other checks for standard libs

AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))

# do gpg/libgcrypt/mpi checks only if we
# are in fact linking against our own crypto
# code and not against openssl/libgcrypt
# set am_conditionals to "false" otherwise
AM_CONDITIONAL(USE_RNDLINUX, test "n" = "y")
AM_CONDITIONAL(USE_RNDUNIX, test "n" = "y")
AM_CONDITIONAL(USE_RNDEGD, test "n" = "y")
AM_CONDITIONAL(USE_RNDW32, test "n" = "y")

if test $openssl == 0 
then
if test $gcrypt == 0
then

# GNUPG checks
GNUPG_CHECK_ENDIAN
GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

# MPI checks
MPI_OPT_FLAGS=""
AC_SUBST(MPI_OPT_FLAGS)

# Define conditionals and config.h symbols depending on the enabled
# random modules.
AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, "$NAME_OF_DEV_RANDOM",
                   [defined to the name of the strong random device])
AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, "$NAME_OF_DEV_URANDOM",
                   [defined to the name of the weaker random device])

LIST_MEMBER(rndlinux, $random_modules)
AM_CONDITIONAL(USE_RNDLINUX, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDLINUX, $found, [Defined if the /dev/random based RNG should be used.])

LIST_MEMBER(rndunix, $random_modules)
AM_CONDITIONAL(USE_RNDUNIX, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDUNIX, $found, [Defined if the default Unix RNG should be used.])
if test "$found" = "1"; then
   print_egd_notice=yes
fi

LIST_MEMBER(rndegd, $random_modules)
AM_CONDITIONAL(USE_RNDEGD, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDEGD, $found, [Defined if the EGD based RNG should be used.])
if test "$found" = "1"; then
   EGDLIBS=$NETLIBS
   AC_SUBST(EGDLIBS)
fi

LIST_MEMBER(rndw32, $random_modules)
AM_CONDITIONAL(USE_RNDW32, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDW32, $found, [Defined if the Windows specific RNG should be used.])


# end of libgcrypt specific checks
fi
fi


# check for gtk
AC_MSG_CHECKING(for gtk)
AC_ARG_WITH(gtk,
    [  --with-gtk=PFX	          Base of GTK installation],
    [AC_MSG_RESULT("$with_gtk")
     if test "$with_gtk" != "no"
     then
      without_gtk=false
      LDFLAGS="-L$with_gtk/lib $LDFLAGS"
      CPPFLAGS="-I$with_gtk/include $CPPFLAGS"     
      AM_GNUNET_PATH_GLIB(1.2.0,,AC_MSG_ERROR(Could not find glib),gthread)
      AM_GNUNET_PATH_GTK(1.2.0,,AC_MSG_ERROR(Could not find gtk),)
     else
      without_gtk=true
     fi],
    [AC_MSG_RESULT([--with-gtk not specified])
     without_gtk=false
     
     if test "$build_target" = "mingw"
     then
      AC_CHECK_LIB(gtk, gtk_window_new, , AC_MSG_ERROR(Could not find gtk))
      AC_CHECK_LIB(gdk, [gdk_init], , AC_MSG_ERROR(Could not find gdk))
      AC_CHECK_LIB(glib-2.0, [g_log], , AC_MSG_ERROR(Could not find glib-win32-2.0))
      AC_CHECK_LIB(gobject-2.0, [g_signal_new], , AC_MSG_ERROR(Could not find gobject-2.0))
      AC_CHECK_LIB(gthread-2.0, [g_thread_init], , AC_MSG_ERROR(Could not find gthread-2.0))
      AC_CHECK_LIB(iconv, [libiconv_open], , AC_MSG_ERROR(Could not find libiconv))       
     else
      if test "$build_target" = "cygwin"
      then
       AC_MSG_CHECKING(for gtk-win32-2.0)
       AC_CHECK_LIB(gtk-win32-2.0, gtk_window_new, AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find gtk-win32-2.0))
       AC_MSG_CHECKING(for gdk-win-2.0)
       AC_CHECK_LIB(gdk-win32-2.0, [gdk_init], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find gdk-win32-2.0))
       AC_MSG_CHECKING(for glib-2.0)
       AC_CHECK_LIB(glib-2.0, [g_log], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find glib-win32-2.0))
       AC_MSG_CHECKING(for gobject-2.0)
       AC_CHECK_LIB(gobject-2.0, [g_signal_new], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find gobject-2.0))
       AC_MSG_CHECKING(for gthread-2.0)
       AC_CHECK_LIB(gthread-2.0, [g_thread_init], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find gthread-2.0))
       AC_MSG_CHECKING(for libintl)
       AC_CHECK_LIB(libintl, [gettext], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find libintl))
       AC_MSG_CHECKING(for libiconv)
       AC_CHECK_LIB(libiconv, [libiconv_open], AC_MSG_RESULT(yes), AC_MSG_ERROR(Could not find libiconv))
      else
       AM_GNUNET_PATH_GLIB(1.2.0,,[without_gtk=true; AC_MSG_RESULT(glib not found)],gthread)
       AM_GNUNET_PATH_GTK(1.2.0,,[without_gtk=true; AC_MSG_RESULT(gtk not found)],)]
      fi
     fi
)
AM_CONDITIONAL(HAVE_GTK, test x$without_gtk != xtrue)




# memory debugger: electric fence?
AC_MSG_CHECKING(whether to link against efence)
AC_ARG_WITH(efence,
    [  --with-efence=PFX       Debug using efence (default is no)],
    [AC_MSG_RESULT("$with_efence")
     if test "$with_efence" != "no"
     then
      LDFLAGS="$with_efence/libefence.a $LDFLAGS"
     fi
    ],
    [AC_MSG_RESULT(no)]
)




# memory debugger: dmalloc? (defunct with GNUnet, do not use)
AC_MSG_CHECKING(wether to link against dmalloc)
AC_ARG_WITH(dmalloc,
    [  --with-dmalloc=PFX      Debug using dmalloc (default is no)],
    [AC_MSG_RESULT("$with_dmalloc")
     LDFLAGS="$with_dmalloc/libdmallocth.a $LDFLAGS"],
    [AC_MSG_RESULT(no)]
)



# right, like we would make use of that already...
AC_MSG_CHECKING(wether to link against gettext)
AC_ARG_WITH(gettext,
    [  --with-gettext=PFX      Use gettext (default is no)],
    [AC_MSG_RESULT("$with_gettext")
     if test "$with_gettext" != "no"
     then
      AC_CHECK_HEADER(libintl.h)
      AC_CHECK_LIB([gettextlib], [libintl_gettext],,
        AC_MSG_RESULT(Could not find gettextlib)) 
     fi
    ],
    [AC_MSG_RESULT(no)
     AC_CHECK_HEADER(libintl.h)
     AC_CHECK_LIB([gettextlib], [libintl_gettext],,,)]
)




# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/mount.h sys/param.h sys/statvfs.h sys/vfs.h arpa/inet.h fcntl.h libintl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h])



# Checks for standard typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM




# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_FUNCS([floor gethostname memmove rmdir strncasecmp strrchr strtol atoll dup2 fdatasync ftruncate gethostbyname gettimeofday memset mkdir mkfifo select socket strcasecmp strchr strdup strerror strstr clock_gettime getrusage rand uname])

AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(EXT_LIB_PATH)
AC_SUBST(EXT_LIBS)

# check for IPv6
ipv6=0
AC_MSG_CHECKING([whether to enable ipv6])
AC_ARG_ENABLE(ipv6,
 [AC_HELP_STRING([--enable-ipv6],[Enable ipv6 support])
  AC_HELP_STRING([--disable-ipv6],[Disable ipv6 support])],
 [case "$enableval" in
  no)	AC_MSG_RESULT(no)
        ipv6=0
	;;
  *)    AC_MSG_RESULT(yes)
        ipv6=1
	;;
  esac],
  [     AC_MSG_RESULT(no)
        ipv6=0])
AM_CONDITIONAL(HAVE_IPV6, test x$ipv6 != x0)
AC_DEFINE_UNQUOTED(USE_IPV6, $ipv6, [IPV6 available])

# check for guile

AC_ARG_ENABLE(guile,
              [AC_HELP_STRING([--enable-guile],
	                      [Install Guile scripts.])],
	      enable_guile=$enableval)

# By default, enable Guile
if test -z $enable_guile
then
    enable_guile="yes"
fi

guile=0
if test "$enable_guile" == "yes"
then
    AC_PATH_PROG([guile_available], [guile])
    if test -z "$guile_available"
    then
	AC_MSG_WARN([Guile not available, so `gnunet-download-manager' won't be installed.])
    else
	# Perform the whole Guile feature tests
	GUILE_PROGS
        guile=1
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 format)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 regex)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 and-let-star)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 pretty-print)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 documentation)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 optargs)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi

	# Check that the keywork syntax used by (ice-9 optargs) is `#:keywork'
	# (as in Guile 1.6) and not `#!' (as in Guile 1.4)
	GUILE_MODULE_CHECK([guile_pound_colon_keywords],
			   [(ice-9 optargs)],
			   [(lambda* (foo [#]:optional (o [#t])) o)],
			   [Guile 1.6's optarg keyword style is supported])
	if test $guile_pound_colon_keywords != "yes"
	then
	   AC_MSG_WARN([`(ice-9 optargs)' doesn't support the `[#:]' keyword syntax.  Upgrade to Guile 1.6 or later.]);
	  guile=0
        else
          guile=1
	fi
    fi
fi # enable_guile
AM_CONDITIONAL(HAVE_GUILE, test x$guile != x0)

AC_CONFIG_FILES([
Makefile
doc/Makefile
doc/man/Makefile
src/Makefile
src/include/Makefile
src/applications/Makefile
src/applications/afs/Makefile
src/applications/afs/esed2/Makefile
src/applications/afs/module/Makefile
src/applications/afs/gtkui/Makefile
src/applications/afs/tools/Makefile
src/applications/chat/Makefile
src/applications/stats/Makefile
src/applications/tbench/Makefile
src/applications/testbed/Makefile
src/applications/tracekit/Makefile
src/server/Makefile
src/test/Makefile
src/transports/Makefile
src/util/Makefile
src/conf/Makefile
contrib/Makefile
src/util/win/Makefile
src/util/gcry/Makefile
src/util/gcry/mpi/Makefile
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version  
if test "$mysqlfail" = "true"
then
  AC_MSG_NOTICE([NOTICE: MySQL found, but too old. MySQL support will not be compiled.])
fi

if test "$ipv6" = "0"
then
  AC_MSG_NOTICE([NOTICE: IPv6 support will NOT be compiled.])
fi

if test "$without_gtk" = "true"
then 
  AC_MSG_NOTICE([NOTICE: gnunet-gtk user interface will NOT be compiled.])
fi

AC_MSG_NOTICE([NOTICE: Database support is set to GDBM: $gdb, TDB: $tdb, BDB: $bdb, MySQL: $mysql])
