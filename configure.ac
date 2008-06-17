# This file is part of GNUnet.
# (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)
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
AC_INIT([GNUnet], [0.6.6b],[bug-gnunet@gnu.org])
AM_INIT_AUTOMAKE([GNUnet], [0.6.6b])
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
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AC_CHECK_LIB(resolv, res_init)
     AC_CHECK_LIB(rt, nanosleep)
     build_target="solaris"
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="cygwin"
     AC_PROG_CXX
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_DEFINE_UNQUOTED(_WIN32,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined -Wl,--export-all-symbols -lws2_32"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="mingw"
     AC_PROG_CXX
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
;;
esac

CHECK_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CPPFLAGS="$PTHREAD_CPPFLAGS $CPPFLAGS $LTDLINCL"
LDFLAGS="$PTHREAD_LDFLAGS $LDFLAGS"

# pthread_t is a struct since 11/2004
AC_CHECK_MEMBER(pthread_t.p, AC_DEFINE(HAVE_NEW_PTHREAD_T, 1,
  [Define if you have a post 11/2004 pthread library]), , [#include <pthread.h>])

AC_MSG_CHECKING([for build target])
AM_CONDITIONAL(CYGWIN, test "$build_target" = "cygwin")
AM_CONDITIONAL(MINGW, test "$build_target" = "mingw")
AM_CONDITIONAL(SOLARIS, test "$build_target" = "solaris")
AC_MSG_RESULT([$build_target])

# We have two choices for the crypto stuff.  
# 1) By default we use whatever is present (OpenSSL or gcrypt)
# 2) If both are present, we default to libgcrypt
# 3) If both are present and --with-openssl=PFX is given,
#    we use OpenSSL

# gcrypt
gcrypt=0
AC_MSG_CHECKING(for libgcrypt) 
AM_PATH_LIBGCRYPT(1.2.0, gcrypt=1)

# openssl
if test "$build_target" = "mingw"
then
  openssl_libs="-lgdi32"
fi

openssl=0
AC_ARG_WITH(crypto,
  [  --with-crypto=PFX        Base of OpenSSL installation],
  [AC_MSG_RESULT("$with_crypto")
   case $with_crypto in
   no) openssl=0
       ;;
   yes) AC_CHECK_LIB([crypto], [RSA_generate_key],
         [AC_CHECK_HEADERS([openssl/rsa.h openssl/blowfish.h],
          openssl=1;gcrypt=0)], ,["$openssl_libs"])
       ;;
   *) LDFLAGS="$LDFLAGS -L$with_crypto/lib"
      CPPFLAGS="$CPPFLAGS -I$with_crypto/include"
      AC_CHECK_LIB([crypto], [RSA_generate_key],
       [AC_CHECK_HEADERS([openssl/rsa.h openssl/blowfish.h], 
         openssl=1;gcrypt=0)], , ["$openssl_libs"])
       ;;
   esac],
   [AC_CHECK_LIB([crypto], [RSA_generate_key],
     [AC_CHECK_HEADERS([openssl/rsa.h openssl/blowfish.h],
      openssl=1)], , ["$openssl_libs"])])

if test $openssl = 0 
then
if test $gcrypt = 0
then
  AC_MSG_ERROR([GNUnet needs libgcrypt or OpenSSL])
fi
fi

# Given the choice, the preference is libgcrypt
if test $openssl = 1
then
if test $gcrypt = 1
then
openssl=0
fi
fi

if test $gcrypt = 1
then
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

AM_CONDITIONAL(USE_OPENSSL, test x$openssl = x1)
AC_DEFINE_UNQUOTED(USE_OPENSSL, $openssl, [openssl available])



# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])


# test for libextractor
extractor=0
AC_MSG_CHECKING(for libextractor)
AC_ARG_WITH(extractor,
   [  --with-extractor=PFX    Base of libextractor installation],
   [AC_MSG_RESULT("$with_extractor")
    case $with_extractor in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
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
   case $with_gdbm in
   no) 
     ;;
   yes)
    AC_CHECK_HEADERS(gdbm.h,
     AC_CHECK_LIB(gdbm, gdbm_open,
      gdb=true))   
     ;;
   *)
    LDFLAGS="-L$with_gdbm/lib $LDFLAGS"
    CPPFLAGS="-I$with_gdbm/include $CPPFLAGS"
    AC_CHECK_HEADERS(gdbm.h,
     AC_CHECK_LIB(gdbm, gdbm_open,
      EXT_LIB_PATH="-L$with_gdbm/lib $EXT_LIB_PATH"
      gdb=true))
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-gdbm not specified])
   AC_CHECK_LIB(gdbm, gdbm_open,
    [AC_CHECK_HEADERS(gdbm.h, gdb=true)])])
AC_CHECK_DECLS([GDBM_CENTFREE, GDBM_COALESCEBLKS])
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

bdb_dll=false
if test x$bdb = xtrue -a "$build_target" = "mingw"
then
 AC_MSG_CHECKING(for bdb DLL)
 AC_LANG_CONFTEST(
   [AC_LANG_SOURCE([[int main(){return 0;}]])])
 $CC $CFLAGS conftest.c /usr/local/lib/libdb.dll -o conftest.exe 2> /dev/null
 if test $? = 0
 then
  AC_MSG_RESULT([yes])
  bdb_dll=true
  AC_DEFINE(HAVE_BDB_DLL, 1, [Define if you have the shared Berkeley DB library.])
 else
  AC_MSG_RESULT([no])
 fi
fi
AM_CONDITIONAL(HAVE_BDB_DLL, test x$bdb_dll = xtrue)



# test for sqlite
sqlite=false
AC_MSG_CHECKING(for SQLite)
AC_ARG_WITH(sqlite,
  [  --with-sqlite=PFX   Base of SQLite installation],
  [AC_MSG_RESULT("$with_sqlite")
   case $with_sqlite in
   no) 
     ;;
   yes)
    AC_CHECK_HEADERS(sqlite3.h,
     sqlite=true)
     ;;
   *)
    LDFLAGS="-L$with_sqlite/lib $LDFLAGS"
    CPPFLAGS="-I$with_sqlite/include $CPPFLAGS"
    AC_CHECK_HEADERS(sqlite3.h,
     EXT_LIB_PATH="-L$with_sqlite/lib $EXT_LIB_PATH"
     sqlite=true)
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-sqlite not specified])
    AC_CHECK_HEADERS(sqlite3.h, sqlite=true)])
AM_CONDITIONAL(HAVE_SQLITE, test x$sqlite = xtrue)


# test for libz (maybe required for linking mysql)
saveLIBS=$LIBS
zlib=1
AC_CHECK_LIB(z, compress,,zlib=0)
ZLIBS=$LIBS
LIBS=$saveLIBS
AM_CONDITIONAL(HAVE_ZLIB, test x$zlib = x1)

# test for mysql
mysql=false
mysqlfail=false
AC_MSG_CHECKING(for mysql)
AC_ARG_WITH(mysql,
  [  --with-mysql=PFX   Base of mysql installation],
  [AC_MSG_RESULT("$with_mysql")
   if test "$with_mysql" != "no"
   then
    LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS $ZLIBS"
    CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
    AC_CHECK_HEADERS(mysql/mysql.h,
     AC_CHECK_LIB(mysqlclient, mysql_init,
      EXT_LIB_PATH="-L$with_mysql/lib -L$with_mysql/lib/mysql $EXT_LIB_PATH"
      mysql=true))
   fi
  ],
  [AC_MSG_RESULT([--with-mysql not specified])
   LDFLAGS="-L/usr/lib/mysql $LDFLAGS $ZLIBS"
   AC_CHECK_LIB(mysqlclient, mysql_init,
    [AC_CHECK_HEADERS(mysql/mysql.h,
      EXT_LIB_PATH="-L/usr/lib/mysql $EXT_LIB_PATH"
      mysql=true
     )])])

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
AC_CHECK_LIB(gmp, __gmpz_import,, AC_MSG_ERROR([GNUnet requires the GNU MP library (libgmp)]))

# check for gtk >= 2.4.0 
AC_MSG_CHECKING(for gtk)
AM_PATH_GTK_2_0(2.4.0,without_gtk=false,without_gtk=true)
AM_CONDITIONAL(HAVE_GTK, test x$without_gtk != xtrue)

# check for gettext
AM_GNU_GETTEXT_VERSION(0.14)
AM_GNU_GETTEXT([external])


# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h limits.h stdio.h locale.h sys/stat.h sys/types.h pthread.h],,AC_MSG_ERROR([Compiling GNUnet requires standard UNIX headers files]))

# Checks for headers that are only required on some systems or opional (and where we do NOT abort if they are not there)
AC_CHECK_HEADERS([sys/mount.h sys/param.h sys/statvfs.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h])

# Check for GMP header (and abort if not present)
AC_CHECK_HEADERS([gmp.h],,AC_MSG_ERROR([Compiling GNUnet requires gmp.h (from the GNU MP library, libgmp)]))


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
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_FUNCS([floor gethostname memmove rmdir strncasecmp strrchr strtol atoll dup2 fdatasync ftruncate gethostbyname gettimeofday memset mkdir mkfifo select socket strcasecmp strchr strdup strerror strstr clock_gettime getrusage rand uname setlocale getcwd mktime])

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
if test "$enable_guile" = "yes"
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

AC_CONFIG_FILES([ po/Makefile.in m4/Makefile 
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
src/applications/rpc/Makefile
src/applications/dht/Makefile
src/applications/dht/tools/Makefile
src/applications/dht/module/Makefile
src/server/Makefile
src/transports/Makefile
src/util/Makefile
src/conf/Makefile
contrib/Makefile
src/util/win/Makefile
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version  
if test "$mysqlfail" = "true"
then
  AC_MSG_NOTICE([NOTICE: MySQL found, but too old. MySQL support will not be compiled.])
fi

# guile 
if test "x$guile" = "x0"
then
  AC_MSG_NOTICE([NOTICE: Guile not found, gnunet-download-manager will not be installed.])
fi

if test "$ipv6" = "0"
then
  AC_MSG_NOTICE([NOTICE: IPv6 support will NOT be compiled.])
fi

if test "$without_gtk" = "true"
then 
  AC_MSG_NOTICE([NOTICE: gnunet-gtk user interface will NOT be compiled.])
fi

AC_MSG_NOTICE([NOTICE: Database support is set to GDBM: $gdb, TDB: $tdb, BDB: $bdb, MySQL: $mysql, SQLite: $sqlite])

if test $openssl = 1
then
  AC_MSG_NOTICE([NOTICE: Using OpenSSL for cryptographic primitives.])
fi

if test $gcrypt = 1
then
  AC_MSG_NOTICE([NOTICE: Using libgcrypt for cryptographic primitives.])
fi
