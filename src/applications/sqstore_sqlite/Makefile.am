INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_sqlite.la

check_PROGRAMS = \
  sqlitetest \
  sqlitetest2 \
  sqlitetest3

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(SQLITE_CPPFLAGS)

libgnunetmodule_sqstore_sqlite_la_SOURCES = \
  sqlite.c 
libgnunetmodule_sqstore_sqlite_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  $(SQLITE_LDFLAGS)
libgnunetmodule_sqstore_sqlite_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lsqlite3 \
  $(GN_LIBINTL)

EXTRA_DIST = check.conf

sqlitetest_SOURCES = \
 sqlitetest.c 
sqlitetest_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  


sqlitetest2_SOURCES = \
 sqlitetest2.c 
sqlitetest2_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  



sqlitetest3_SOURCES = \
 sqlitetest3.c 
sqlitetest3_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
