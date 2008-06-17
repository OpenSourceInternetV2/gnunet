INCLUDES = -I$(top_srcdir)/src/include

bin_PROGRAMS = \
 gnunet-check \
 gnunet-convert

check_PROGRAMS = \
 low_db_test \
 high_db_test 

TESTS = \
 $(check_PROGRAMS)

if HAVE_GDBM
LIB_GDBM = libgnunetafs_database_gdbm.la 
else
LIB_GDBM =
XGDBM =
endif

if HAVE_TDB
LIB_TDB = libgnunetafs_database_tdb.la
else
LIB_TDB =
endif

if HAVE_MYSQL
LIB_MYSQL = libgnunetafs_database_mysql.la
else
LIB_MYSQL =
XMYSQL = 
endif

if HAVE_DIRECTORY
LIB_DIRECTORY = libgnunetafs_database_directory.la
else
LIB_DIRECTORY =
XDIR = 
endif

if HAVE_BDB
LIB_BDB = libgnunetafs_database_bdb.la
else
LIB_BDB =
XBDB =
endif

lib_LTLIBRARIES = \
  libgnunetafs_protocol.la \
  $(LIB_BDB) \
  $(LIB_DIRECTORY) \
  $(LIB_GDBM) \
  $(LIB_MYSQL) \
  $(LIB_TDB)



libgnunetafs_protocol_la_SOURCES = \
  afs.c \
  bloomfilter.c \
  fileindex.c \
  handler.c\
  large_file_support.c \
  manager.c \
  migration.c \
  policy.c \
  querymanager.c \
  routing.c \
  afs.h \
  fileindex.h \
  high_backend.h \
  large_file_support.h \
  manager.h \
  policy.h \
  routing.h\
  bloomfilter.h \
  handler.h \
  high_simple_helper.h \
  low_backend.h \
  migration.h  \
  querymanager.h

libgnunetafs_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunetafs_protocol_la_LIBADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunet_afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la 


libgnunetafs_database_bdb_la_SOURCES = \
  high_simple.c \
  high_simple_helper.c \
  low_bdb.c

libgnunetafs_database_bdb_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_bdb_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -ldb


libgnunetafs_database_directory_la_SOURCES = \
  high_simple.c \
  high_simple_helper.c \
  low_directory.c

libgnunetafs_database_directory_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_directory_la_LDFLAGS = \
 -export-dynamic -avoid-version -module


libgnunetafs_database_gdbm_la_SOURCES = \
  high_simple.c \
  high_simple_helper.c \
  low_gdbm.c

libgnunetafs_database_gdbm_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_gdbm_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -lgdbm


libgnunetafs_database_mysql_la_SOURCES = \
  high_mysql.c

libgnunetafs_database_mysql_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_mysql_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -lmysqlclient


libgnunetafs_database_tdb_la_SOURCES = \
  high_simple.c \
  high_simple_helper.c \
  low_tdb.c

libgnunetafs_database_tdb_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_tdb_la_LDFLAGS = \
  -export-dynamic -avoid-version -module -ltdb


gnunet_check_SOURCES = \
  gnunet-check.c 

gnunet_check_LDADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunet_afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_convert_SOURCES = \
  gnunet-convert.c 

gnunet_convert_LDADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunet_afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la


low_db_test_SOURCES = \
 low_db_test.c

low_db_test_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  

high_db_test_SOURCES = \
 high_db_test.c

high_db_test_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
