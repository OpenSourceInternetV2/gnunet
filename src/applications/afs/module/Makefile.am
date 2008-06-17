INCLUDES = -I$(top_srcdir)/src/include

bin_PROGRAMS = \
 gnunet-check \
 gnunet-convert

if HAVE_GDBM
LIB_GDBM = libgnunetafs_database_gdbm.la 
TEST_GDBM = low_db_test_gdbm high_db_test_gdbm
else
LIB_GDBM =
XGDBM =
endif


if HAVE_TDB
LIB_TDB = libgnunetafs_database_tdb.la
TEST_TDB = low_db_test_tdb high_db_test_tdb
else
LIB_TDB =
endif

if HAVE_MYSQL
LIB_MYSQL = libgnunetafs_database_mysql.la
TEST_MYSQL = high_db_test_mysql
else
LIB_MYSQL =
XMYSQL = 
endif

if HAVE_DIRECTORY
LIB_DIRECTORY = libgnunetafs_database_directory.la
TEST_DIRECTORY = low_db_test_directory high_db_test_directory
else
LIB_DIRECTORY =
XDIR = 
endif

if HAVE_BDB
LIB_BDB = libgnunetafs_database_bdb.la
TEST_BDB = low_db_test_bdb high_db_test_bdb
else
LIB_BDB =
XBDB =
endif

if HAVE_SQLITE
LIB_SQLITE = libgnunetafs_database_sqlite.la
TEST_SQLITE = high_db_test_sqlite
else
LIB_SQLITE = 
TEST_SQLITE = 
endif

lib_LTLIBRARIES = \
  libgnunetafs_protocol.la \
  $(LIB_BDB) \
  $(LIB_DIRECTORY) \
  $(LIB_GDBM) \
  $(LIB_MYSQL) \
  $(LIB_TDB) \
  $(LIB_SQLITE)



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


if HAVE_BDB_DLL
  BDB_LDFLAGS =
else
  BDB_LDFLAGS = -ldb
endif

libgnunetafs_database_bdb_la_SOURCES = \
  high_simple.c \
  high_simple_helper.c \
  low_bdb.c

libgnunetafs_database_bdb_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

libgnunetafs_database_bdb_la_LDFLAGS = \
 -export-dynamic -avoid-version -module $(BDB_LDFLAGS)


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

if HAVE_ZLIB
libgnunetafs_database_mysql_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -lmysqlclient -lz
else
libgnunetafs_database_mysql_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -lmysqlclient 
endif


libgnunetafs_database_sqlite_la_SOURCES = \
  high_sqlite.c

libgnunetafs_database_sqlite_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la

libgnunetafs_database_sqlite_la_LDFLAGS = \
 -export-dynamic -avoid-version -module -lsqlite3

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


check_PROGRAMS = \
 $(TEST_GDBM) $(TEST_TDB) $(TEST_MYSQL) $(TEST_DIRECTORY) $(TEST_BDB) $(TEST_SQLITE)

TESTS = \
 $(check_PROGRAMS)


low_db_test_gdbm_SOURCES = \
 low_db_test.c
low_db_test_gdbm_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
low_db_test_gdbm_CFLAGS = \
 -DDBSELECT="\"gdbm\""

low_db_test_directory_SOURCES = \
 low_db_test.c
low_db_test_directory_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
low_db_test_directory_CFLAGS = \
 -DDBSELECT="\"directory\""

low_db_test_bdb_SOURCES = \
 low_db_test.c
low_db_test_bdb_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
low_db_test_bdb_CFLAGS = \
 -DDBSELECT="\"bdb\""

low_db_test_tdb_SOURCES = \
 low_db_test.c
low_db_test_tdb_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
low_db_test_tdb_CFLAGS = \
 -DDBSELECT="\"tdb\""


high_db_test_gdbm_SOURCES = \
 high_db_test.c
high_db_test_gdbm_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_gdbm_CFLAGS = \
 -DDBSELECT="\"gdbm\""

high_db_test_directory_SOURCES = \
 high_db_test.c
high_db_test_directory_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_directory_CFLAGS = \
 -DDBSELECT="\"directory\""

high_db_test_tdb_SOURCES = \
 high_db_test.c
high_db_test_tdb_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_tdb_CFLAGS = \
 -DDBSELECT="\"tdb\""

high_db_test_bdb_SOURCES = \
 high_db_test.c
high_db_test_bdb_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_bdb_CFLAGS = \
 -DDBSELECT="\"bdb\""

high_db_test_mysql_SOURCES = \
 high_db_test.c
high_db_test_mysql_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_mysql_CFLAGS = \
 -DDBSELECT="\"mysql\""

high_db_test_sqlite_SOURCES = \
 high_db_test.c
high_db_test_sqlite_LDADD    = \
 $(top_builddir)/src/util/libgnunetutil.la  
high_db_test_sqlite_CFLAGS = \
 -DDBSELECT="\"sqlite\""

