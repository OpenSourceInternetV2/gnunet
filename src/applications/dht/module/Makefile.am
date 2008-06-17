INCLUDES = -I$(top_srcdir)/src/include


lib_LTLIBRARIES = \
  libgnunetdht_datastore_memory.la \
  libgnunetdht_protocol.la 


libgnunetdht_protocol_la_SOURCES = \
  dht.c \
  cs.c 
libgnunetdht_protocol_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/rpc/libgnunetrpc_util.la \
 $(top_builddir)/src/applications/dht/module/libgnunetdht_datastore_memory.la 
libgnunetdht_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module


libgnunetdht_datastore_memory_la_SOURCES = \
  datastore_memory.c 
libgnunetdht_datastore_memory_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetdht_datastore_memory_la_LDFLAGS = \
  -export-dynamic 


check_PROGRAMS = \
  datastore_memory_test \
  dht_test

TESTS = $(check_PROGRAMS)

datastore_memory_test_SOURCES = \
  datastore_memory_test.c
datastore_memory_test_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


dht_test_SOURCES = \
  dht_test.c
dht_test_LDADD = \
  $(top_builddir)/src/applications/rpc/libgnunetrpc_protocol.la \
  $(top_builddir)/src/applications/dht/module/libgnunetdht_protocol.la \
  $(top_builddir)/src/util/libgnunetutil.la 
