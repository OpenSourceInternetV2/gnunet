INCLUDES = -I$(top_srcdir)/src/include


lib_LTLIBRARIES = \
  libgnunetrpc_util.la \
  libgnunetrpc_protocol.la

libgnunetrpc_protocol_la_SOURCES = \
  rpc.c 

libgnunetrpc_protocol_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/applications/rpc/libgnunetrpc_util.la

libgnunetrpc_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunetrpc_util_la_SOURCES = \
  parameters.c 

libgnunetrpc_util_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  parameterstest 

TESTS = $(check_PROGRAMS)

parameterstest_SOURCES = \
  parameterstest.c 

parameterstest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
