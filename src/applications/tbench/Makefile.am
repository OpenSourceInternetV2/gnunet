INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-tbench

lib_LTLIBRARIES = \
  libgnunettbench_protocol.la


gnunet_tbench_SOURCES = \
  gnunet-tbench.c \
  tbench.h


libgnunettbench_protocol_la_SOURCES = \
  tbench.c\
  tbench.h

libgnunettbench_protocol_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
  
libgnunettbench_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
