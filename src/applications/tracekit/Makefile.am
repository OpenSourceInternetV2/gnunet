INCLUDES = -I$(top_srcdir)/src/include

LDADD =  \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-tracekit

lib_LTLIBRARIES = \
  libgnunettracekit_protocol.la


gnunet_tracekit_SOURCES = \
  gnunet-tracekit.c \
  tracekit.h


libgnunettracekit_protocol_la_SOURCES = \
  tracekit.c \
  tracekit.h

libgnunettracekit_protocol_la_LIBADD = \
  $(LDADD)

libgnunettracekit_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
