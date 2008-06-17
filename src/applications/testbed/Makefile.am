INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-testbed

lib_LTLIBRARIES = \
  libgnunettestbed_protocol.la


gnunet_testbed_SOURCES = \
  gnunet-testbed.c \
  testbed.h \
  socket.c \
  socket.h \
  commands.c \
  get-stats.c \
  get-stats.h \
  commands.h


libgnunettestbed_protocol_la_SOURCES = \
  testbed.c\
  testbed.h

libgnunettestbed_protocol_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
  
libgnunettestbed_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

EXTRA_DIST = \
  functions.sh \
  connect.php3 \
  display.php3 \
  startup.php3 
