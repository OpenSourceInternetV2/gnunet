INCLUDES = -I$(top_srcdir)/src/include

LDADD =  \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-chat

lib_LTLIBRARIES = \
  libgnunetchat_protocol.la


gnunet_chat_SOURCES = \
  gnunet-chat.c \
  chat.h 


libgnunetchat_protocol_la_SOURCES = \
  chat.c \
  chat.h

libgnunetchat_protocol_la_LIBADD = \
  $(LDADD)

libgnunetchat_protocol_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
