INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunet_afs_esed2.la 

libgnunet_afs_esed2_la_SOURCES = \
  block.c \
  contentencoding.c \
  deleteutil.c \
  directory.c \
  downloadutil.c \
  insertutil.c \
  keywords.c \
  policy.c \
  pseudonym.c \
  requestmanager.c \
  sblock.c \
  searchutil.c \
  priority.c \
  uri.c

if USE_LIBEXTRACTOR
libgnunet_afs_esed2_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor 
else
libgnunet_afs_esed2_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
endif


