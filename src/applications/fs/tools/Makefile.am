INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
LDADD = \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

bin_PROGRAMS = \
  gnunet-auto-share \
  gnunet-directory \
  gnunet-pseudonym \
  gnunet-search \
  gnunet-insert \
  gnunet-download \
  gnunet-unindex



gnunet_auto_share_SOURCES = \
  gnunet-auto-share.c


gnunet_insert_SOURCES = \
  gnunet-insert.c 	
gnunet_insert_LDADD = \
  $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_unindex_SOURCES = \
  gnunet-unindex.c 	

gnunet_directory_SOURCES = \
  gnunet-directory.c
gnunet_directory_LDADD = \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_pseudonym_SOURCES = \
  gnunet-pseudonym.c
gnunet_pseudonym_LDADD = \
  $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
  $(top_builddir)/src/applications/fs/collection/libgnunetcollection.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_search_SOURCES = \
  gnunet-search.c

gnunet_download_SOURCES = \
  gnunet-download.c 
