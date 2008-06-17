INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunet_afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la

if CYGWIN
 CYGFLAGS = -I/usr/include/gtk-2.0/ -I/usr/lib/gtk-2.0/include \
  -I/usr/include/glib-2.0/ -I/usr/lib/glib-2.0/include/ \
  -I/usr/include/pango-1.0 -I/usr/include/atk-1.0
endif

if MINGW
 MINGWFLAGS = -I/mingw/include -I/mingw/lib/gtk+/include \
  -I/mingw/include/glib-2.0/ -I/mingw/lib/glib-2.0/include/ \
  -I/mingw/include/pango-1.0 -I/mingw/include/atk-1.0 \
  -mms-bitfields
endif

AM_CFLAGS = $(CYGFLAGS) $(MINGWFLAGS) $(GTK_CFLAGS)

bin_PROGRAMS = \
  gnunet-gtk

if CYGWIN
 CYGLDADD = \
   -lgtk-win32-2.0 -lgdk-win32-2.0 -lglib-2.0 -lgobject-2.0 -lgthread-2.0 
endif

if MINGW
 MINGWLDADD = \
  -lgtk-0 -lgdk-0 -lglib-2.0 -lcomdlg32 \
  @EXT_LIB_PATH@ $(LDADD) @EXT_LIBS@
endif

gnunet_gtk_LDADD = $(CYGLDADD) $(MINGWLDADD) $(GTK_LIBS) $(GLIB_LIBS) @EXT_LIB_PATH@ $(LDADD) @EXT_LIBS@

gnunet_gtk_SOURCES = \
  main.c \
  search.c  \
  saveas.c  \
  download.c \
  directory.c \
  pseudonyms.c \
  namespace.c \
  helper.c \
  insert.c\
  insertprogress.c\
  delete.c\
  directorydisplay.c \
  about.c \
  statistics.c \
  statistics.h \
  main.h \
  search.h  \
  saveas.h  \
  download.h \
  directory.h \
  pseudonyms.h \
  namespace.h \
  helper.h \
  insert.h\
  insertprogress.h\
  delete.h\
  directorydisplay.h \
  about.h
