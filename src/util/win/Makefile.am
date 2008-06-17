INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libwin.la

if HAVE_BDB_DLL
 BDB_DLL = bdb_dll_wrapper.c
else
 BDB_DLL = 
endif

if MINGW
  libwin_la_SOURCES = \
     winproc.c \
     winselect.c \
     winstrptime.c \
     win.cc \
     inet_pton.c \
     $(BDB_DLL)
endif

if CYGWIN
  libwin_la_SOURCES = \
     winproc.c \
     $(BDB_DLL)
endif

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -lstdc++ -lcomdlg32
endif

if CYGWIN
  CYGFLAGS = -Wl,--no-undefined -Wl,--export-all-symbol
endif

libwin_la_LDFLAGS = \
  -export-dynamic $(WINFLAGS) $(CYGFLAGS) $(LIBS)

