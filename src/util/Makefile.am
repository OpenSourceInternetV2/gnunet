INCLUDES = -I$(top_srcdir)/src/include

if SOLARIS
 SOLFLAGS = -lrt
endif

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -lstdc++
 WINSUBDIRS = win
 WINLIBADD = $(top_builddir)/src/util/win/libwin.la 
endif

if CYGWIN
 CYGSUBDIRS = win
 CYGLIBADD = $(top_builddir)/src/util/win/libwin.la 
endif

ELIBDIR = $(libdir)

AM_CPPFLAGS = \
 -DPLUGIN_PATH="\"${libdir}\"" \
 -DELIBDIR=\"$(ELIBDIR)\"
# FIXME: ELIBDIR somehow no longer works...

lib_LTLIBRARIES = libgnunetutil.la

if USE_OPENSSL
 cryptofiles = hostkey_openssl.c symcipher_openssl.c
 CRYPTLIB = -lcrypto
else
if USE_GCRYPT
# nothing here
else
 GCSUBDIRS = gcry 
 cryptofiles = hostkey_gcry.c symcipher_gcry.c locking_gcrypt.c locking_gcrypt.h
 GCLIBADD = $(top_builddir)/src/util/gcry/libcipher.la 
endif
endif

libgnunetutil_la_LIBADD = $(GCLIBADD) $(CYGLIBADD) $(WINLIBADD)
SUBDIRS = $(GCSUBDIRS) $(WINSUBDIRS) $(CYGSUBDIRS) .

if USE_GCRYPT
if USE_OPENSSL
# nothing here 
else
 cryptofiles = hostkey_gcrypt.c symcipher_gcrypt.c locking_gcrypt.c locking_gcrypt.h
 CRYPTLIB = -lgcrypt
endif
endif

EXTRA_DIST = generate \
  hostkey_gcrypt.c \
  hostkey_gcry.c \
  hostkey_openssl.c \
  symcipher_gcrypt.c \
  symcipher_gcry.c \
  symcipher_openssl.c \
  locking_gcrypt.c \
  locking_gcrypt.h 

libgnunetutil_la_LDFLAGS = -export-dynamic $(LIBLTDL) $(CRYPTLIB) $(SOLFLAGS) $(WINFLAGS) $(LIBS)

generate_gnunetd_conf.c: generate
	./generate $(top_srcdir)/contrib/gnunet.root generate_gnunetd_conf > generate_gnunetd_conf.c
generate_gnunet_conf.c: generate
	./generate $(top_srcdir)/contrib/gnunet.user generate_gnunet_conf > generate_gnunet_conf.c

CLEANFILES = \
  generate_gnunetd_conf.c \
  generate_gnunet_conf.c

BUILT_SOURCES = \
  generate_gnunetd_conf.c \
  generate_gnunet_conf.c


libgnunetutil_la_SOURCES = \
 bloomfilter.c \
 checksum.c \
 configuration.c \
 cron.c \
 dso.c \
 getopt.c \
 generate_gnunetd_conf.c \
 generate_gnunet_conf.c \
 hashing.c \
 $(cryptofiles) \
 identity.c \
 initialize.c \
 io.c \
 ipcheck.c \
 logging.c \
 printhelp.c \
 port.c \
 semaphore.c \
 shutdown.c \
 state.c \
 statistics.c \
 statuscalls.c \
 storage.c \
 tcp_return.c \
 tcpio.c \
 timer.c \
 xmalloc.c 
