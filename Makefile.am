INCLUDES = -I$(top_srcdir)/src/include
SUBDIRS  = libltdl src doc contrib

if USE_GCRYPT
  DISTCHECK_CONFIGURE_FLAGS=--with-gcrypt
endif
if USE_OPENSSL
  DISTCHECK_CONFIGURE_FLAGS=--with-crypto
endif

EXTRA_DIST = \
 README.fr \
 UPDATING \
 PLATFORMS \
 acinclude.m4
