INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

if USE_OPENSSL
if USE_GCRYPT
CRYPT_TESTS = cry_comp
endif
endif

EXTRA_DIST = \
 testconfig.conf\
 dbspeedtest.c 

check_PROGRAMS = $(CRYPT_TESTS) \
 xmalloctest \
 timertest \
 shutdowntest \
 statetest \
 crctest \
 tcpiotest \
 hostkeytest \
 symciphertest \
 statuscallstest \
 storagetest \
 crontest \
 configtest \
 bloomtest \
 hashtest \
 semaphoretest \
 weakkeytest

TESTS = $(check_PROGRAMS)

xmalloctest_SOURCES = \
 xmalloctest.c 

statetest_SOURCES = \
 statetest.c

shutdowntest_SOURCES = \
 shutdowntest.c

timertest_SOURCES = \
 timertest.c

tcpiotest_SOURCES = \
 tcpiotest.c

crctest_SOURCES = \
 crctest.c

configtest_SOURCES = \
 configtest.c

crontest_SOURCES = \
 crontest.c

hostkeytest_SOURCES = \
 hostkeytest.c

hashtest_SOURCES = \
 hashtest.c

storagetest_SOURCES = \
 storagetest.c

statuscallstest_SOURCES = \
 statuscallstest.c

symciphertest_SOURCES = \
 symciphertest.c

semaphoretest_SOURCES = \
 semaphoretest.c

weakkeytest_SOURCES = \
 weakkeytest.c

if USE_OPENSSL
if USE_GCRYPT
cry_comp_SOURCES = \
 hk_gcrypt.h \
 hk_gcrypt.c \
 hk_crypto.h \
 hk_crypto.c \
 cry_comp.c 
cry_comp_LDADD = -lcrypto -lgcrypt $(LDADD)
endif
endif

bloomtest_SOURCES = \
 bloomtest.c
