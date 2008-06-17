INCLUDES = -I$(top_srcdir)/src/include

bin_PROGRAMS = \
 gnunetd \
 gnunet-update \
 gnunet-peer-info \
 gnunet-transport-check



gnunetd_SOURCES = \
 connection.c \
 core.c \
 fragmentation.c \
 gnunetd.c \
 handler.c  \
 heloexchange.c  \
 keyservice.c \
 knownhosts.c \
 pingpong.c \
 policy.c \
 startup.c  \
 tcpserver.c  \
 traffic.c \
 transport.c \
 connection.h \
 core.h \
 fragmentation.h \
 handler.h \
 heloexchange.h \
 keyservice.h \
 knownhosts.h \
 pingpong.h \
 policy.h \
 startup.h \
 tcpserver.h \
 traffic.h \
 transport.h \
 httphelo.h \
 httphelo.c 

gnunetd_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la


gnunet_update_SOURCES = \
 gnunet-update.c 

gnunet_update_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la


gnunet_transport_check_SOURCES = \
 gnunet-transport-check.c \
 keyservice.c \
 keyservice.h \
 knownhosts.c \
 knownhosts.h \
 transport.c \
 transport.h \
 httphelo.h \
 httphelo.c 

gnunet_transport_check_LDADD  = \
 $(top_builddir)/src/util/libgnunetutil.la


gnunet_peer_info_SOURCES = \
 gnunet-peer-info.c \
 keyservice.c \
 knownhosts.c \
 transport.c

gnunet_peer_info_LDADD  = \
 $(top_builddir)/src/util/libgnunetutil.la



################################
# TESTCASES 
################################

check_PROGRAMS = \
 fragmentationtest

TESTS = $(check_PROGRAMS)

fragmentationtest_SOURCES = \
 fragmentationtest.c 
fragmentationtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

