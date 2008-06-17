# Makefile for cipher modules
# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# Process this file with automake to produce Makefile.in

SUBDIRS = mpi .

INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libcipher.la

libcipher_la_LIBADD = \
 $(top_builddir)/src/util/gcry/mpi/libmpi.la

if USE_RNDLINUX
  tmprndlinux = rndlinux.c
endif
if USE_RNDUNIX
  tmprndunix = rndunix.c
endif
if USE_RNDEGD
  tmprndegd = rndegd.c
endif
if USE_RNDW32
  tmprndw32 = rndw32.c
endif

random = \
$(tmprndlinux) \
$(tmprndunix) \
$(tmprndegd) \
$(tmprndw32)

libcipher_la_SOURCES = \
 ath.c \
 random.c \
 $(random) \
 blowfish.c \
 primegen.c \
 rsa.c \
 rmd160.c \
 rsa.h \
 blowfish.h \
 gcrypt.h \
 types.h \
 g10lib.h \
 rmd.h \
 ath.h \
 random.h\
 rand-internal.h \
 bithelp.h

check_PROGRAMS = \
 testrsa
 
TESTS = $(check_PROGRAMS)

testrsa_SOURCES = \
 testrsa.c 

testrsa_LDADD = \
 $(top_builddir)/src/util/gcry/libcipher.la
