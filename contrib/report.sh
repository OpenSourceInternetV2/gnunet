#!/bin/sh

TEST=`type type|grep not`
if test -n "$TEST"; then
  WHICH=which
else
  WHICH=type
fi

echo "On some systems, you may need to change /bin/sh to point to bash"
echo
echo "Please submit the following information with your bug report: "
echo "--------------------------------------------------------------"
OS=`uname -s 2>/dev/null`
echo "OS             : $OS" 
REL=`uname -r 2>/dev/null`
echo "OS RELEASE     : $REL"
HW=`uname -m 2>/dev/null`
echo "HARDWARE       : $HW"

TEST=`$WHICH openssl 2>/dev/null`
if test -n "$TEST"; then
  VERS=`openssl version 2>/dev/null | sed -e "s/OpenSSL //"`
  echo "OpenSSL Version: $VERS"
else
  echo "OpenSSL Version: Not Found"
fi

TEST=`$WHICH gcc 2>/dev/null`
if test -n "$TEST"; then
  VERS=`gcc --version 2>/dev/null | head -n 1`
  echo "gcc version    : $VERS"
else
  echo "gcc version    : Not Found";
fi

TEST=`$WHICH gmake 2>/dev/null`
if test -n "$TEST" ; then
	gmake --version 2>/dev/null |\
		awk -F, '{print $1}' |\
		awk '/GNU Make/{print "Gnu gmake      :",$NF}'
else
  TEST=`make --version 2>/dev/null`
  if test -n "$TEST"; then
		make --version 2>/dev/null |\
			awk -F, '{print $1}' |\
			awk '/GNU Make/{print "Gnu make       :",$NF}'
  else
		echo "Gnu Make       : Not Found"
  fi
fi

TEST=`$WHICH autoconf 2>/dev/null`
if test -n "$TEST"; then
  autoconf --version |\
    head -1 |\
    awk '{\
	if (length($4) == 0) {\
		print "autoconf       : "$3\
	} else {\
		print "autoconf       : "$4\
	}}'
else
  echo "autoconf       : Not Found"
fi

TEST=`$WHICH automake 2>/dev/null`
if test -n "$TEST"; then
  automake --version 2>/dev/null |\
    head -1 |\
    awk '{print "automake       : "$4}'
else
  echo "automake       : Not Found"
fi

TEST=`$WHICH libtool 2>/dev/null`
if test -n "$TEST"; then
  libtool --version 2>/dev/null |\
    head -1 |\
    awk '{print "libtool        : "$4}'
else
  echo "libtool        : Not Found"
fi

TEST=`$WHICH extract 2>/dev/null`
if test -n "$TEST"; then
  extract -v 2>/dev/null |\
    head -1 |\
    awk '{print "libextractor   : "$2}'
else
  echo "libextractor   : Not Found"
fi

TEST=`$WHICH gnunetd 2>/dev/null`
if test -n "$TEST"; then
  gnunetd -v 2>/dev/null |\
    awk '{print "GNUnet         : "$2}'
else
  echo "GNUnet         : Not Found"
fi

TEST=`$WHICH libgcrypt-config 2> /dev/null`
if test -n "$TEST"; then
  libgcrypt-config --version 2> /dev/null | \
    awk '{print "libgcrypt      : "$1}'
else
   echo 'libgcrypt     : Not Found'
fi

TEST=`$WHICH mysql_config 2> /dev/null`
if test -n "$TEST"; then
  mysql_config --version 2> /dev/null | \
    awk '{print "mysql          : "$1}'
else
   echo 'mysql         : Not Found'
fi

echo "--------------------------------------------------------------"
