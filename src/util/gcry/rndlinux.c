/* rndlinux.c  -  raw random number for OSes with /dev/random
 * Copyright (C) 1998, 2001, 2002, 2003  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "platform.h"
#include <assert.h>
#include "types.h"

int
rndlinux_gather_random(void (*add)(const void*, size_t, int), 
		       int requester,
		       size_t length, int level ) {
    int fd;
    int n;
    byte buffer[768];

    fd = open(NAME_OF_DEV_RANDOM, O_RDONLY);
    if (fd == -1) {
      fprintf(stderr, 
	      "FATAL: can't open %s: %s\n", 
	      NAME_OF_DEV_RANDOM, 
	      strerror(errno) );
      exit(-1);
    }
    while ( length ) {
	do {
	    int nbytes = length < sizeof(buffer) ? length : sizeof(buffer);
	    n = read(fd, buffer, nbytes );
	    if( n >= 0 && n > nbytes ) {
	      fprintf(stderr, 
		      "bogus read from random device (n=%d)\n", n );
		n = nbytes;
	    }
	} while( n == -1 && errno == EINTR );
	if ( n == -1 ) {
	  fprintf(stderr, 
		  "read error on random device: %s\n", 
		  strerror(errno));
	  exit(-1);
	}
	(*add)( buffer, n, requester );
	length -= n;
    }
    close(fd);

    return 0; /* success */
}
