/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/tcp_return.c
 * @brief code to communicate simple (int) return values via reliable
 *        TCP stream
 * @author Christian Grothoff
 *
 * Helper methods to send and receive return values over a TCP stream
 * that has tcpio (see util/tcpio.c) semantics.
 **/

#include "gnunet_util.h"
#include "platform.h"

/**
 * Obtain a return value from a remote call from TCP.
 *
 * @param sock the TCP socket 
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was read
 * successfully
 **/
int readTCPResult(GNUNET_TCP_SOCKET * sock,
		  int * ret) {
  CS_RETURN_VALUE * rv;
  
  rv = NULL;
  if (SYSERR == readFromSocket(sock,
			       (CS_HEADER **) &rv)) { 
    LOG(LOG_WARNING,
	"WARNING: readTCPResult failed, server closed connection\n");
    return SYSERR;
  }
  if ( (ntohs(rv->header.size) != sizeof(CS_RETURN_VALUE)) ||
       (ntohs(rv->header.tcpType) != CS_PROTO_RETURN_VALUE) ) {
    LOG(LOG_WARNING,
	"WARNING: readTCPResult failed, reply invalid (%d, %d)\n",
	ntohs(rv->header.size),
	ntohs(rv->header.tcpType));
    FREE(rv);
    return SYSERR;
  }
  *ret = ntohl(rv->return_value);
  FREE(rv);
  return OK;
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 **/
int sendTCPResult(GNUNET_TCP_SOCKET * sock,
		  int ret) {
  CS_RETURN_VALUE rv;
  
  rv.header.size 
    = htons(sizeof(CS_RETURN_VALUE));
  rv.header.tcpType 
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value 
    = htonl(ret);
  return writeToSocket(sock,
		       &rv.header);
}


/**
 * Obtain option from a peer.
 * @return NULL on error
 **/   
char * getConfigurationOptionValue(GNUNET_TCP_SOCKET * sock,
				   char * section,
				   char * option) {
  CS_GET_OPTION_REQUEST req;
  CS_GET_OPTION_REPLY * reply;
  int res;
  char * ret;
  
  memset(&req,
	 0,
	 sizeof(CS_GET_OPTION_REQUEST));
  req.header.tcpType = htons(CS_PROTO_GET_OPTION_REQUEST);
  req.header.size = htons(sizeof(CS_GET_OPTION_REQUEST));
  if ( (strlen(section) >= CS_GET_OPTION_REQUEST_OPT_LEN) ||
       (strlen(option) >= CS_GET_OPTION_REQUEST_OPT_LEN) ) 
    return NULL;
  strcpy(&req.section[0],
	 section);
  strcpy(&req.option[0],
	 option);
  res = writeToSocket(sock,
		      &req.header);
  if (res != OK) 
    return NULL;
  reply = NULL;
  res = readFromSocket(sock,
		       (CS_HEADER**)&reply);
  if (res != OK) 
    return NULL;
  ret = MALLOC(ntohs(reply->header.size) - sizeof(CS_HEADER) + 1);
  memcpy(ret,
	 &reply->value[0],
	 ntohs(reply->header.size) - sizeof(CS_HEADER));
  ret[ntohs(reply->header.size) - sizeof(CS_HEADER)] = '\0';
  FREE(reply);
  return ret;
}



/* end of tcp_return.c */
