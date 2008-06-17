/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/handler.h
 * @brief Handlers for AFS related messages (CS and p2p).
 * @author Christian Grothoff
 **/
#ifndef AFS_HANDLER_H
#define AFS_HANDLER_H

#include "afs.h"

/**
 * Initialize the handler module. Registers counters
 * with the statistics module.
 *
 * @return OK on success, SYSERR on failure
 **/
int initAFSHandler();

/**
 * Handle query for content. Depending on how we like
 * the sender, lookup or even forward.
 **/
int handleQUERY(HostIdentity * sender, 
		 p2p_HEADER * msg);

/**
 * Receive content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to gproxy via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.  <p>
 **/
int handle3HASH_CONTENT(HostIdentity * sender,
			p2p_HEADER * msg);

/**
 * Receive CHK content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to gproxy via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.
 **/
int handleCHK_CONTENT(HostIdentity * sender,
		      p2p_HEADER * msg);

/**
 * Process a query from the client. Forwards to the network.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/ 
int csHandleRequestQuery(GNUNET_TCP_SOCKET * sock,
			 AFS_CS_QUERY * queryRequest);

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestInsertCHK(GNUNET_TCP_SOCKET * sock,
			     AFS_CS_INSERT_CHK * insertRequest);

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestInsert3HASH(GNUNET_TCP_SOCKET * sock,
			       AFS_CS_INSERT_3HASH * insertRequest);

/**
 * Process a request to index content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestIndexBlock(GNUNET_TCP_SOCKET * sock,
			      AFS_CS_INDEX_BLOCK * indexingRequest);
/**
 * Process a query to list a file as on-demand encoded from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestIndexFile(GNUNET_TCP_SOCKET * sock,
			     AFS_CS_INDEX_FILE * listFileRequest);

/**
 * Process a client request to extend our super-query bloom
 * filter.
 **/
int csHandleRequestIndexSuper(GNUNET_TCP_SOCKET * sock,
			      AFS_CS_INDEX_SUPER * superIndexRequest);

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestDeleteCHK(GNUNET_TCP_SOCKET * sock,
			     AFS_CS_INSERT_CHK * insertRequest);

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestDelete3HASH(GNUNET_TCP_SOCKET * sock,
			       AFS_CS_INSERT_3HASH * insertRequest);

/**
 * Process a request to index content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestUnindexBlock(GNUNET_TCP_SOCKET * sock,
				AFS_CS_INDEX_BLOCK * indexingRequest);
/**
 * Process a query to list a file as on-demand encoded from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 **/
int csHandleRequestUnindexFile(GNUNET_TCP_SOCKET * sock,
			       AFS_CS_INDEX_FILE * listFileRequest);

/**
 * Process a client request to extend our super-query bloom
 * filter.
 **/
int csHandleRequestUnindexSuper(GNUNET_TCP_SOCKET * sock,
				AFS_CS_INDEX_SUPER * superIndexRequest);

/**
 * Process a client request to upload a file (indexing).
 **/
int csHandleRequestUploadFile(GNUNET_TCP_SOCKET * sock,
			      AFS_CS_UPLOAD_FILE * uploadRequest);

/* ************* namespace specific handlers ******** */

int csHandleRequestInsertSBlock(GNUNET_TCP_SOCKET * sock,
				AFS_CS_INSERT_SBLOCK * insertRequest);

int csHandleRequestNSQuery(GNUNET_TCP_SOCKET * sock,
			   AFS_CS_NSQUERY * queryRequest);

int csHandleRequestLinkFile(ClientHandle sock,
			    AFS_CS_LINK_FILE * linkFileRequest);

int handleNSQUERY(HostIdentity * sender,
		  p2p_HEADER * msg);

int handleSBLOCK_CONTENT(HostIdentity * sender, 
			 p2p_HEADER * msg);


#endif
