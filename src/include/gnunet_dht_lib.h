/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dht_lib.h
 * @brief convenience API to the DHT infrastructure for use by clients
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_LIB_H
#define GNUNET_DHT_LIB_H

#include "gnunet_dht_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Opaque handle for asynchronous DHT get operation group.
 */
struct GNUNET_DHT_Context;

/**
 * Opaque handle for a DHT get request.
 */
struct GNUNET_DHT_GetRequest;

/**
 * Set up a context for performing asynchronous DHT operations.
 *
 * @param resultCallback function to call for results,
 *        the operation also aborts if the callback returns
 *        GNUNET_SYSERR
 * @return NULL on error
 */
struct GNUNET_DHT_Context *GNUNET_DHT_context_create (struct
                                                      GNUNET_GC_Configuration
                                                      *cfg,
                                                      struct GNUNET_GE_Context
                                                      *ectx,
                                                      GNUNET_ResultProcessor
                                                      resultCallback,
                                                      void
                                                      *resCallbackClosure);

/**
 * Start an asynchronous GET operation on the DHT looking for
 * key.
 *
 * @param type the type of key to look up
 * @param key the key to look up
 * @return NULL on error
 */
struct GNUNET_DHT_GetRequest *GNUNET_DHT_get_start (struct GNUNET_DHT_Context
                                                    *ctx, unsigned int type,
                                                    const GNUNET_HashCode *
                                                    key);

/**
 * Stop an asynchronous GET operation on the DHT looking for
 * key.
 *
 * @param handle request to stop
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DHT_get_stop (struct GNUNET_DHT_Context *ctx,
                         struct GNUNET_DHT_GetRequest *handle);

/**
 * Destroy a previously created context for DHT operations.
 *
 * @param ctx context to destroy
 * @return GNUNET_SYSERR on error
 */
int GNUNET_DHT_context_destroy (struct GNUNET_DHT_Context *ctx);

/**
 * Perform a synchronous put operation.
 *
 * @param key the key to store
 * @param value what to store
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DHT_put (struct GNUNET_GC_Configuration *cfg,
                    struct GNUNET_GE_Context *ectx,
                    const GNUNET_HashCode * key,
                    unsigned int type, unsigned int size, const char *value);



/**
 * Check if this peer has DHT connections to 
 * any other peer.
 *
 * @param sock connection to gnunetd
 * @return number of connections
 */
unsigned long long
GNUNET_DHT_test_connected(struct GNUNET_ClientServerConnection *sock);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_DHT_LIB_H */
