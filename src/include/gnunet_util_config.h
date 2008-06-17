/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_config.h
 * @brief configuration API
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_CONFIG_H
#define GNUNET_UTIL_CONFIG_H

#include "gnunet_util_error.h"

#define GNUNET_CONFIG_VERSION 0x00000000

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GNUNET_GC_Configuration;

void GNUNET_GC_free (struct GNUNET_GC_Configuration *cfg);

/**
 * Set the context for reporting configuration IO errors
 * (and errors reported by configuration change notification
 * callbacks when reading a new configuration).
 *
 * Note that for setting options a different context can be
 * used (since failing to change an option may have to be reported
 * in a fundamentally different way to the user).
 *
 * @param ectx may be NULL, in that case errors will no longer
 *        be reported
 */
void GNUNET_GC_set_error_context (struct GNUNET_GC_Configuration *cfg,
                                  struct GNUNET_GE_Context *ectx);

/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 * @return 0 on success, -1 on error
 */
int GNUNET_GC_parse_configuration (struct GNUNET_GC_Configuration *cfg,
                                   const char *filename);

/**
 * Test if there are configuration options that were
 * changed since the last save.
 * @return 0 if clean, 1 if dirty, -1 on error (i.e. last save failed)
 */
int GNUNET_GC_test_dirty (struct GNUNET_GC_Configuration *cfg);

/**
 * Write configuration file.
 * @return 0 on success, -1 on error
 */
int GNUNET_GC_write_configuration (struct GNUNET_GC_Configuration *cfg,
                                   const char *filename);

/**
 * Get a configuration value that should be a number.
 * @param min minimal legal value
 * @param max maximal legal value
 * @param default default value (use indicated by return value)
 * @return 0 on success, -1 on error, 1 for default
 */
int GNUNET_GC_get_configuration_value_number (struct GNUNET_GC_Configuration
                                              *cfg, const char *section,
                                              const char *option,
                                              unsigned long long min,
                                              unsigned long long max,
                                              unsigned long long def,
                                              unsigned long long *number);

/**
 * Test if we have a value for a particular option
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int GNUNET_GC_have_configuration_value (struct GNUNET_GC_Configuration *cfg,
                                        const char *section,
                                        const char *option);

/**
 * Get a configuration value that should be a string.
 * @param default default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL)
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int GNUNET_GC_get_configuration_value_string (struct GNUNET_GC_Configuration
                                              *cfg, const char *section,
                                              const char *option,
                                              const char *def, char **value);

/**
 * Get a configuration value that should be the name of a file
 * or directory.
 *
 * @param default default value (use indicated by return value;
 *        will NOT be aliased, may NOT be NULL)
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int GNUNET_GC_get_configuration_value_filename (struct GNUNET_GC_Configuration
                                                *cfg, const char *section,
                                                const char *option,
                                                const char *def,
                                                char **value);

/**
 * Get a configuration value that should be in a set of
 * predefined strings
 *
 * @param choices NULL-terminated list of legal values
 * @param default default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL), must be reference
 *        into set given by choices
 * @param value will be set to an entry in the legal list,
 *        or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int GNUNET_GC_get_configuration_value_choice (struct GNUNET_GC_Configuration
                                              *cfg, const char *section,
                                              const char *option,
                                              const char **choices,
                                              const char *def,
                                              const char **value);

/**
 * Get a configuration value that should be in a set of
 * "GNUNET_YES" or "GNUNET_NO".
 *
 * @param def default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL)
 * @return GNUNET_YES, GNUNET_NO or GNUNET_SYSERR
 */
int GNUNET_GC_get_configuration_value_yesno (struct GNUNET_GC_Configuration
                                             *cfg, const char *section,
                                             const char *option, int def);

/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment
 * "FOO" is set to "DIRECTORY".

 * @param old string to $-expand (will be freed!)
 * @return $-expanded string
 */
char *GNUNET_GC_configuration_expand_dollar (struct GNUNET_GC_Configuration
                                             *cfg, char *old);

/**
 * Set a configuration value that should be a number.
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GNUNET_GC_set_configuration_value_number (struct GNUNET_GC_Configuration
                                              *cfg,
                                              struct GNUNET_GE_Context *ectx,
                                              const char *section,
                                              const char *option,
                                              unsigned long long number);


/**
 * Set a configuration value that should be a string.
 * @param value
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GNUNET_GC_set_configuration_value_string (struct GNUNET_GC_Configuration
                                              *cfg,
                                              struct GNUNET_GE_Context *ectx,
                                              const char *section,
                                              const char *option,
                                              const char *value);

/**
 * Set a configuration value that should be in a set of
 * predefined strings.
 * @param value
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GNUNET_GC_set_configuration_value_choice (struct GNUNET_GC_Configuration
                                              *cfg,
                                              struct GNUNET_GE_Context *ectx,
                                              const char *section,
                                              const char *option,
                                              const char *choice);

/**
 * Callback function that is called if a configuration option
 * changes.  Note that the new value is not explicitly
 * communicated, the client must query it.
 *
 * @param ectx context to log errors to
 * @return 0 if the change is ok, -1 if the change must be
 *         refused
 */
typedef int (*GNUNET_GC_ChangeListener) (void *ctx,
                                         struct GNUNET_GC_Configuration * cfg,
                                         struct GNUNET_GE_Context * ectx,
                                         const char *section,
                                         const char *option);

/**
 * Attach a callback that is notified whenever a
 * configuration option changes.<p>
 *
 * @return 0 on success, -1 on error
 */
int GNUNET_GC_attach_change_listener (struct GNUNET_GC_Configuration *cfg,
                                      GNUNET_GC_ChangeListener callback,
                                      void *ctx);

/**
 * Attach a callback that is notified whenever a
 * configuration option changes.
 * @return 0 on success, -1 on error, 1 for no such handler registered
 */
int GNUNET_GC_detach_change_listener (struct GNUNET_GC_Configuration *cfg,
                                      GNUNET_GC_ChangeListener callback,
                                      void *ctx);

/**
 * Create a GNUNET_GC_Configuration
 */
struct GNUNET_GC_Configuration *GNUNET_GC_create (void);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
