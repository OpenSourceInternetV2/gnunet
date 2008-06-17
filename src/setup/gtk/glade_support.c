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

#include "platform.h"
#include "gnunet_util.h"
#include "glade_support.h"

/**
 * Handle to the dynamic library (which contains this code)
 */
static struct GNUNET_PluginHandle *library;

/**
 * Current glade handle.
 */
static GladeXML *mainXML_;

GladeXML *
GNUNET_GTK_get_main_glade_XML ()
{
  return mainXML_;
}

void
destroyMainXML ()
{
  GNUNET_GE_ASSERT (NULL, mainXML_ != NULL);
  g_object_unref (mainXML_);
  mainXML_ = NULL;
}

char *
get_glade_filename ()
{
  char *path;
  char *gladeFile;

  path = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  gladeFile = GNUNET_malloc (strlen (path) + 20);
  strcpy (gladeFile, path);
  strcat (gladeFile, "gnunet-setup.glade");
  GNUNET_free (path);
  return gladeFile;
}


static void
connector (const gchar * handler_name,
           GObject * object,
           const gchar * signal_name,
           const gchar * signal_data,
           GObject * connect_object, gboolean after, gpointer user_data)
{
  GladeXML *xml = user_data;
  void *method;

  GNUNET_GE_ASSERT (NULL, xml != NULL);
  method = GNUNET_plugin_resolve_function (library, handler_name, GNUNET_YES);
  if (method == NULL)
    return;
  glade_xml_signal_connect (xml, handler_name, (GCallback) method);
}

GladeXML *
load_xml (const char *dialog_name)
{
  char *gladeFile;
  GladeXML *ret;

  gladeFile = get_glade_filename ();
  ret = glade_xml_new (gladeFile, dialog_name, PACKAGE_NAME);
  if (ret == NULL)
    GNUNET_GE_DIE_STRERROR_FILE (NULL,
                                 GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                 GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE,
                                 "open", gladeFile);
  GNUNET_free (gladeFile);
  glade_xml_signal_autoconnect_full (ret, &connector, ret);
  return ret;
}

GtkWidget *
lookup_widget (const char *name)
{
  return glade_xml_get_widget (mainXML_, name);
}

GtkWidget *
get_xml (const char *dialog_name)
{
  mainXML_ = load_xml (dialog_name);
  return glade_xml_get_widget (mainXML_, dialog_name);
}

/**
 * Helper function to just show a simple dialog
 * that requires no initialization.
 */
void
showDialog (const char *name)
{
  GtkWidget *msgSave;
  char *gladeFile;
  GladeXML *myXML;

  gladeFile = get_glade_filename ();
  myXML = glade_xml_new (gladeFile, name, PACKAGE_NAME);
  if (mainXML_ == NULL)
    GNUNET_GE_DIE_STRERROR_FILE (NULL,
                                 GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                 GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE,
                                 "open", gladeFile);
  GNUNET_free (gladeFile);
  glade_xml_signal_autoconnect_full (myXML, &connector, myXML);
  msgSave = glade_xml_get_widget (myXML, name);
  gtk_widget_show (msgSave);
  g_object_unref (myXML);
}

void
setLibrary (struct GNUNET_PluginHandle *lib)
{
  library = lib;
}
