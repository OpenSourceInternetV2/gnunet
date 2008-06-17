/*
     This file is part of GNUnet

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
 * @file src/applications/afs/gtkui/about.c
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * This file contains the about dialog.
 **/

#include "gnunet_afs_esed2.h"

#include "helper.h"
#include "about.h"

#define ABOUT_STRING "\nGNUnet "\
  VERSION\
  ", gnunet-gtk "\
  AFS_VERSION\
  "\n\n\n"\
  "GNUnet is free software, released under GNU General Public License version 2."\
  "\n\n\n"\
  "For more information, visit the GNUnet homepage at \n\n"\
  "http://www.ovmj.org/GNUnet/\n"


/**
 * This displays an about window
 **/
void about(GtkWidget *dummy,
	   gpointer data) {
  GtkWidget * window;
  GtkWidget * box1;
  GtkWidget * table;
  GtkWidget * text;
  GtkWidget * button;

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_signal_connect(GTK_OBJECT(window), 
                     "delete_event",
                     GTK_SIGNAL_FUNC(deleteEvent), 
		     NULL);
 
  gtk_window_set_title(GTK_WINDOW(window), 
		       "About gnunet-gtk");
  gtk_widget_set_usize(GTK_WIDGET(window), 
		       600, 
		       300);

  box1 = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER (window), 
		    box1);
  gtk_widget_show(box1);

  table = gtk_table_new(2, 2, FALSE);
  gtk_table_set_row_spacing(GTK_TABLE (table), 
			    0,
			    2);
  gtk_table_set_col_spacing(GTK_TABLE (table), 
			    0, 
			    2);
  gtk_box_pack_start(GTK_BOX (box1), 
		     table, 
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(table);

  /* create a text widget */
  text = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT (text), 
			FALSE);
  gtk_table_attach(GTK_TABLE (table), 
		   text,
		   0, 
		   1, 
		   0, 
		   1,
		   GTK_EXPAND | GTK_SHRINK | GTK_FILL,
		   GTK_EXPAND | GTK_SHRINK | GTK_FILL,
		   0, 0);
  gtk_widget_show(text);
  gtk_widget_realize(text);

  /* write some about text */
  gtk_text_freeze(GTK_TEXT (text));

  gtk_text_insert(GTK_TEXT(text), 
		  NULL, 
		  &text->style->black, 
		  NULL,
		  ABOUT_STRING, -1); 
  
  gtk_text_thaw(GTK_TEXT(text));

  /* finish with a close button */
  button = gtk_button_new_with_label("Right");
  gtk_box_pack_start(GTK_BOX (box1), 
		     button, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button), 
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget), 
		     window);
  gtk_widget_show(button);
  gtk_widget_show(window);
}

/* end of about.c */
