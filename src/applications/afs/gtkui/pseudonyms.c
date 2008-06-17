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
 * @file src/applications/afs/gtkui/pseudonyms.c
 * @brief dialogs for creating and deleting pseudonyms
 * @author Christian Grothoff
 **/
#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "insertprogress.h"
#include "pseudonyms.h"
#include "main.h"

/**
 * @brief state of the CreatePseudonym window
 **/
typedef struct {
  GtkWidget * window;
  GtkWidget * pseudonymLine;
  GtkWidget * passwordLine;
} CreatePseudonymWindowModel;


/**
 * Collects the results of the assembly dialog, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 **/
static void create_ok(GtkWidget * dummy, 
		      CreatePseudonymWindowModel * ewm) {
  char * name;
  char * pass;
  Hostkey ps;
  
  name = gtk_entry_get_text(GTK_ENTRY(ewm->pseudonymLine));
  if (name == NULL) {
    guiMessage("WARNING: cowardly refusing to create pseudonym without name.\n");
    return;
  }
  name = STRDUP(name);
  pass = gtk_entry_get_text(GTK_ENTRY(ewm->passwordLine));
  if (pass != NULL) 
    pass = STRDUP(pass);
  gtk_widget_destroy(ewm->window);

  /* we may want to do this in another thread
     to keep the event manager running (and potentially
     even give feedback in the form of a popup window).
     After all, this can take a while... */
  ps = createPseudonym(name, pass);
  if (ps == NULL)
    guiMessage("WARNING: failed to create pseudonym (see logs).\n");
  else
    freeHostkey(ps);
  refreshMenuSensitivity();
  FREE(name);
  FREENONNULL(pass);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 **/
static void destroyPCWindow(GtkWidget * widget,
			    CreatePseudonymWindowModel * ewm) {
  FREE(ewm);
}


/**
 * Open a window to allow the user to create a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 **/
void openCreatePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2) {
  CreatePseudonymWindowModel * ewm;
  GtkWidget * vbox;
  GtkWidget * hbox;
  GtkWidget * label;
  GtkWidget * button_ok;
  GtkWidget * button_cancel;
  GtkWidget * separator;

  ewm = MALLOC(sizeof(CreatePseudonymWindowModel));
  /* create new window for editing */
  ewm->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_usize(GTK_WIDGET(ewm->window),
		       400,
		       120);
  gtk_window_set_title(GTK_WINDOW(ewm->window), 
		       "Create Pseudonym");

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(ewm->window),
		    vbox);
  gtk_widget_show(vbox);

  /* when user clicks on close box, always "destroy" */
  gtk_signal_connect(GTK_OBJECT(ewm->window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(deleteEvent),
		     ewm);
  /* whenever edit window gets destroyed, 
     free *ALL* ewm data */
  gtk_signal_connect(GTK_OBJECT(ewm->window),
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyPCWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(ewm->window), 
				 10);

  /* Create a line to change the pseudonym */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new("Pseudonym:");
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->pseudonymLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->pseudonymLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->pseudonymLine), 
		     "");
  gtk_widget_show(ewm->pseudonymLine);
  
  /* Create a line to change the description */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new("Password:");
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  
  ewm->passwordLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->passwordLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->passwordLine), 
		     "");
  gtk_widget_show(ewm->passwordLine);
  
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);

  /* add the insertion ok/cancel buttons */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox, 
		     FALSE, 
		     TRUE, 
		     0);
  gtk_widget_show(hbox);
  button_ok = gtk_button_new_with_label("Ok");
  button_cancel = gtk_button_new_with_label("Cancel");
  gtk_box_pack_start(GTK_BOX(hbox),
		     button_ok,
		     TRUE,
		     TRUE,
		     0);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_cancel, 
		     TRUE,
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_ok), 
		     "clicked",
		     GTK_SIGNAL_FUNC(create_ok),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     ewm->window);
  gtk_widget_show(button_ok);
  gtk_widget_show(button_cancel);

  /* all clear, show the window */
  gtk_widget_show(ewm->window);
}



/**
 * @brief state of the DeletePseudonym window
 **/
typedef struct {
  GtkWidget * window;
  char * selected;
  GtkWidget * pseudonymList;
} DeletePseudonymWindowModel;

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 **/
static void destroyDPWindow(GtkWidget * widget,
			    DeletePseudonymWindowModel * ewm) {
  FREE(ewm);
}

/**
 * The keyword delete button was clicked. Delete the 
 * currently selected pseudonym.
 *
 * @param w not used
 * @param ewm state of the edit window
 **/
static void button_del_clicked(GtkWidget * w, 
			       DeletePseudonymWindowModel * ewm) {
  GList * tmp;
  gchar * key[1];
  int row;
 
  tmp = GTK_CLIST(ewm->pseudonymList)->selection;
  if (NULL == tmp) {
    /* message that keyword must be selected to delete one? */
    return;
  }  
  row = (int) tmp->data;
  if (row < 0) 
    return; /* should never happen... */
  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->pseudonymList),
		     row,
		     0,
		     &key[0]);
  if (key[0] == NULL)
    return;
  if (OK != deletePseudonym(key[0]))
    guiMessage("WARNING: failed to delete pseudonym (see logs).\n");
  gtk_clist_remove(GTK_CLIST(ewm->pseudonymList),
		   row);
  refreshMenuSensitivity();
}

/**
 * Open a window to allow the user to delete a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 **/
void openDeletePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2) {
  DeletePseudonymWindowModel * ewm;
  GtkWidget * window;
  GtkWidget * vbox, * hbox;
  GtkWidget * clist;
  GtkWidget * scrolled_window;
  GtkWidget * button_delete;
  GtkWidget * button_cancel;
  gchar * titles[1] = { "Pseudonyms" };
  int i;
  int cnt;
  char ** list;

  ewm = MALLOC(sizeof(DeletePseudonymWindowModel));
  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->window = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       250,
		       300);
  gtk_window_set_title(GTK_WINDOW(window), 
		       "Delete Pseudonym");

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window),
		    vbox);
  gtk_widget_show(vbox);

  /* when user clicks on close box, always "destroy" */
  gtk_signal_connect(GTK_OBJECT(window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(deleteEvent),
		     ewm);
  /* whenever edit window gets destroyed, 
     free *ALL* ewm data */
  gtk_signal_connect(GTK_OBJECT(window),
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyDPWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  /* add a list of pseudonyms */
  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(vbox), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titles); 
  ewm->pseudonymList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);
  /* add the known RootNodes to the list */
  list = NULL;
  cnt = listPseudonyms(&list);
  if (cnt > 0) {
    gtk_clist_freeze(GTK_CLIST(clist));
    for (i=0;i<cnt;i++) {
      gtk_clist_append(GTK_CLIST(clist),
		       &list[i]);
      FREE(list[i]);
    }
    gtk_clist_thaw(GTK_CLIST(clist));
  }
  FREENONNULL(list);

  /* add the buttons to add and delete keywords */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  button_delete = gtk_button_new_with_label("Delete Pseudonym");
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_delete, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_del_clicked),
		     ewm);
  gtk_widget_show(button_delete);


  button_cancel = gtk_button_new_with_label("Cancel");
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_cancel, 
		     TRUE,
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_widget_show(button_cancel);

  /* all clear, show the window */
  gtk_widget_show(window);
}


/* end of pseudonyms.c */
