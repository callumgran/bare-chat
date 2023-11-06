#include <gtk/gtk.h>

typedef struct
{
        GSList *windows;
        
        /* etc... whatever application vars you need */
} MyApp;


void 
on_window_destroy (GtkWidget *widget, MyApp *app)
{
        app->windows = g_slist_remove (app->windows, widget);
        
        if (g_slist_length (app->windows) == 0)
        {
                /* last window was closed... exit */
                
                g_debug ("Exiting...");
                g_slist_free (app->windows);
                gtk_main_quit ();
        }
}

void
on_add_button_clicked (GtkWidget *widget, MyApp *app)
{
        GtkWidget *window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
        GtkWidget *button = gtk_button_new_from_stock (GTK_STOCK_ADD);
        gchar *title;
        
        /* add window to list */
        
        app->windows = g_slist_prepend (app->windows, window);
        
        /* setup window and pack a button into it */
        
        gtk_container_set_border_width (GTK_CONTAINER (window), 25);
        gtk_container_add (GTK_CONTAINER (window), button);
        title = g_strdup_printf ("Window %d", g_slist_length (app->windows));
        gtk_window_set_title (GTK_WINDOW (window), title);
        g_free (title);
        
        /* connect callbacks to signals */
        
        g_signal_connect (G_OBJECT (window), "destroy", 
                          G_CALLBACK (on_window_destroy), app);
        
        g_signal_connect (G_OBJECT (button), "clicked", 
                          G_CALLBACK (on_add_button_clicked), app);
                                       
        
        gtk_widget_show_all (window);     
}

int
main (int argc, char *argv[])
{
        MyApp *app;
        
        gtk_init (&argc, &argv);
        app = g_slice_new (MyApp);
        app->windows = NULL;
        
        /* create first window */
        on_add_button_clicked (NULL, app);
        
        gtk_main ();
        g_slice_free (MyApp, app);
        
        return 0;               
}