#include <ncurses.h>
#include <string.h>

#include <monitor.h>
#include <log.h>
#include <wifi.h>
#include <error.h>

#include <pthread.h>


#define MAX_ROWS 5

/* Function to initialize ncurses */
static void init_ncurses() {
    initscr();            // Start curses mode
    cbreak();             // Line buffering disabled
    noecho();             // Do not echo input
    keypad(stdscr, TRUE); // Enable function keys
}

static void display_access_points(struct monitor* monitor, int selected_network) {
    clear();  // Clear the screen
    for (int i = 0; i < monitor->networks[selected_network]->ap_list.size; i++) {
        /* print bssid, channel, signal etc */
        struct access_point *ap = &monitor->networks[selected_network]->ap_list.aps[i];
        printw("%x:%x:%x:%x:%x:%x: ", ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5]); 
        printw("%d dBm, %d\n", ap->signal_strength, ap->channel);
    }
    refresh();  // Print it on to the real screen
}

static void display_networks(struct monitor *monitor, int selected_network) {
    clear();  // Clear the screen
    for (int i = 0; i < MAX_NETWORKS; i++) {
        if (monitor->networks[i] != NULL) {
            if (i == selected_network) {
                attron(A_REVERSE);  // Highlight selected network
            }
            printw("%s\n", monitor->networks[i]->ssid[0] == 0 ? "Hidden" : monitor->networks[i]->ssid);
            attroff(A_REVERSE);  // Remove highlight
        }
    }
    refresh();  // Print it on to the real screen
}
static struct monitor monitor;

int main(int argc, char** argv) {
    if(argc < 2){
        logprintf(LOG_ERROR, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    init_ncurses(); // Initialize ncurses
    if(monitor_init(&monitor, argv[1]) != MON_ERR_OK){
        logprintf(LOG_ERROR, "Failed to initialize monitor\n");
        return 1;
    }

    pthread_t thread;
    int ch;
    int thread_create_status;
    int selected_network = 0;

    thread_create_status = pthread_create(&thread, NULL, monitor_recv_loop, (void *) &monitor);
    
    timeout(500);
    while(1){
        display_networks(&monitor, selected_network);
        ch = getch();
        if (ch != ERR) { // Check if a key was pressed
            switch (ch) {
                case KEY_UP:
                    if (selected_network > 0) selected_network--;
                    break;
                case KEY_DOWN:
                    if (selected_network < MAX_NETWORKS - 1) selected_network++;
                    break;
                case '\n':  // Enter key pressed
                    display_access_points(&monitor, selected_network);
                    while(1){
                        ch = getch();
                        if (ch != ERR) { // Check if a key was pressed
                            if(ch == 'q'){
                                break;
                            }
                        }

                    }
                    break;
                case 'q':  // Quit on 'q'
                    endwin();
                    return 0;
            }
        }
    }

    pthread_join(thread, NULL);
    monitor_free(&monitor);
    endwin(); // End curses mode
    return 0;
}
