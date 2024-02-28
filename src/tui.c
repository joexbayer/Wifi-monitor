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

#include <ncurses.h>

/* ... [Other code and function declarations] ... */

#include <ncurses.h>

/* ... [Other code and function declarations] ... */

static void tui_monitor_access_point(struct monitor *monitor, int selected_network, int selected_ap) {
    int ret;
    struct access_point *ap = &monitor->networks[selected_network]->ap_list.aps[selected_ap];
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x); // Get screen size

    // Create a window for the header
    WINDOW *header_win = newwin(1, max_x, 0, 0); // 1 line high, full width
    // Create a window for the packet data
    WINDOW *data_win = newwin(max_y - 1, max_x, 1, 0); // Rest of the screen

    // Configure the packet data window for scrolling
    scrollok(data_win, TRUE);

    // Print header in the header window
    wprintw(header_win, "SSID: %s, ", monitor->networks[selected_network]->ssid);
    wprintw(header_win, "BSSID: %02x:%02x:%02x:%02x:%02x:%02x, ", 
        ap->bssid[0], ap->bssid[1], ap->bssid[2], 
        ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    wprintw(header_win, "Ch: %d, ", ap->channel);
    wprintw(header_win, "Signal: %d dBm, ", ap->signal_strength);
    wprintw(header_win, "Beacon: %d ms, ", ap->beacon_interval);
    wprintw(header_win, "Cap: %d, ", ap->capability_info);
    wprintw(header_win, "Hash: %d, ", ap->hash);
    wprintw(header_win, "Retries: %ld, ", ap->stats.retries);
    wprintw(header_win, "Failed: %ld, ", ap->stats.failed);
    wprintw(header_win, "Frames: %ld", ap->stats.frames);
    wrefresh(header_win);  // Refresh header window

    timeout(1);

    while(1) {
        struct packet packet;
        ret = packet_queue_pop(&ap->packets, &packet);
        if (ret == 0) {
            wprintw(data_win, "\nPacket: Length %zu, Sender Addr: %02x:%02x:%02x:%02x:%02x:%02x", 
                packet.length,
                packet.header.addr2[0], packet.header.addr2[1], packet.header.addr2[2], 
                packet.header.addr2[3], packet.header.addr2[4], packet.header.addr2[5]);
            wrefresh(data_win); // Refresh data window
        }

        int ch = getch();
        if (ch != ERR) { // Check if a key was pressed
            if (ch == 'q') {
                monitor->mode = MONITOR_SCAN_DISCOVERY;
                timeout(500);
                delwin(header_win); // Delete the header window
                delwin(data_win); // Delete the data window
                return; // Exit the loop
            }
        }
    }
}



static void display_access_points(struct monitor* monitor, int selected_network, int selected_ap) {
   clear();  // Clear the screen

    // Print table header
    printw("%-17s %-15s %-10s %-18s %-18s\n", "BSSID", "Signal Strength", "Channel", "Frames Received", "Retries");

    // Loop through access points and print their information
    for (int i = 0; i < monitor->networks[selected_network]->ap_list.size; i++) {

        if (i == selected_ap) {
            attron(A_REVERSE);  // Highlight selected network
        }

        // Get access point data
        struct access_point *ap = &monitor->networks[selected_network]->ap_list.aps[i];

        // Print BSSID, Signal Strength, Channel, and Frames
        printw("%02x:%02x:%02x:%02x:%02x:%02x  ", ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5]); 
        printw("%-15d %-10d %-18ld %-18ld\n", ap->signal_strength, ap->channel, ap->stats.frames, ap->stats.retries);

        attroff(A_REVERSE);  // Remove highlight
    }

    refresh();  // Print it on to the real screen

}

static void tui_access_points(struct monitor *monitor, int selected_network) {
    int selected_ap = 0;
    while(1){
        display_access_points(monitor, selected_network, selected_ap);
        int ch = getch();

        /* TOOD: Convert to switch */
        if (ch != ERR) { // Check if a key was pressed
            if(ch == KEY_UP){
                if (selected_ap > 0) selected_ap--;
            } else if(ch == KEY_DOWN){
                if (selected_ap < monitor->networks[selected_network]->ap_list.size - 1) selected_ap++;
            } else if(ch == '\n'){
                monitor->selected_network = selected_network;
                monitor->selected_access_point = selected_ap;
                monitor->mode = MONITOR_SCAN_ACCESS_POINT;
                tui_monitor_access_point(monitor, selected_network, selected_ap);
            } else if(ch == 'q'){
                break;
            }
        }
    }
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

    thread_create_status = pthread_create(&thread, NULL, monitor_thread_loop, (void *) &monitor);
    
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
                    tui_access_points(&monitor, selected_network);
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
