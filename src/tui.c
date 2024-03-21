#include <ncurses.h>
#include <string.h>

#include <timeline.h>

#include <monitor.h>
#include <log.h>
#include <wifi.h>
#include <error.h>
#include <db.h>

#include <pthread.h>


#define MAX_ROWS 5

static struct db hostdb;
static const char* modes [] = {
    "MONITOR_SCAN_DISCOVERY",
    "MONITOR_SCAN_ACCESS_POINT",
    "MONITOR_SCAN_NETWORK",
    "MONITOR_ACT_ACCESS_POINT"
};

/* Function to initialize ncurses */
static void init_ncurses() {
    initscr();            
    cbreak();             
    noecho();             
    keypad(stdscr, TRUE); 
}

static void tui_display_monitor_stats(struct monitor *monitor) {
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    move(max_y - 1, 0);
    clrtoeol();
    printw("Channel: %d, Interval: %d, Mode: %s", monitor->channel, monitor->interval, modes[monitor->mode]);
    refresh();
}

static void tui_monitor_access_point(struct monitor *monitor, int selected_network, int selected_ap) {
    int ret;
    int max_y, max_x;
    struct access_point *ap = &monitor->networks[selected_network]->ap_list.aps[selected_ap];

    getmaxyx(stdscr, max_y, max_x); 
    WINDOW *header_win = newwin(1, max_x, 0, 0); 
    WINDOW *data_win = newwin(max_y - 1, max_x, 1, 0); 
    
    scrollok(data_win, TRUE);
    
    wprintw(header_win, "SSID: %s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x, Ch: %d, Signal: %d dBm, Beacon: %d ms", 
        monitor->networks[selected_network]->ssid, 
        ap->bssid[0], ap->bssid[1], ap->bssid[2], 
        ap->bssid[3], ap->bssid[4], ap->bssid[5], 
        ap->channel, ap->signal_strength, ap->beacon_interval
    );
    wrefresh(header_win);  

    timeout(75);

    char name[32];
    int packet_count = 0;
    struct packet packet;
    struct packet_history history;
    init_packet_history(&history);
    while (1){
        werase(data_win);

        int row = 0;
        for (int i = 0; i < ap->assoc_list.size; i++) {
            struct association *assoc = &ap->assoc_list.associations[i];
            memset(name, 0, 32);
            db_find(&hostdb, hash(assoc->addr), name);
            
            wprintw(data_win, "Client: %02x:%02x:%02x:%02x:%02x:%02x, Cap: %d, Status: %d, Assoc ID: %d, Retries: %d, Failed: %d, Frames: %d, %s\n", 
                assoc->addr[0], assoc->addr[1], assoc->addr[2], 
                assoc->addr[3], assoc->addr[4], assoc->addr[5], 
                assoc->capability_info, 
                assoc->status_code, 
                assoc->association_id, 
                assoc->retries, 
                assoc->failed, 
                assoc->frames,
                name
            );
            row += 1;
        }
        mvwhline(data_win, row + 1, 0, '.', 80);
       
        int new_packets = 0;
        while (packet_queue_pop(&ap->packets, &packet) == 0) {
            new_packets++;
        }
        add_packet_to_history(&history, new_packets);

        start_color();
        init_pair(1, COLOR_GREEN, COLOR_BLACK); 
        init_pair(2, COLOR_BLACK, COLOR_BLACK); 

        for (int i = 0; i < TIMELINE_LENGTH; i++) {
            int color_pair = history.data[i] == 0? 2 : 1;
            mvwaddch(data_win, row, i, '*' | COLOR_PAIR(color_pair));
        }
        wrefresh(data_win); 

        tui_display_monitor_stats(monitor);

        int ch = getch();
        if (ch != ERR) { 
            if (ch == 'q') {
                monitor->mode = MONITOR_SCAN_NETWORK;
                timeout(500);
                delwin(header_win);
                delwin(data_win);
                return;
            }
        }
    }
}

static void tui_display_access_points(struct monitor* monitor, int selected_network, int selected_ap) {
    clear();  
    start_color();
    init_pair(1, COLOR_RED, COLOR_BLACK);    
    init_pair(2, COLOR_YELLOW, COLOR_BLACK); 
    init_pair(3, COLOR_GREEN, COLOR_BLACK);  

    printw("%-17s %-15s %-10s %-18s %-10s %-15s %-18s %-18s\n", 
        "BSSID", "Signal Strength", "Channel", "Frames Received",
        "Retries", "Clients", "Disassociations", "Deauthentications"
    );

    for (int i = 0; i < monitor->networks[selected_network]->ap_list.size; i++) {
        if (i == selected_ap) {
            attron(A_REVERSE);  
        }

        struct access_point *ap = &monitor->networks[selected_network]->ap_list.aps[i];
        printw("%02x:%02x:%02x:%02x:%02x:%02x  ", 
            ap->bssid[0], ap->bssid[1], ap->bssid[2], 
            ap->bssid[3], ap->bssid[4], ap->bssid[5]
        );

        if (ap->signal_strength > -50) {
            attron(COLOR_PAIR(3)); 
        } else if (ap->signal_strength > -70) {
            attron(COLOR_PAIR(2)); 
        } else {
            attron(COLOR_PAIR(1)); 
        }
        printw("%-15d", ap->signal_strength);
        attroff(COLOR_PAIR(1) | COLOR_PAIR(2) | COLOR_PAIR(3)); 

        printw("%-10d %-18ld %-10ld %-15ld %-18ld %-18ld\n", 
            ap->channel, ap->stats.frames, ap->stats.retries, 
            ap->assoc_list.size, ap->stats.disassociations,
            ap->stats.deauthentications
        );

        attroff(A_REVERSE);  
    }
    tui_display_monitor_stats(monitor);
    refresh();
}

static void tui_access_points(struct monitor *monitor, int selected_network) {
    int selected_ap = 0;
    monitor->interval = 25;

    monitor->mode = MONITOR_SCAN_NETWORK;
    monitor->selected_network = selected_network;

    while(1){
        tui_display_access_points(monitor, selected_network, selected_ap);
        int ch = getch();

        /* TOOD: Convert to switch */
        if (ch != ERR) { 
            if(ch == KEY_UP){
                if (selected_ap > 0) selected_ap--;
            } else if(ch == KEY_DOWN){
                if (selected_ap < monitor->networks[selected_network]->ap_list.size - 1) selected_ap++;
            } else if(ch == '\n'){
                monitor->selected_access_point = selected_ap;
                monitor->mode = MONITOR_SCAN_ACCESS_POINT;
                tui_monitor_access_point(monitor, selected_network, selected_ap);
            } else if(ch == 'q'){
                monitor->interval = 100;
                monitor->mode = MONITOR_SCAN_DISCOVERY;
                break;
            }
        }
    }
}

static void tui_find_client(struct monitor* monitor){
    char str[100]; 
    uint8_t addr[6];
    
    timeout(-1);
    echo();

    printw("Enter a MAC address: "); 
    getnstr(str, 17);
    str[17] = '\0';  

    noecho();

    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
    struct association* assoc = monitor_find_client(monitor, addr);
    if (assoc != NULL) {
        printw("Client found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            assoc->addr[0], assoc->addr[1], assoc->addr[2], 
            assoc->addr[3], assoc->addr[4], assoc->addr[5]
        );

        if (assoc->ap != NULL) {
            printw("Connected to AP SSID: %s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                assoc->ap->ssid, 
                assoc->ap->bssid[0], assoc->ap->bssid[1], assoc->ap->bssid[2], 
                assoc->ap->bssid[3], assoc->ap->bssid[4], assoc->ap->bssid[5]
            );
            printw("Signal Strength: %d dBm, Frames Sent: %ld\n", assoc->ap->signal_strength, assoc->frames);
        } else {
            printw("AP information not available\n");
        }
    } else {
        printw("Client not found\n");
    }

    getch(); 
    
    timeout(500);
}

static void display_networks(struct monitor *monitor, int selected_network) {
    clear();  
    for (int i = 0; i < MAX_NETWORKS; i++) {
        if (monitor->networks[i] != NULL) {
            if (i == selected_network) {
                attron(A_REVERSE);
            }
            printw("%s\n", monitor->networks[i]->ssid[0] == 0 ? "Hidden" : monitor->networks[i]->ssid);
            attroff(A_REVERSE);
        }
    }
    printw("Dissociations: %ld, Deauthentications: %ld\n", monitor->dissasociations, monitor->deauthentications);
    refresh();  
}

static int load_hostdb(struct db* hostdb, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        return -1;
    }

    char line[100];
    char name[32];
    char mac[18];
    while (fgets(line, sizeof(line), file)) {
        memset(name, 0, sizeof(name));
        memset(mac, 0, sizeof(mac));
        line[strcspn(line, "\n")] = 0; /* Remove newline character */

        if (sscanf(line, "%[^,],%s", name, mac) == 2) {
            printf("Name: %s, MAC Address: %s\n", name, mac);
            db_insert(hostdb, hash(mac), name); 
        } else {
            fprintf(stderr, "Invalid line format: %s\n", line);
        }
    }

    fclose(file);
    return 0;
}

static struct monitor monitor;

int main(int argc, char** argv) {
    if(argc < 2){
        logprintf(LOG_ERROR, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    init_ncurses(); 
    if(monitor_init(&monitor, argv[1]) != MON_ERR_OK){
        logprintf(LOG_ERROR, "Failed to initialize monitor\n");
        return 1;
    }
    db_init(&hostdb);

    load_hostdb(&hostdb, "data_parsed.csv");

    pthread_t thread;
    int ch;
    int thread_create_status;
    int selected_network = 0;

    thread_create_status = pthread_create(&thread, NULL, monitor_thread_loop, (void *) &monitor);
    
    timeout(500);
    while(1){
        display_networks(&monitor, selected_network);
         tui_display_monitor_stats(&monitor);
        ch = getch();
        if (ch != ERR) { 
            switch (ch) {
                case KEY_UP:
                    if (selected_network > 0) selected_network--;
                    break;
                case KEY_DOWN:
                    if (selected_network < MAX_NETWORKS - 1) selected_network++;
                    break;
                case '\n':  
                    tui_access_points(&monitor, selected_network);
                    break;
                case 'f':  
                    tui_find_client(&monitor);
                    break;
                case 'q':  
                    endwin();
                    return 0;
            }
        }
    }

    pthread_join(thread, NULL);
    monitor_free(&monitor);
    endwin(); 
    return 0;
}
