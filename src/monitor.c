#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>  // For fcntl
#include <errno.h>  // For errno
#include <ncurses.h>

#include <monitor.h>
#include <wifi.h>
#include <error.h>
#include <log.h>


/* Global monitor */
static struct monitor monitor;

static int is_new_association(const struct access_point* ap, const uint8_t* mac_address) {
    for (size_t i = 0; i < ap->assoc_list.size; ++i) {
        if (memcmp(ap->assoc_list.associations[i].addr, mac_address, MAC_ADDRESS_LENGTH) == 0) {
            return 0; // Found, not a new association
        }
    }
    return 1; // Not found, new association
}

static void ap_add_association(struct access_point* ap, struct association* new_assoc) {
    if (ap->assoc_list.size == ap->assoc_list.capacity) {
        size_t new_capacity = ap->assoc_list.capacity == 0 ? 4 : ap->assoc_list.capacity * 2;
        struct association* new_associations = realloc(ap->assoc_list.associations, new_capacity * sizeof(struct association));
        if (!new_associations) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        ap->assoc_list.associations = new_associations;
        ap->assoc_list.capacity = new_capacity;
    }

    ap->assoc_list.associations[ap->assoc_list.size] = *new_assoc;
    ap->assoc_list.size++;
}

/**
 * @brief Check if the access point already exists in the list
 * Identifies using the BSSID
 * @param list list of access points
 * @param ap_info access point to check
 * @return int 1 if new access point, 0 if not
 */
static int is_new_access_point(const struct access_point_list* list, const struct access_point* ap_info) {
    for (size_t i = 0; i < list->size; ++i) {
        if (memcmp(list->aps[i].bssid, ap_info->bssid, MAC_ADDRESS_LENGTH) == 0) {
            return 0; // Found, not a new AP
        }
    }
    return 1; // Not found, new AP
}

/**
 * @brief Add an access point to the list
 * @param list list of access points
 * @param ap_info access point to add
 */
static void add_access_point(struct access_point_list* list, const struct access_point* ap_info) {
    if (list->size == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 4 : list->capacity * 2;
        struct access_point* new_aps = realloc(list->aps, new_capacity * sizeof(struct access_point));
        if (!new_aps) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        list->aps = new_aps;
        list->capacity = new_capacity;
    }

    list->aps[list->size] = *ap_info;
    list->size++;
}
/* Function to extract RSSI from Radiotap header */
static int get_rssi(const unsigned char* radiotap_header, int header_length) {
    if (header_length < 3) {
        return -100; // return a default low RSSI
    }

    int offset = 10; // Offset where RSSI is typically found
    if (offset + 1 > header_length) {
        return -100; // return default RSSI
    }

    int8_t rssi = (int8_t)radiotap_header[offset];
    return (int)rssi;
}

static struct wifi_network* monitor_new_network(char* ssid){
    struct wifi_network* network = malloc(sizeof(struct wifi_network));
    if(network == NULL){
        logprintf(LOG_ERROR, "Out of memory!");
        return NULL;
    }

    network->ap_list.aps = NULL;
    network->ap_list.size = 0;
    network->ap_list.capacity = 0;

    strcpy(network->ssid, ssid);

    return network;
}

static struct wifi_network* monitor_find_network(struct monitor* mon, char* ssid){
    for(int i = 0; i < MAX_NETWORKS; i++){
        if(mon->networks[i] != NULL && strcmp(mon->networks[i]->ssid, ssid) == 0){
            return mon->networks[i];
        }
    }
    return NULL;
}

static struct wifi_network* monitor_add_network(struct monitor* mon, char* ssid){
    struct wifi_network* network = monitor_find_network(mon, ssid);
    if(network != NULL){
        return network;
    }

    for(int i = 0; i < MAX_NETWORKS; i++){
        if(mon->networks[i] == NULL){
            mon->networks[i] = monitor_new_network(ssid);
            return mon->networks[i];
        }
    }
    return NULL; // No space for new network
}

static void monitor_free_network(struct wifi_network* network){
    free(network->ap_list.aps);
    free(network);
}

static void monitor_free_networks(struct monitor* mon){
    for(int i = 0; i < MAX_NETWORKS; i++){
        if(mon->networks[i] != NULL){
            monitor_free_network(mon->networks[i]);
        }
    }
}

static struct access_point* monitor_find_access_point(struct monitor* monitor, uint8_t* bssid){
    uint32_t bssid_hash = hash(bssid);
    for(int i = 0; i < MAX_NETWORKS; i++){
        if(monitor->networks[i] != NULL){
            for(int j = 0; j < monitor->networks[i]->ap_list.size; j++){
                if(bssid_hash == monitor->networks[i]->ap_list.aps[j].hash){
                    return &monitor->networks[i]->ap_list.aps[j];
                }
            }
        }
    }
    return NULL;
}   

void monitor_free(struct monitor* mon){
    monitor_free_networks(mon);
    close(mon->raw_socket);
}

static void monitor_parse_beacon_frame(struct monitor* monitor, struct wifi_packet* packet){
    int offset = 0;
    uint8_t* frame = &packet->data[packet->offset];
    packet->beacon_frame = (struct ieee80211_beacon_frame*)&packet->data[packet->offset];

    /* Create new access point info */
    struct access_point ap_info = {
        .beacon_interval = packet->beacon_frame->beacon_interval,
        .capability_info = packet->beacon_frame->capability_info,
        .signal_strength = packet->rssi,
        .channel = packet->channel,
        .hash = 0,
        .stats = {
            .retries = 0,
            .failed = 0,
        }
    };

    /* Extract BSSID (from MAC header) */
    memcpy(ap_info.bssid, packet->wifi_header->addr3, MAC_ADDRESS_LENGTH);
    ap_info.hash = hash(ap_info.bssid);                     /* Hash of the BSSID */

    /* Extract SSID */
    offset = sizeof(struct ieee80211_beacon_frame);
    while (offset < packet->length - packet->offset) {
        uint8_t tag_type = frame[offset];
        uint8_t tag_length = frame[offset + 1];

        if (tag_type == 0) { // SSID tag
            memcpy(ap_info.ssid, &frame[offset + 2], tag_length);
            ap_info.ssid[tag_length] = '\0';
            offset += (2 + tag_length);
        } else if (tag_type == 3) { // DS Parameter set (Channel)
            ap_info.channel = frame[offset + 2];
            offset += (2 + tag_length);
        } else {
            offset += (2 + tag_length);
        }
    }

    packet_queue_init(&ap_info.packets, MAX_AP_PACKETS);

    struct wifi_network* network = monitor_add_network(monitor, ap_info.ssid);
    if(network == NULL){
        logprintf(LOG_ERROR, "Failed to add network\n");
        return;
    }

    ap_info.network = network;
    if(is_new_access_point(&network->ap_list, &ap_info)){
        add_access_point(&network->ap_list, &ap_info);
    }
}

static void monitor_parse_data_frame(struct monitor* monitor, struct wifi_packet* packet){
  
}

static void monitor_parse_packet(struct monitor* monitor, struct wifi_packet* packet){
    struct access_point* ap;

    packet->offset = 0;

    /* Check if the first header is a radiotap header */
    packet->radiotap_header = (struct ieee80211_radiotap_header*)packet->data;
    if(packet->radiotap_header->it_version == 0){
        /* Most importantly we need to adjust offset. */
        packet->offset = packet->radiotap_header->it_len;
        packet->rssi = get_rssi(packet->data, packet->offset);
    } else {
        packet->rssi = -100;
    }

    /* Extract the 802.11 header */
    packet->wifi_header = (const struct ieee80211_header *)(&packet->data[packet->offset]);
    if(packet->wifi_header->frame_control.protocol_version != 0){
        logprintf(LOG_WARNING, "Unsupported protocol version: %u\n", packet->wifi_header->frame_control.protocol_version);
        return;
    }

    /* Check if AP already exists, addr1 is the receiver */
    ap = monitor_find_access_point(monitor, packet->wifi_header->addr1);
    if(ap != NULL){
        ap->signal_strength = packet->rssi;
        ap->stats.frames++;

        /* track errors */
        if(packet->wifi_header->frame_control.retry){
            ap->stats.retries++;
        }
    }

    if(
        monitor->mode == MONITOR_SCAN_ACCESS_POINT && ap != NULL &&
        monitor->networks[monitor->selected_network]->ap_list.aps[monitor->selected_access_point].hash == ap->hash
    ){
        packet_queue_push(&ap->packets, 
           &(struct packet){
                .header = *packet->wifi_header,
                .length = packet->length
           }     
        );
    }

    switch (packet->wifi_header->frame_control.type){
    case TYPE_MANAGEMENT:
        /* Maintenance and control of the wireless network */
        switch (packet->wifi_header->frame_control.subtype){
        /* Beacon frames indicate an access point */
        case SUBTYPE_BEACON:{
                packet->offset += 24;
                monitor_parse_beacon_frame(monitor, packet);
            }
            break;
        /* Association and disassociation */
        case SUBTYPE_ASSOCIATION_REQUEST:
        case SUBTYPE_ASSOCIATION_RESPONSE:{
                struct ieee80211_association_response* association_response = (struct ieee80211_association_response*)(&packet->data[packet->offset]);
                if(association_response->capability_info == ASSOCIATION_STATUS_SUCCESS){
                    logprintf(LOG_INFO, "Association successful\n");
                } 
            }
        case SUBTYPE_DISASSOCIATION:
        case SUBTYPE_DEAUTHENTICATION:
            logprintf(LOG_INFO, "Association data\n");
            break;
        default:
            //logprintf(LOG_WARNING, "Unsupported management frame subtype: %u\n", subtype);
            break;
        }
        break;
    case TYPE_CONTROL:
        break;
    case TYPE_DATA:
        monitor_parse_data_frame(monitor, packet);
        break;
    default:
        //logprintf(LOG_WARNING, "Unknown frame type: %u\n", type);
        break;
    }
}


void* monitor_thread_loop(void* ptr){
    int data_size;
    struct sockaddr saddr;
    struct timeval start, current;
    struct monitor* monitor = (struct monitor*)ptr;

    /* Get the start time */
    gettimeofday(&start, NULL);

    struct wifi_packet packet;
    while(1){
        char* buffer = malloc(2048);
        memset(&packet, 0, sizeof(struct wifi_packet));
        packet.data = buffer;
        packet.channel = monitor->channel;
        
        packet.length = recvfrom(monitor->raw_socket, packet.data, 2048, 0, NULL, NULL);
        if(packet.length > 0){
            monitor_parse_packet(monitor, &packet);
        }

        if(packet.length < 0){
            if(errno != EAGAIN && errno != EWOULDBLOCK){
                perror("Recvfrom error");
                exit(EXIT_FAILURE);
            }
        }

        gettimeofday(&current, NULL);
        long elapsed_ms = (current.tv_sec - start.tv_sec) * 1000 + (current.tv_usec - start.tv_usec) / 1000;
        //printf("Elapsed: %ld\n", elapsed_ms);
        if (elapsed_ms >= 100) {

            if(monitor->mode == MONITOR_SCAN_ACCESS_POINT){
                monitor->ops.set_channel(monitor->ifn, monitor->networks[monitor->selected_network]->ap_list.aps[monitor->selected_access_point].channel);
            } else {
                monitor->channel_index = (monitor->channel_index + 1) % monitor->ops.num_channels;  /* Change channel */
                monitor->ops.set_channel(monitor->ifn, monitor->ops.channels[monitor->channel_index]);
                monitor->channel = monitor->ops.channels[monitor->channel_index];  /* Update current channel */
            }

            /* Reset start time */
            start = current;

        }

        free(buffer);
    }

    return NULL;
}

/**
 * @brief Initialize monitor for the given interface
 * Creates a raw socket which is configured for the given interface
 * @note The socket is set to non-blocking mode
 * @note Default mode is MONITOR_SCAN_DISCOVERY
 * @param mon Monitor to initialize
 * @param ifn Interface name
 * @return error_t
 */
error_t monitor_init(struct monitor* mon, char* ifn)
{
    struct sockaddr_ll socket_address;
    if(mon == NULL){
        return -MON_ERR_NULL;   
    }
    memset(mon, 0, sizeof(struct monitor));
    
    mon->mode = MONITOR_SCAN_DISCOVERY;

    mon->raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (mon->raw_socket < -1) {
        perror("Socket error");
        return -MON_ERR_SOCKET;
    }

    /* Bind socket to the interface */
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = if_nametoindex(ifn);
    if (bind(mon->raw_socket , (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        perror("Bind error");
        close(mon->raw_socket);
        return -MON_ERR_BIND;
    }

    int flags = fcntl(mon->raw_socket, F_GETFL, 0);
    if (flags == -1) {
        // Handle error
        perror("fcntl F_GETFL");
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(mon->raw_socket, F_SETFL, flags) == -1) {
        // Handle error
        perror("fcntl F_SETFL O_NONBLOCK");
        return -1;
    }

    strcpy(mon->ifn, ifn);

    wifi_init(&mon->ops);

    mon->channel_index = 0;
    mon->channel = mon->ops.channels[mon->channel_index];
    mon->ops.set_channel(ifn, mon->channel);
 
    return MON_ERR_OK;
}

// int main(int argc, char** argv)
// {
//     logprintf(LOG_INFO, "Hello from %s!\n", argv[0]);

//     if(argc < 2){
//         logprintf(LOG_ERROR, "Usage: %s <interface>\n", argv[0]);
//         return 1;
//     }

//     if(monitor_init(&monitor, argv[1]) != MON_ERR_OK){
//         logprintf(LOG_ERROR, "Failed to initialize monitor\n");
//         return 1;
//     }


//     monitor_thread_loop(&monitor);
//     monitor_free(&monitor);
//     return 0;
// }

