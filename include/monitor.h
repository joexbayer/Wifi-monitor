#ifndef __MONITOR_H
#define __MONITOR_H

#include <stdint.h>
#include <stdlib.h>
#include <wifi.h>
#include <packets.h>
#include <pthread.h>

#define MAX_SSID_LENGTH 32
#define MAC_ADDRESS_LENGTH 6
#define MAX_ACCESS_POINTS 32
#define MAX_INTERFACE_NAME 32
#define MAX_NETWORKS 16

#define MAX_AP_PACKETS 1024

typedef enum {
    MONITOR_SCAN_DISCOVERY,
    MONITOR_SCAN_ACCESS_POINT,
    MONITOR_SCAN_NETWORK,
    MONITOR_ACT_ACCESS_POINT
} monitor_mode_t;

struct access_point {
    uint32_t hash;                      // Hash of the BSSID
    struct wifi_network *network;       // Network to which the AP belongs
    char ssid[MAX_SSID_LENGTH + 1];     // SSID of the AP, +1 for null terminator
    uint8_t bssid[MAC_ADDRESS_LENGTH];  // BSSID (MAC Address) of the AP
    int channel;                        // Operating channel of the AP
    int signal_strength;                // RSSI in dBm
    uint16_t beacon_interval;           // Beacon interval in milliseconds
    struct capability_info capability_info;           // Capability information
    struct statistics {
        long retries;                   // Number of retries
        long failed;                    // Number of failed frames
        long frames;                    // Number of frames
        long associations;              // Number of associations
        long disassociations;           // Number of disassociations
        long deauthentications;         // Number of deauthentications
    } stats;
    struct associations_list {
        struct association {
            uint8_t addr[MAC_ADDRESS_LENGTH];   // MAC address of the client
            uint16_t capability_info;           // Capability information
            uint16_t status_code;               // Status of the association (success, failure, etc.)
            uint16_t association_id;            // Association ID assigned by the AP
            struct packet_queue packets;        // Queue of packets from this client
            struct access_point *ap;            // Pointer to the access point
            int frames;
            int retries;
            int failed;
        }* associations;
        size_t size;
        size_t capacity;
    } assoc_list;

    struct packet_queue packets;
};

struct monitor {
    struct wifi_network {
        char ssid[MAX_SSID_LENGTH + 1];     // SSID of the AP, +1 for null terminator
        struct access_point_list {
            struct access_point *aps;               // Array of access points
            size_t size;                            // Number of access points stored
            size_t capacity;                        // Capacity of the array
            pthread_mutex_t mutex;                  // Mutex for the access point list
        } ap_list;
        /* stats */
    }* networks[MAX_NETWORKS];

    struct wifi_ops ops;
    int raw_socket;
    char ifn[MAX_INTERFACE_NAME];
    volatile monitor_mode_t mode;

    int selected_network;
    int selected_access_point;

    int channel_index;
    int channel;

    int interval;
    long dissasociations;
    long deauthentications;
};
void monitor_free(struct monitor* mon);
void* monitor_thread_loop(void*);
struct associtation* monitor_find_client(struct monitor* monitor, uint8_t addr[6]);

/* Utility functions */
void print_as_hex(const unsigned char* buffer, int length);
unsigned int hash(uint8_t *bssid);


#endif // !__MONITOR_H
