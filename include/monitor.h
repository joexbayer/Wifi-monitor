#ifndef __MONITOR_H
#define __MONITOR_H

#include <stdint.h>
#include <wifi.h>

#define MAX_SSID_LENGTH 32
#define MAC_ADDRESS_LENGTH 6
#define MAX_ACCESS_POINTS 32
#define MAX_INTERFACE_NAME 32
#define MAX_NETWORKS 16

typedef enum {
    MONITOR_SCAN_DISCOVERY,
    MONITOR_SCAN_ACCESS_POINT,
    MONITOR_SCAN_NETWORK
} monitor_mode_t;

struct access_point {
    struct wifi_network *network;       // Network to which the AP belongs
    char ssid[MAX_SSID_LENGTH + 1];     // SSID of the AP, +1 for null terminator
    uint8_t bssid[MAC_ADDRESS_LENGTH];  // BSSID (MAC Address) of the AP
    int channel;                        // Operating channel of the AP
    int signal_strength;                // RSSI in dBm
    uint16_t beacon_interval;           // Beacon interval in milliseconds
    uint16_t capability_info;           // Capability information
    uint32_t hash;                      // Hash of the BSSID
    
    struct statistics {
        long retries;                   // Number of retries
        long failed;                    // Number of failed frames
        long frames;                    // Number of frames
    } stats;

    struct associations_list {
        struct association {
            uint8_t addr[MAC_ADDRESS_LENGTH];   // MAC address of the client
            uint16_t capability_info;           // Capability information
            uint16_t status_code;               // Status of the association (success, failure, etc.)
            uint16_t association_id;            // Association ID assigned by the AP
        }* associations;
        size_t size;
        size_t capacity;
    } assoc_list;
};

struct monitor {
    struct wifi_network {
        char ssid[MAX_SSID_LENGTH + 1];     // SSID of the AP, +1 for null terminator
        struct access_point_list {
            struct access_point *aps;               // Array of access points
            size_t size;                            // Number of access points stored
            size_t capacity;                        // Capacity of the array
        } ap_list;
        /* stats */
    }* networks[MAX_NETWORKS];

    struct wifi_ops ops;

    int raw_socket;
    char ifn[MAX_INTERFACE_NAME];

    volatile monitor_mode_t mode;

    int channel_index;
    int channel;
};
void monitor_free(struct monitor* mon);
void* monitor_recv_loop(void*);

/* Utility functions */
void print_as_hex(const unsigned char* buffer, int length);
unsigned int hash(uint8_t *bssid);


#endif // !__MONITOR_H
