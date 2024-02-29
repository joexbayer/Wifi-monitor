#ifndef __WIFI_H
#define __WIFI_H

#include <stdint.h>

typedef char bool_t;
#define true 1
#define false 0


struct wifi_ops {
    void (*set_channel)(const char *interface, int channel);
    void (*set_monitor_mode)(const char *interface);
    void (*set_managed_mode)(const char *interface);
    void (*set_interface_down)(const char *interface);
    void (*set_interface_up)(const char *interface);
    int* channels;
    int num_channels;
};
void wifi_init(struct wifi_ops *ops);

/* Wifi standard headers */

/* Frame Types */
#define TYPE_MANAGEMENT 0x00
#define TYPE_CONTROL    0x01
#define TYPE_DATA       0x02

/* Management Frame Subtypes */
#define SUBTYPE_ASSOCIATION_REQUEST    0x00
#define SUBTYPE_ASSOCIATION_RESPONSE   0x01
#define SUBTYPE_REASSOCIATION_REQUEST  0x02
#define SUBTYPE_REASSOCIATION_RESPONSE 0x03
#define SUBTYPE_PROBE_REQUEST          0x04
#define SUBTYPE_PROBE_RESPONSE         0x05
#define SUBTYPE_BEACON                 0x08
#define SUBTYPE_ATIM                   0x09
#define SUBTYPE_DISASSOCIATION         0x0A
#define SUBTYPE_AUTHENTICATION         0x0B
#define SUBTYPE_DEAUTHENTICATION       0x0C
#define SUBTYPE_ACTION                 0x0D
#define SUBTYPE_ACTION_NO_ACK          0x0E

/* Control Frame Subtypes */
#define SUBTYPE_PS_POLL                0x0A
#define SUBTYPE_RTS                    0x0B
#define SUBTYPE_CTS                    0x0C
#define SUBTYPE_ACK                    0x0D
#define SUBTYPE_CF_END                 0x0E
#define SUBTYPE_CF_END_CF_ACK          0x0F
#define SUBTYPE_BLOCK_ACK_REQUEST      0x08
#define SUBTYPE_BLOCK_ACK              0x09

/* Data Frame Subtypes */
#define SUBTYPE_DATA                   0x00
#define SUBTYPE_DATA_CF_ACK            0x01
#define SUBTYPE_DATA_CF_POLL           0x02
#define SUBTYPE_DATA_CF_ACK_CF_POLL    0x03
#define SUBTYPE_NULL_FUNCTION          0x04
#define SUBTYPE_CF_ACK                 0x05
#define SUBTYPE_CF_POLL                0x06
#define SUBTYPE_CF_ACK_CF_POLL         0x07
#define SUBTYPE_QOS_DATA               0x08
#define SUBTYPE_QOS_DATA_CF_ACK        0x09
#define SUBTYPE_QOS_DATA_CF_POLL       0x0A
#define SUBTYPE_QOS_DATA_CF_ACK_CF_POLL 0x0B
#define SUBTYPE_QOS_NULL               0x0C
#define SUBTYPE_QOS_CF_POLL            0x0E
#define SUBTYPE_QOS_CF_ACK_CF_POLL     0x0F

#define ASSOCIATION_STATUS_SUCCESS 0x00

struct wifi_packet {
    uint8_t* data;
    int length;
    int rssi;
    int channel;

    int offset;

    struct ieee80211_radiotap_header* radiotap_header;
    struct ieee80211_mac_header* wifi_header;
    struct ieee80211_frame_control* frame_control;
    struct ieee80211_beacon_frame* beacon_frame;
};


struct ieee80211_radiotap_header {
    uint8_t it_version;     /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;         /* entire length */
    uint32_t it_present;     /* fields present */
} __attribute__((__packed__));

struct ieee80211_mac_header {
    struct ieee80211_frame_control {
        uint8_t protocol_version : 2;  // Protocol Version (2 bits)
        uint8_t type             : 2;  // Type (2 bits)
        uint8_t subtype          : 4;  // Subtype (4 bits)

        uint8_t to_ds            : 1;  // To Distribution System flag (1 bit)
        uint8_t from_ds          : 1;  // From Distribution System flag (1 bit)
        uint8_t more_fragments   : 1;  // More Fragments flag (1 bit)
        uint8_t retry            : 1;  // Retry flag (1 bit)
        uint8_t power_management : 1;  // Power Management flag (1 bit)
        uint8_t more_data        : 1;  // More Data flag (1 bit)
        uint8_t protected_frame  : 1;  // Protected Frame flag (1 bit)
        uint8_t order            : 1;  // Order flag (1 bit)
    } __attribute__((packed)) frame_control;    // Frame Control
    uint16_t duration_id;      // Duration ID
    uint8_t  addr1[6];         // Address 1 (Receiver Address)
    uint8_t  addr2[6];         // Address 2 (Transmitter Address)
    uint8_t  addr3[6];         // Address 3 (Source Address or BSSID)
    uint16_t sequence_control; // Sequence Control (Fragment number and Sequence number)
    uint8_t  addr4[6];         // Address 4 (optional, used in WDS - Wireless Distribution System)
    uint16_t qos_control;      // QoS Control (optional, used in QoS Data frames)
    uint32_t ht_control;       // HT Control (optional, used in HT - High Throughput frames)
}__attribute__((__packed__));

struct ieee80211_association_response {
    // IEEE 802.11 MAC Header
    struct ieee80211_mac_header header;

    // Association Response-specific fields
    uint16_t capability_info;       // Capabilities of the AP
    uint16_t status_code;           // Status of the association (success, failure, etc.)
    uint16_t association_id;        // Association ID assigned by the AP
    uint8_t info_elements[];
} __attribute__((__packed__));


struct tagged_parameter {
    uint8_t tag_number;         // Tag number (e.g., 0 for SSID)
    uint8_t tag_length;         // Length of the tag data
    uint8_t tag_data[];         // Tag data (variable length)
};

struct ieee80211_beacon_frame {
    uint64_t timestamp;
    uint16_t beacon_interval;
    struct capability_info {
        uint16_t ess : 1;           // Extended Service Set (ESS)
        uint16_t ibss : 1;          // Independent Basic Service Set (IBSS)
        uint16_t cfpollable : 1;    // CF-Pollable
        uint16_t cfpreq : 1;        // CF-Poll Request
        uint16_t privacy : 1;       // Privacy
        uint16_t short_preamble : 1;// Short Preamble
        uint16_t pbcc : 1;          // PBCC
        uint16_t channel_agility : 1;// Channel Agility
        uint16_t spectrum_mgmt : 1; // Spectrum Management
        uint16_t qos : 1;           // QoS
        uint16_t short_slot_time : 1;// Short Slot Time
        uint16_t apsd : 1;          // Automatic Power Save Delivery
        uint16_t radio_measurement : 1; // Radio Measurement
        uint16_t dsss_ofdm : 1;     // DSSS-OFDM
        uint16_t delayed_block_ack : 1; // Delayed Block Ack
        uint16_t immediate_block_ack : 1; // Immediate Block Ack
    } __attribute__((__packed__)) capability_info;
    // Tagged parameters follow
}__attribute__((__packed__));

#endif // !__WIFI_H