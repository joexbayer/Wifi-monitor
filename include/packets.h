#ifndef __PACKETS_H
#define __PACKETS_H

struct packet;
struct packet_queue;

#include <stdint.h>
#include <stdlib.h>
#include <wifi.h>

struct packet {
    struct ieee80211_mac_header header;
    size_t length;
};

struct packet_queue {
    struct packet* packets;
    int size;
    int head;
    int tail;
    bool_t full;
};

void packet_queue_init(struct packet_queue *queue, int size);
void packet_queue_push(struct packet_queue* queue, struct packet* packet);
int packet_queue_pop(struct packet_queue* queue, struct packet* packet);
void packet_queue_free(struct packet_queue* queue);

#endif // !__PACKETS_H