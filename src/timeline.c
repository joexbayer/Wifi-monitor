#include <timeline.h>
#include <stdlib.h>


void init_packet_history(struct packet_history *history) {
    memset(history->data, 0, sizeof(history->data));
    history->write_index = 0;
}

void add_packet_to_history(struct packet_history *history, int packet_count) {
    for (int i = 1; i < TIMELINE_LENGTH; i++) {
        history->data[i - 1] = history->data[i];
    }
    history->data[TIMELINE_LENGTH - 1] = packet_count;
}