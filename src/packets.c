#include <packets.h>

/* Initialize the circular buffer */
void packet_queue_init(struct packet_queue *queue, int size) {
    queue->packets = (struct packet *)malloc(sizeof(struct packet) * size);
    queue->size = size;
    queue->head = 0;
    queue->tail = 0;
    queue->full = false;
}

/* Check if the buffer is empty */
static bool_t packet_queue_is_empty(struct packet_queue* queue) {
    return (!queue->full && (queue->head == queue->tail));
}

/* Check if the buffer is full */
static bool_t packet_queue_is_full(struct packet_queue* queue) {
    return queue->full;
}

/* Add packet to the buffer */
void packet_queue_push(struct packet_queue* queue, struct packet* packet) {
    if (packet_queue_is_full(queue)) {
        return;
    }

    
    queue->packets[queue->head] = *packet;
    queue->head = (queue->head + 1) % queue->size;
    queue->full = (queue->head == queue->tail);
}

/* Retrieve a packet from the buffer */
int packet_queue_pop(struct packet_queue* queue, struct packet* packet) {
    if (packet_queue_is_empty(queue)) {
        return -1; // Buffer is empty
    }

    *packet = queue->packets[queue->tail];
    queue->tail = (queue->tail + 1) % queue->size;
    queue->full = false;
    return 0;
}

/* Clean up the buffer */
void packet_queue_free(struct packet_queue* queue) {
    free(queue->packets);
}