#ifndef __TIMELINE_H
#define __TIMELINE_H

#define TIMELINE_LENGTH 80

struct packet_history {
    int data[TIMELINE_LENGTH];
    int write_index;
};

#endif // !__TIMELINE_H