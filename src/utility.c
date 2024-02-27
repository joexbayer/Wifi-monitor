#include <stdint.h>

void print_as_hex(const unsigned char* buffer, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

/* Hash function */
unsigned int hash(uint8_t *bssid) {
    unsigned int h = 0;
    for (int i = 0; i < 6; i++) {
        h = (h << 5) ^ (h >> 27) ^ bssid[i]; // Use bit shifts and XOR for better mixing
    }
    return h % 1000;
}
