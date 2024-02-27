#include <wifi.h>
#include <stdio.h>
#include <stdlib.h>

static const int channels[] = {
    1, 6, 11, 36, 40, 44, 48, 52,
    56, 60, 64, 100, 104, 108, 112,
    116, 120, 124, 128, 132, 136,
    140, 149, 153, 157, 161, 165
};
static const int num_channels = sizeof(channels) / sizeof(channels[0]);
static int channel_index = 0;

static void wifi_set_channel(const char *interface, int channel) {
    char command[100];
    sprintf(command, "iw %s set channel %d", interface, channel);
    system(command);
}

static void wifi_set_monitor_mode(const char *interface) {
    char command[100];
    sprintf(command, "iw %s set monitor control", interface);
    system(command);
}

static void wifi_set_managed_mode(const char *interface) {
    char command[100];
    sprintf(command, "iw %s set type managed", interface);
    system(command);
}

static void wifi_set_interface_down(const char *interface) {
    char command[100];
    sprintf(command, "ip link set dev %s down", interface);
    system(command);
}

static void wifi_set_interface_up(const char *interface) {
    char command[100];
    sprintf(command, "ip link set dev %s up", interface);
    system(command);
}

static struct wifi_ops wifi_ops = {
    .set_channel = wifi_set_channel,
    .set_monitor_mode = wifi_set_monitor_mode,
    .set_managed_mode = wifi_set_managed_mode,
    .set_interface_down = wifi_set_interface_down,
    .set_interface_up = wifi_set_interface_up,
    .channels = (int*)channels,
    .num_channels = num_channels
};

void wifi_init(struct wifi_ops *ops){
    *ops = wifi_ops;
}




