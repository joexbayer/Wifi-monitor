#ifndef __WIFI_ERR_H
#define __WIFI_ERR_H

typedef int error_t;

typedef enum __monitor_errors {
    MON_ERR_OK = 0,
    MON_ERR_GENERIC,
    MON_ERR_NULL,
    MON_ERR_SOCKET,
    MON_ERR_BIND
} monitor_errors_t;

#endif // !__WIFI_ERR_H
