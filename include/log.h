#ifndef __LOGG_H
#define __LOGG_H

typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} log_level_t;

void logprintf(log_level_t level, const char *format, ...);
void log_set_level(log_level_t level);

#endif // !__LOGG_H