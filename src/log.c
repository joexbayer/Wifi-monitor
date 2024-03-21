#include <stdio.h>
#include <stdarg.h>

#include <log.h>

static log_level_t min_log_level = LOG_INFO;

void log_set_level(log_level_t level){
    min_log_level = level;
}

void logprintf(log_level_t level, const char *format, ...){
    if (level < min_log_level) {
        return;
    }
    return ;

    va_list args;
    va_start(args, format);

    switch (level) {
        case LOG_INFO:
            printf("INFO: ");
            break;
        case LOG_WARNING:
            printf("WARNING: ");
            break;
        case LOG_ERROR:
            printf("ERROR: ");
            break;
        default:
            return;
    }

    vprintf(format, args);
    //printf("\n");

    va_end(args);
}
