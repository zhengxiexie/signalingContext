#ifndef __READER_THREAD_H__
#define __READER_THREAD_H__

extern volatile int exit_flag;

#define MAX_LINE (1024)

#include <pthread.h>
#include <time.h>
#include <stdint.h>

#include "config.h"

struct signal_entry_t {
    char  imsi[16];
    char  imei[16];
    char  msisdn[16];
    time_t timestamp;
    char lac_cell[LEN_LACCELL];
    enum_event_type event;
};
typedef struct signal_entry_t signal_entry_t;

struct signal_sort_buffer_t {
    int    size;
    int    used;
    time_t time;
    signal_entry_t * buffer;
};
typedef struct signal_sort_buffer_t signal_sort_buffer_t;

void * read_file_thread(void * data);

#endif /* __READER_THREAD_H__ */

