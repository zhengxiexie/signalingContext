#ifndef __CONTEXT_H__
#define __CONTEXT_H__
#include <stdint.h>
#include <time.h>

#include "config.h"
#include "reader-thread.h"

#define CONTEXT_ERR_MALLOC 1

// user information in hash table
struct context_content_t {
    char   imsi[16];
    char   imei[16];
#ifdef WITH_MSISDN
    char   msisdn[16];
#endif
    enum   {POWER_ON = 0, POWER_OFF = 1} state;
    char   last_lac_cell[LEN_LACCELL];
    int    lac_cell_change;
    uint16_t poweron_duration;
    time_t last_open_time;
#ifdef WITH_CLOSE_TIME
    time_t close_time;
#endif
    time_t ts_signal;
    struct context_content_t * next;

};
typedef struct context_content_t context_content_t;

// each segment in context
struct context_seg_t {
    uint64_t size;
    context_content_t * content;
    pthread_mutex_t mutex_lock;
};
typedef struct context_seg_t context_seg_t;

// the context
struct context_t {
    uint64_t size;
    uint32_t part;
    context_seg_t contexts[CONTEXT_PART];
};
typedef struct context_t context_t;

extern context_t context;
extern int context_inited;

int update_context(const signal_entry_t * content);
int check_hourly_update(time_t t);
int dump_context(const char * filename);
int restore_context(const char * filename);
int init_context();
int daily_cleanup(time_t t);

#endif /* __CONTEXT_H__ */
