/*
 * file: sscontext.c
 * holds method to dealing with context
 * all function here *MUST* be thread safe
 * but not necessery be reentrant
 *
 */

#ifndef _THREAD_SAFE_
#error "Must be compiled with -D_THREAD_SAFE_"
#endif

#define ROUND(a, b) ((a) / (b) * (b))

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <pthread.h>

#include "config.h"
#include "context.h"
#include "reader-thread.h"
#include "comsumer-thread.h"
#include "log.h"

typedef struct _output_file_t {
    char filename[256];
    time_t filename_ts;
    FILE * output;
} output_file_t;

// init output file;
static output_file_t output_info = {"", -1, NULL};

int context_inited = 0;

static inline uint64_t BKDRHash(const char * str);
static int time_format(const time_t t, char * line);
static int do_write_file(const context_content_t * cc);
static int do_update_context(context_content_t * old, const signal_entry_t * new);
static int do_new_context(context_content_t * cc, const signal_entry_t * se);
static int format_context(const context_content_t * c, char * line);
static int hourly_update_context(time_t time);
static int restore_one_context(context_content_t * c);
static int write_context(context_content_t * content);
static int fmt_output_timestamp(const time_t t, char * line);
static int time_format(const time_t t, char * line);

static inline
uint64_t BKDRHash(const char * str) {
    static const unsigned int seed = 1313; // 31 131 1313 13131 131313 etc..
    uint64_t hash = 0;
    while (*str) hash = hash * seed + (*str++);
    return hash;
}

#define time_in_period(t1, t2) \
    ((uint16_t)(t2 - MAX(t1, ROUND(t2, CFG(output_interval)))))

// update context. invoke do_update when content is already in context
// otherwise insert new content into context.
int update_context(const signal_entry_t * se) {
    uint64_t hash_in = BKDRHash(se->imsi) % context.size;
    uint64_t part    = hash_in % context.part;
    uint64_t offset  = hash_in / context.part;
    int ret = 0;
    int flag_content_found = 0;

    context_seg_t * context_seg = &context.contexts[part];
    context_content_t * temp_content;

    // lookup content in content_seg
    flag_content_found = 0;

    // lock {{
    pthread_mutex_lock(&context_seg->mutex_lock);
    for (temp_content = &context_seg->content[offset];
         temp_content && temp_content->imsi[0];
         temp_content = temp_content->next) {
        if (0 == strcmp(se->imsi, temp_content->imsi)) {
            flag_content_found = 1;
            break;
        }
    }

    // invoke new content or insert new content
    if (flag_content_found) {
        ret = do_update_context(temp_content, se);
    } else {
        ret = do_new_context(&context_seg->content[offset], se);
    }

    pthread_mutex_unlock(&context_seg->mutex_lock);
    // unlock }}

    if (ret) {
        logmsg(stderr, "Update Context failed");
        return ret;
    }

    return 0;
}

static
int do_update_context(context_content_t * old, const signal_entry_t * new) {
    int imei_changed = 0;
    old->ts_signal = new->timestamp;

    if (!old->imei[0] && new->imei[0]) {
        // user without imei, assume all previous event using same imei
        strcpy(old->imei, new->imei);
        imei_changed = 0;
    } else if (new->imei[0] && strcmp(old->imei, new->imei)) {
        // we got a new imei
        imei_changed = 1;
    }

#ifdef WITH_MSISDN
    if (!old->msisdn[0] && new->msisdn[0]) strcpy(old->msisdn, new->msisdn);
#endif
    if (imei_changed) {
        // imei change, assume power old terminal and power on new one
        if (old->state == POWER_ON) {
            old->state = POWER_OFF;
            old->poweron_duration =
                time_in_period(old->last_open_time, new->timestamp);
#ifdef WITH_CLOSE_TIME
            old->close_time = new->timestamp;
#endif
            write_context(old);
        }
        old->lac_cell_change = 0;
        old->last_open_time = new->timestamp;
        if (new->event == MOBILE_CLOSE) {
            old->poweron_duration = 0;
#ifdef WITH_CLOSE_TIME
            old->close_time = new->timestamp;
#endif
            write_context(old);
            old->state = POWER_OFF;
        } else {
            strcpy(old->last_lac_cell, new->lac_cell);
            old->state = POWER_ON;
        }
        strcpy(old->imei, new->imei);
    } else {
        if (old->state == POWER_ON) {
            // update lac_cell_change only when terminal is powered on
            if (strcmp(old->last_lac_cell, new->lac_cell)) {
                old->lac_cell_change++;
                strcpy(old->last_lac_cell, new->lac_cell);
            }

            if (new->event == MOBILE_CLOSE) {
                // ON -> OFF, that's normal
                old->state = POWER_OFF;
                old->poweron_duration =
                    time_in_period(old->last_open_time, new->timestamp);
#ifdef WITH_CLOSE_TIME
                old->close_time = new->timestamp;
#endif
                write_context(old);
                old->lac_cell_change = 0;
            }
            // ON -> ON, nothing changes
        } else {
            if (new->event == MOBILE_CLOSE) {
                // OFF -> OFF, hold on, we are missing someting here
                old->poweron_duration =
                    time_in_period(old->last_open_time, new->timestamp);
#ifdef WITH_CLOSE_TIME
                old->close_time = new->timestamp;
#endif
                write_context(old);
                old->lac_cell_change = 0;
                old->last_open_time = new->timestamp;
                old->poweron_duration = 0;
#ifdef WITH_CLOSE_TIME
                old->close_time = new->timestamp;
#endif
                // missing last_lac_cell? Not really, it makes no difference.
                write_context(old);
            } else {
                // OFF -> ON, every thing changes
                old->state = POWER_ON;
                old->lac_cell_change = 0;
                strcpy(old->last_lac_cell, new->lac_cell);
            }
        }
    }

    return 0;
}

static int do_new_context(context_content_t * cc, const signal_entry_t * se) {
    context_content_t * tmp_cc = NULL;
    if (!cc->imsi[0]) {
        // newcontext node in this hash slot
        tmp_cc = cc;
        cc->next = NULL;
    } else {
        // prefix a new node
        tmp_cc = (context_content_t*)calloc(1, sizeof(context_content_t));
        tmp_cc->next = cc->next;
        cc->next = tmp_cc;
    }

    tmp_cc->ts_signal = se->timestamp;
    strcpy(tmp_cc->imsi, se->imsi);
    strcpy(tmp_cc->imei, se->imei);
    tmp_cc->lac_cell_change = 0;
    tmp_cc->last_open_time = 0;
#ifdef WITH_CLOSE_TIME
    tmp_cc->close_time = 0;
#endif
#ifdef WITH_MSISDN
    strcpy(tmp_cc->msisdn, se->msisdn);
#endif
    if (se->event == MOBILE_CLOSE) {
        // first record for user is power off
#ifdef WITH_CLOSE_TIME
        tmp_cc->close_time = se->timestamp;
#endif
        tmp_cc->state = POWER_OFF;
        tmp_cc->poweron_duration = (uint16_t)se->timestamp % CFG(output_interval);
        write_context(tmp_cc);
    } else {
        strcpy(tmp_cc->last_lac_cell, se->lac_cell);
        tmp_cc->last_open_time = se->timestamp;
        tmp_cc->state = POWER_ON;
    }
    return 0;
}

static int do_write_file(const context_content_t * cc) {
    char line[LEN_LINE];
    int  len = 0;
    memset(line, 0, LEN_LINE);

    // format Context to line
    len = format_context(cc, line);
    if (!output_info.output) output_info.output = fopen(CFG(tmp_filename), "a");
    // according to POSIX standard, fwrite is atomic, therefore no lock needed.
    //printf("out line: %s", line);
    fwrite(line, len, 1, output_info.output);
    return 0;
}

static int write_context(context_content_t * content) {
    int ret =  do_write_file(content);
#ifdef WITH_CLOSE_TIME
    content->close_time = 0;
#endif
    return ret;
}

static int format_context(const context_content_t * c, char * line) {
    int ret = 0;
    char time_laop[27], time_close[27];

    time_format(c->last_open_time, time_laop);
#ifdef WITH_CLOSE_TIME
    time_format(c->close_time, time_close);
#endif
    ret = sprintf(line,
     /*  1  2  3  4  5 */
        "%s,%s,%s,%d,%hu"
#ifdef WITH_MSISDN
        ",%s"
#endif
#ifdef WITH_CLOSE_TIME
        ",%s"
#endif
        "\n",
        c->imsi, c->imei, time_laop, c->lac_cell_change, c->poweron_duration
#ifdef WITH_MSISDN
        , c->msisdn
#endif
#ifdef WITH_CLOSE_TIME
        , time_close
#endif
    );

    return ret;
}

static int fmt_output_timestamp(const time_t t, char * line) {
    struct tm tp;
    if (t != 0) {
        localtime_r(&t, &tp);
        strftime(line, 27, "%Y%m%d%H%M", &tp);
    }
    return 0;
}

static int time_format(const time_t t, char * line) {
    struct tm tp;
    if (t > 0) {
        localtime_r(&t, &tp);
        strftime(line, 27, "%Y-%m-%d %H:%M:%S", &tp);
    } else {
        line[0] = '\0';
    }
    return 0;
}

int hourly_update_context(time_t time) {
    int i = 0, j = 0;
    context_seg_t     * ch = NULL;
    context_content_t * cc = NULL;
    char output_timestamp[24];
    int total_in_context = 0;

    // wait all context thread finished.
    wait_context_thread();

    // lock all context
    for (i = 0; i < context.part; i++) {
        pthread_mutex_lock(&context.contexts[i].mutex_lock);
    }

    for (i = 0; i < context.part; i++) {
        ch = &context.contexts[i];
        for (j = 0; j < ch->size; j++) {
            for (cc = &ch->content[j]; cc && cc->imsi[0]; cc = cc -> next) {
                total_in_context++;
                if (cc->state == POWER_OFF) continue;
                cc->poweron_duration = CFG(output_interval)
                        - cc->last_open_time % CFG(output_interval);
                write_context(cc);
                cc->lac_cell_change = 0;
            }
        }
    }

    // switch to new file
    if (output_info.output) {
        fflush(output_info.output);
        fclose(output_info.output);
    }
    fmt_output_timestamp(output_info.filename_ts / CFG(output_interval) * CFG(output_interval), output_timestamp);
    // trim min if CFG(output_interval) is multiply of 3600
    if (CFG(output_interval) % 3600 == 0) output_timestamp[10] = '\0';
    // trim hour if daily output
    if (CFG(output_interval) % (24 * 3600) == 0) output_timestamp[8] = '\0';
    sprintf(output_info.filename, "%s/%s%s%s",
            CFG(output_dir), CFG(output_prefix), output_timestamp, CFG(output_suffix));

    logmsg(stdout, "Output File: %s, Context: %d", output_info.filename, total_in_context);

    if (CFG(cross_mountpoint)) {
        // using mv to move file, rename() cannot handle
        // moving a file cross mount points
        char cmd_buffer[1024];
        sprintf(cmd_buffer, "mv '%s' '%s'", CFG(tmp_filename), output_info.filename);
        logmsg(stdout, "Ecec shell cmd: %s", cmd_buffer);
        system(cmd_buffer);
    } else {
        logmsg(stdout, "Moving %s to %s", CFG(tmp_filename), output_info.filename);
        rename(CFG(tmp_filename), output_info.filename);
    }

    output_info.output = fopen(CFG(tmp_filename), "a");
    // unlock all context
    for (i = 0; i < context.part; i++) {
        pthread_mutex_unlock(&context.contexts[i].mutex_lock);
    }
    output_info.filename_ts = time;
    return 0;
}

int check_hourly_update(time_t t) {
    time_t rd_t = (t + CFG(tz_offset)) / CFG(output_interval) * CFG(output_interval) - CFG(tz_offset);

    // time
    if (output_info.filename_ts == -1) output_info.filename_ts = rd_t;
#ifdef __DEBUG__
    printf("%d, %d, %d\n", t, rd_t, output_info.filename_ts);
#endif
    // need hourly update
    if (rd_t != output_info.filename_ts) {
        logmsg(stdout, "Hourly update: %d -> %d", rd_t, output_info.filename_ts);
        // need switch file name
        hourly_update_context(rd_t);
    }
    return 0;
}

int daily_cleanup(time_t t) {
    static const int sec_in_day = 24 * 3600;
    int i = 0;
    int j = 0;
    int cleaned = 0;

    context_content_t * cc = NULL;
    context_seg_t     * ch = NULL;
    context_content_t * c_next = NULL;
    context_content_t * c_prev = NULL;

    // wait context thread
    wait_context_thread();

    for (i = 0; i < context.part; i++) {
        ch = &context.contexts[i];
        for (j = 0; j < ch->size; j++) {
            cc = &ch->content[j];
            c_prev = NULL;
            while (cc && cc->imsi[0]) {
                // check ts_signal
                if (t - cc->ts_signal < sec_in_day) {
                    c_prev = cc;
                    cc     = cc->next;
                    continue;
                }
                // update poweron_duration;
                cc->poweron_duration =
                    (t - MAX(t - CFG(output_interval), cc->last_open_time));

                // output
                write_context(cc);

                // remove from context
                cleaned++;
                if (c_prev == NULL) {

                    // remove first node
                    if (!c_next) {
                        // next is null
                        memset(cc, 0, sizeof(context_content_t));
                    } else {
                        memcpy(cc, c_next, sizeof(context_content_t));
                        free(c_next);
                    }
                } else {
                    c_prev->next = cc->next;
                    free(cc);
                    cc = c_prev->next;
                }
            }
        }
    }

    return cleaned;
}

// dump all context to file
int dump_context(const char * filename) {
    FILE * dump_file = fopen(filename, "wb");
    int i = 0;
    int j = 0;

    context_content_t * cc = NULL;

    if (!dump_file) {
        logmsg(stderr, "Open backup file %s fail, context not backup", filename);
        return 1;
    }

    logmsg(stdout, "Backing up context to %s", filename);
    // write all context
    for (i = 0; i < CONTEXT_PART; i++) {
        for (j = 0; j < context.contexts[i].size; j++) {
            for (cc = &context.contexts[i].content[j]; cc && cc->imsi[0]; cc = cc->next) {
                fwrite(cc, sizeof(context_content_t), 1, dump_file);
            }
        }
    }
    fflush(dump_file);
    fclose(dump_file);
    logmsg(stdout, "Backing up context done!", filename);
    return 0;
}

// restore context from backup file
int restore_context(const char * filename) {
    FILE * dump_file = fopen(filename, "rb");
    context_content_t * cc;
    int backuped = 0;

    if (!dump_file) {
        logmsg(stderr, "Backup file %s not found, ignored", filename);
        return 1;
    }

    logmsg(stdout, "Restoring context from %s", filename);
    cc = calloc(1, sizeof(context_content_t));
    while (fread(cc, sizeof(context_content_t), 1, dump_file)) {
        cc->next = NULL;
        restore_one_context(cc);
        backuped++;
    }
    fclose(dump_file);
    logmsg(stdout, "%d Context retored", backuped, filename);
    free(cc);
    remove(filename);
    return 0;
}

static int restore_one_context(context_content_t * c) {
    uint64_t hash_in = BKDRHash(c->imsi) % context.size;
    uint64_t part    = hash_in % context.part;
    uint64_t offset  = hash_in / context.part;

    context_seg_t * context_seg = &context.contexts[part];
    context_content_t * curr = &context_seg->content[offset];

    if (curr->imsi[0]) {
        // new node
        context_content_t * new = (context_content_t*)
            calloc(1, sizeof(context_content_t));
        memcpy(curr, c, sizeof(context_content_t));
        new->next  = curr->next;
        curr->next = new;
    } else {
        memcpy(curr, c, sizeof(context_content_t));
        curr->next = NULL;
    }

    return 0;
}

int init_context() {
    int i = 0;
    int size_per_part = 0;

    memset(&context, 0, sizeof(context_t));

    context.size = CFG(context_size);
    context.part = CONTEXT_PART;
    size_per_part = context.size / context.part;

    logmsg(stdout, "starting to allocated Context: %1.3fMB x %d",
            size_per_part * sizeof(context_content_t) / 1024.0 / 1024,
            context.part);
    for (i = 0; i < context.part; i++) {
        context.contexts[i].size = size_per_part;
        pthread_mutex_init(&context.contexts[i].mutex_lock, NULL);
        context.contexts[i].content = calloc(size_per_part, sizeof(context_content_t));
        if (!context.contexts[i].content) return CONTEXT_ERR_MALLOC;
    }
    logmsg(stdout, "Context allocated");

    return 0;
}

