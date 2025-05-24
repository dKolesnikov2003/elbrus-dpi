#include "elbrus_dpi_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <sys/stat.h>
#include <pthread.h>

#include "config.h"          /* существующие модули проекта */
#include "capture.h"
#include "packet_processor.h"
#include "db_writer.h"

/* ---------------------------------------------------------------------------
 * Internal helper structures
 * ------------------------------------------------------------------------ */
struct elbrus_dpi_handle {
    CaptureOptions   opts;
    pcap_t          *pcap_handle;

    /* thread‑related */
    unsigned         thread_count;
    pthread_t       *threads;        /* packet processors        */
    ThreadParam     *thread_params;
    PacketQueue     *queues;
    NDPI_ThreadInfo *ndpi_infos;

    CaptureThreadArgs capture_args;

    pthread_t        capture_thread;
    pthread_t        flusher_thread;
    FlushQueue       flush_queue;

    /* state */
    volatile int     running;
};

/* ---------------------------------------------------------------------------
 * Static helpers
 * ------------------------------------------------------------------------ */
static int build_table_name(const CaptureOptions *opts, char *out, size_t len)
{
    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);

    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d_%H-%M-%S", &tm);

    const char *src_base = basename((char*)opts->source);
    return snprintf(out, len, "%c-%s-%s", (opts->mode == CAP_SRC_FILE ? 'f' : 'i'),
                    src_base, datebuf) < (int)len ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * Public API implementation
 * ------------------------------------------------------------------------ */
int elbrus_dpi_init(const elbrus_dpi_config_t *cfg, elbrus_dpi_handle_t **out)
{
    if (!cfg || !out) return -1;
    *out = NULL;

    elbrus_dpi_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return -1;

    /* translate public config -> internal CaptureOptions */
    memset(&h->opts, 0, sizeof(h->opts));
    h->opts.mode      = (cfg->mode == ELBRUS_DPI_SRC_FILE) ? CAP_SRC_FILE : CAP_SRC_IFACE;
    h->opts.source    = strdup(cfg->source);
    h->opts.bpf       = cfg->bpf_filter ? strdup(cfg->bpf_filter) : NULL;
    h->opts.db_name   = cfg->db_path ? strdup(cfg->db_path) : strdup("data/traffic.sqlite");

    h->thread_count   = cfg->thread_count ? cfg->thread_count : THREAD_COUNT;

    /* ensure data folder exists */
    mkdir("data", 0755);

    /* init DB writer so that table is ready before first packet */
    char table_name[128];
    if (build_table_name(&h->opts, table_name, sizeof(table_name)) != 0) {
        free(h);
        return -1;
    }
    if (db_writer_init(h->opts.db_name, table_name) != 0) {
        fprintf(stderr, "libelbrus_dpi: can't open DB %s\n", h->opts.db_name);
        free(h);
        return -1;
    }

    /* allocate thread‑related arrays */
    h->threads       = calloc(h->thread_count, sizeof(pthread_t));
    h->thread_params = calloc(h->thread_count, sizeof(ThreadParam));
    h->queues        = calloc(h->thread_count, sizeof(PacketQueue));
    h->ndpi_infos    = calloc(h->thread_count, sizeof(NDPI_ThreadInfo));
    if (!h->threads || !h->thread_params || !h->queues || !h->ndpi_infos) {
        goto fail_alloc;
    }

    flush_queue_init(&h->flush_queue);
    h->running = 0;
    *out = h;
    return 0; /* success – user must call start */

fail_alloc:
    free(h->threads); free(h->thread_params);
    free(h->queues);  free(h->ndpi_infos);
    free(h);
    return -1;
}

int elbrus_dpi_start(elbrus_dpi_handle_t *h)
{
    if (!h) return -1;
    if (h->running) return 0; /* already running */

    char errbuf[PCAP_ERRBUF_SIZE];
    h->pcap_handle = capture_init(&h->opts, errbuf, sizeof(errbuf), NULL);
    if (!h->pcap_handle) {
        fprintf(stderr, "libelbrus_dpi: pcap init failed: %s\n", errbuf);
        return -1;
    }

    /* initialise queues, ndpi contexts and spawn packet‑processor threads */
    for (unsigned i = 0; i < h->thread_count; ++i) {
        init_queue(&h->queues[i]);
        if (init_ndpi_detection(&h->ndpi_infos[i]) != 0) {
            fprintf(stderr, "libelbrus_dpi: nDPI init failed (thread %u)\n", i);
            return -1;
        }
        pthread_mutex_init(&h->ndpi_infos[i].results_mutex, NULL);

        h->ndpi_infos[i].flush_queue = &h->flush_queue;
        h->thread_params[i].thread_id   = i;
        h->thread_params[i].pcap_handle = h->pcap_handle;
        h->thread_params[i].queue       = &h->queues[i];
        h->thread_params[i].ndpi_info   = &h->ndpi_infos[i];

        if (pthread_create(&h->threads[i], NULL, packet_processor_thread,
                           &h->thread_params[i]) != 0) {
            fprintf(stderr, "libelbrus_dpi: can't create processor thread %u\n", i);
            return -1;
        }
    }

    /* spawn capture thread */
    h->capture_args.pcap_handle = h->pcap_handle;
    h->capture_args.queues      = h->queues;
    if (pthread_create(&h->capture_thread, NULL,
                        capture_thread_func,
                        &h->capture_args) != 0) {
        fprintf(stderr, "libelbrus_dpi: can't create capture thread\n");
        return -1;
    }

    /* spawn DB flusher thread */
    if (pthread_create(&h->flusher_thread, NULL, db_flusher_thread,
                       &h->flush_queue) != 0) {
        fprintf(stderr, "libelbrus_dpi: can't create flusher thread\n");
        return -1;
    }

    h->running = 1;
    return 0;
}

void elbrus_dpi_stop(elbrus_dpi_handle_t *h)
{
    if (!h || !h->running) return;

    /* Break capture loop, threads will finish when queues empty */
    pcap_breakloop(h->pcap_handle);
    h->running = 0;
}

void elbrus_dpi_join(elbrus_dpi_handle_t *h)
{
    if (!h) return;
    if (h->capture_thread)  pthread_join(h->capture_thread, NULL);
    for (unsigned i = 0; i < h->thread_count; ++i) {
        pthread_join(h->threads[i], NULL);
    }

    /* final flush */
    for (unsigned i = 0; i < h->thread_count; ++i) {
        pthread_mutex_lock(&h->ndpi_infos[i].results_mutex);
        if (h->ndpi_infos[i].result_count > 0) {
            FlushBuffer *buf = malloc(sizeof(*buf));
            buf->entries = h->ndpi_infos[i].results;
            buf->count   = h->ndpi_infos[i].result_count;
            flush_queue_push(&h->flush_queue, buf);
            h->ndpi_infos[i].results = NULL;
            h->ndpi_infos[i].result_count = 0;
        }
        pthread_mutex_unlock(&h->ndpi_infos[i].results_mutex);
    }
    flush_queue_terminate(&h->flush_queue);
    if (h->flusher_thread) pthread_join(h->flusher_thread, NULL);
}

void elbrus_dpi_destroy(elbrus_dpi_handle_t *h)
{
    if (!h) return;
    /* tear down resources */
    pthread_mutex_destroy(&h->flush_queue.mutex);
    pthread_cond_destroy(&h->flush_queue.cond_nonempty);
    for (unsigned i = 0; i < h->thread_count; ++i) {
        pthread_mutex_destroy(&h->ndpi_infos[i].results_mutex);
        free_thread_resources(&h->ndpi_infos[i]);
        destroy_queue(&h->queues[i]);
    }
    pcap_close(h->pcap_handle);

    free((char*)h->opts.source);
    free((char*)h->opts.bpf);
    free((char*)h->opts.db_name);

    free(h->threads);
    free(h->thread_params);
    free(h->queues);
    free(h->ndpi_infos);
    free(h);
}