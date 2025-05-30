#define _POSIX_C_SOURCE 199309L
#include "flusher.h"

#include "DPI_result_flush_queue.h"
#include "raw_packets_log_flush_queue.h"
#include <time.h>


#define MAX_BATCH   512
#define FLUSH_MS    1000    // 1 секунда

static inline long ms_since(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec  - b->tv_sec)  * 1000L +
           (a->tv_nsec - b->tv_nsec) / 1000000L;
}



void *flusher_thread(void *arg) {
    FlusherThreadArgs *args = (FlusherThreadArgs *)arg;
    DPIResultFlushQueue *resultsQueue = args->resultsQueue;
    DBConn *db = args->db;

    dpi_db_begin(db);                // BEGIN;
    struct timespec last_flush; clock_gettime(CLOCK_MONOTONIC, &last_flush);
    size_t batch_count = 0;

    while (1) {
        // Обработка результатов nDPI
        DPIResultFlushQueueItem resItem = dequeue_DPI_res_flush_queue(resultsQueue);
        if (resItem.packet_length == 0 && resItem.timestamp_ms == 0) {
            // Получен сигнал завершения
            break;
        }
        insert_prepared(db, &resItem);
        ++batch_count;

        /* Нужно ли сбрасывать? */
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        if (batch_count >= MAX_BATCH || ms_since(&now, &last_flush) >= FLUSH_MS) {
            dpi_db_commit(db);       // COMMIT;
            dpi_db_begin(db);        // BEGIN;
            batch_count = 0;
            last_flush  = now;
        }
    }

    /* Финальный сброс, если что-то осталось */
    dpi_db_commit(db);
    return NULL;

    return NULL;
}