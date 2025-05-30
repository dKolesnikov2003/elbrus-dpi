#ifndef FLUSHER_H
#define FLUSHER_H

#include "db_writer.h"
#include "DPI_result_flush_queue.h"
#include "raw_packets_log_flush_queue.h"


typedef struct {
    DPIResultFlushQueue *resultsQueue;
    RawPacketsLogFlushQueue *rawPacketsLogQueue;
    DBConn *db;  // Указатель на соединение с БД
} FlusherThreadArgs;

void *flusher_thread(void *arg);


#endif // FLUSHER_H