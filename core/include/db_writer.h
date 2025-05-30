#ifndef DB_WRITER_H
#define DB_WRITER_H

#include <sqlite3.h>

#include "DPI_result_flush_queue.h"
#include "eldpi_api.h"

// Простая структура для соединения:
//   db           — указатель на sqlite3*
//   insert_stmt  — подготовленный запрос INSERT
typedef struct {
    sqlite3       *db;
    sqlite3_stmt  *insert_stmt;
} DBConn;

int dpi_db_init(const CaptureOptions *opts);
void dpi_db_begin(DBConn *conn);
void dpi_db_close(DBConn *conn);
void insert_prepared_DPI_results(DBConn *conn, const DPIResultFlushQueueItem *it);

#endif // DB_WRITER_H