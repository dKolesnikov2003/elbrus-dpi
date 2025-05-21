#include "db_writer.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

static sqlite3 *db = NULL;

void* db_flusher_thread(void *arg) {
    FlushQueue *fq = (FlushQueue*)arg;
    FlushBuffer *buf;

    static int db_initialized = 0;
    if(!db_initialized) {
        db_writer_init("data/results.db");
        db_initialized = 1;
    }

    while ((buf = flush_queue_pop(fq)) != NULL) {
        db_writer_insert_batch(buf->entries, buf->count);
        free(buf->entries);
        free(buf);
    }
    db_writer_close();
    return NULL;
}

int db_writer_init(const char *db_filename) {
    if(sqlite3_open(db_filename, &db) != SQLITE_OK) {
        fprintf(stderr, "Ошибка открытия SQLite: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    const char *create_table_sql =
        "CREATE TABLE IF NOT EXISTS packet_log ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip_version INTEGER,"
        "src_addr TEXT,"
        "dst_addr TEXT,"
        "src_port INTEGER,"
        "dst_port INTEGER,"
        "packet_length INTEGER,"
        "protocol_name TEXT,"
        "timestamp INTEGER"
        ");";
    char *errmsg = NULL;
    if(sqlite3_exec(db, create_table_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Ошибка создания таблицы: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

int db_writer_insert_batch(const PacketLogEntry *entries, size_t count) {
    if(db == NULL) return -1;
    const char *insert_sql =
        "INSERT INTO packet_log "
        "(ip_version, src_addr, dst_addr, src_port, dst_port, packet_length, protocol_name, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Транзакция ускоряет вставку пакета
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    for(size_t i = 0; i < count; ++i) {
        const PacketLogEntry *entry = &entries[i];

        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];
        if(entry->ip_version == 4) {
            inet_ntop(AF_INET, &entry->ip_src.v4, src_addr, sizeof(src_addr));
            inet_ntop(AF_INET, &entry->ip_dst.v4, dst_addr, sizeof(dst_addr));
        } else if(entry->ip_version == 6) {
            inet_ntop(AF_INET6, &entry->ip_src.v6, src_addr, sizeof(src_addr));
            inet_ntop(AF_INET6, &entry->ip_dst.v6, dst_addr, sizeof(dst_addr));
        } else {
            strcpy(src_addr, "N/A");
            strcpy(dst_addr, "N/A");
        }

        sqlite3_bind_int(stmt, 1, entry->ip_version);
        sqlite3_bind_text(stmt, 2, src_addr, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, dst_addr, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, entry->src_port);
        sqlite3_bind_int(stmt, 5, entry->dst_port);
        sqlite3_bind_int(stmt, 6, entry->packet_length);
        sqlite3_bind_text(stmt, 7, entry->protocol_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 8, entry->timestamp_ms);

        if(sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Ошибка вставки: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_reset(stmt);
    }

    sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);

    sqlite3_finalize(stmt);
    return 0;
}

void db_writer_close(void) {
    if(db) {
        sqlite3_close(db);
        db = NULL;
    }
}
