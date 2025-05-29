#include "db_writer.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "capture.h"

static sqlite3 *db = NULL;
static char     tbl1[128];
static char     tbl2[128];

void* db_flusher_thread(void *arg) {
    FlushQueue *fq = (FlushQueue*)arg;
    FlushBuffer *buf;

    while ((buf = flush_queue_pop(fq)) != NULL) {
        db_writer_insert_batch(buf->entries, buf->count);
        free(buf->entries);
        free(buf);
    }
    db_writer_close();
    return NULL;
}

int db_writer_init(const CaptureOptions *opts)
{   
    char *errmsg = NULL;
    char db_full_path[256];
    snprintf(db_full_path, sizeof(db_full_path), "%s", opts->db_name);       

    char table_1_name[128];
    snprintf(table_1_name, sizeof(table_1_name), "%s", file_and_table_name_pattern);

    if (sqlite3_open(db_full_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Ошибка открытия SQLite: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if (sqlite3_exec(db, "PRAGMA foreign_keys = ON;", 0, 0, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Ошибка включения foreign keys: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(db);
        return 1;
    }

    strncpy(tbl1, table_1_name, sizeof(tbl1) - 1);
    tbl1[sizeof(tbl1) - 1] = '\0';

    /* формируем CREATE TABLE IF NOT EXISTS "tbl1" (...) */
    char create_sql[512];
    snprintf(create_sql, sizeof(create_sql),
             "CREATE TABLE IF NOT EXISTS \"%s\" ("
             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
             "timestamp_ms INTEGER,"
             "ip_version INTEGER,"
             "src_addr TEXT,"
             "dst_addr TEXT,"
             "src_port INTEGER,"
             "dst_port INTEGER,"
             "packet_length INTEGER,"
             "protocol_name TEXT);",
             tbl1);

    if (sqlite3_exec(db, create_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Ошибка создания таблицы: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    char table_2_name[132];
    snprintf(table_2_name, sizeof(table_2_name), "%s_raw", file_and_table_name_pattern);
    if (sqlite3_open(db_full_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Ошибка открытия SQLite: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    strncpy(tbl2, table_2_name, sizeof(tbl2) - 1);
    tbl2[sizeof(tbl2) - 1] = '\0';

    snprintf(create_sql, sizeof(create_sql),
         "CREATE TABLE IF NOT EXISTS \"%s\" ("
         "id INTEGER PRIMARY KEY AUTOINCREMENT,"
         "timestamp_ms INTEGER,"
         "pcap_file_offset INTEGER,"
         "packet_length INTEGER,"
         "FOREIGN KEY (timestamp_ms) REFERENCES \"%s\"(timestamp_ms));",
         tbl2, table_1_name);

    if (sqlite3_exec(db, create_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Ошибка создания таблицы: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

int db_writer_insert_batch(const PacketLogEntry *entries, size_t count) {
    if(db == NULL) return -1;
    char insert_sql[512];
    snprintf(insert_sql, sizeof(insert_sql),
            "INSERT INTO \"%s\" "
            "(timestamp_ms, ip_version, src_addr, dst_addr, "
            "src_port, dst_port, packet_length, protocol_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            tbl1);

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
       
        sqlite3_bind_int64(stmt, 1, entry->timestamp_ms);
        sqlite3_bind_int   (stmt, 2, entry->ip_version);
        sqlite3_bind_text  (stmt, 3, src_addr,       -1, SQLITE_TRANSIENT);
        sqlite3_bind_text  (stmt, 4, dst_addr,       -1, SQLITE_TRANSIENT);
        sqlite3_bind_int   (stmt, 5, entry->src_port);
        sqlite3_bind_int   (stmt, 6, entry->dst_port);
        sqlite3_bind_int   (stmt, 7, entry->packet_length);
        sqlite3_bind_text  (stmt, 8, entry->protocol_name, -1, SQLITE_TRANSIENT);

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
