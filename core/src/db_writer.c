#include <sqlite3.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "DPI_result_flush_queue.h"
#include "db_writer.h"
#include "eldpi_api.h"
#include "capture.h"

// Вспомогательная функция для проверки ошибок SQLite
static void check_sqlite(int rc, sqlite3 *db, const char *msg) {
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
}

// Открытие БД и создание схемы
int dpi_db_init(const CaptureOptions *opts) {
    char *errmsg = NULL;
    char db_full_path[256];
    sqlite3 *db = NULL;
    snprintf(db_full_path, sizeof(db_full_path), "%s", get_DB_path());       

    char table_1_name[128];
    snprintf(table_1_name, sizeof(table_1_name), "%s", file_and_table_name_pattern);

    if (sqlite3_open(db_full_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Ошибка открытия SQLite: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Включаем WAL — для параллельных чтений\записей
    int rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;", NULL, NULL, &errmsg);
    check_sqlite(rc, db, "Не удалось включить WAL");

    // Создаём таблицу, если её ещё нет
    const char *ddl =
      "CREATE TABLE IF NOT EXISTS dpi_results ("
      "  id INTEGER     PRIMARY KEY AUTOINCREMENT,"
      "  timestamp_ms   INTEGER NOT NULL,"
      "  ip_version     INTEGER NOT NULL,"
      "  ip_src         TEXT    NOT NULL,"
      "  ip_dst         TEXT    NOT NULL,"
      "  src_port       INTEGER NOT NULL,"
      "  dst_port       INTEGER NOT NULL,"
      "  packet_length  INTEGER NOT NULL,"
      "  protocol_name  TEXT    NOT NULL"
      ");";

    rc = sqlite3_exec(db, ddl, NULL, NULL, &errmsg);
    check_sqlite(rc, db, "Не удалось создать схему БД");

    return SQLITE_OK;
}

// Вызывается из flusher_thread при инициализации БД:
void dpi_db_begin(DBConn *conn) {
    int rc = sqlite3_exec(conn->db, "BEGIN;", NULL, NULL, NULL);
    check_sqlite(rc, conn->db, "Не удалось начать транзакцию");
    conn->insert_stmt = NULL;
}

// Вызывается при завершении работы с БД:
void dpi_db_close(DBConn *conn) {
    int rc;
    if (conn->insert_stmt) {
        rc = sqlite3_finalize(conn->insert_stmt);
        check_sqlite(rc, conn->db, "Ошибка sqlite3_finalize");
    }
    rc = sqlite3_exec(conn->db, "COMMIT;", NULL, NULL, NULL);
    check_sqlite(rc, conn->db, "Не удалось зафиксировать транзакцию (COMMIT)");
    rc = sqlite3_close(conn->db);
    if (rc != SQLITE_OK) {
        // sqlite3_errmsg нельзя вызывать после sqlite3_close, поэтому просто код
        fprintf(stderr, "Ошибка sqlite3_close: код %d\n", rc);
    }
}


// Функция вставки одной записи через подготовленный запрос.
// При первом вызове — компилируем запрос, дальше — просто биндим параметры и step/reset.
void insert_prepared_DPI_results(DBConn *conn, const DPIResultFlushQueueItem *it) {
    static const char *sql =
        "INSERT INTO dpi_results "
        "(timestamp_ms, ip_version, ip_src, ip_dst, src_port, dst_port, packet_length, protocol_name) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8);";

    // 0) Подготовка запроса при первом вызове
    if (conn->insert_stmt == NULL) {
        int rc = sqlite3_prepare_v2(conn->db, sql, -1, &conn->insert_stmt, NULL);
        check_sqlite(rc, conn->db, "sqlite3_prepare_v2 failed");
    }

    int rc;
    // 1) Биндим timestamp_ms
    rc = sqlite3_bind_int64(conn->insert_stmt, 1, (sqlite3_int64)it->timestamp_ms);
    check_sqlite(rc, conn->db, "bind timestamp_ms failed");

    // 2) ip_version
    rc = sqlite3_bind_int(conn->insert_stmt, 2, it->ip_version);
    check_sqlite(rc, conn->db, "bind ip_version failed");

    // 3,4) Преобразуем IP в текстовую форму и биндим
    char buf[INET6_ADDRSTRLEN];
    if (it->ip_version == 4) {
        if (inet_ntop(AF_INET, &it->ip_src.v4, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop IPv4 src failed");
            exit(EXIT_FAILURE);
        }
        rc = sqlite3_bind_text(conn->insert_stmt, 3, buf, -1, SQLITE_TRANSIENT);
        check_sqlite(rc, conn->db, "bind ip_src failed");

        if (inet_ntop(AF_INET, &it->ip_dst.v4, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop IPv4 dst failed");
            exit(EXIT_FAILURE);
        }
        rc = sqlite3_bind_text(conn->insert_stmt, 4, buf, -1, SQLITE_TRANSIENT);
        check_sqlite(rc, conn->db, "bind ip_dst failed");
    } else {
        if (inet_ntop(AF_INET6, &it->ip_src.v6, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop IPv6 src failed");
            exit(EXIT_FAILURE);
        }
        rc = sqlite3_bind_text(conn->insert_stmt, 3, buf, -1, SQLITE_TRANSIENT);
        check_sqlite(rc, conn->db, "bind ip_src failed");

        if (inet_ntop(AF_INET6, &it->ip_dst.v6, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop IPv6 dst failed");
            exit(EXIT_FAILURE);
        }
        rc = sqlite3_bind_text(conn->insert_stmt, 4, buf, -1, SQLITE_TRANSIENT);
        check_sqlite(rc, conn->db, "bind ip_dst failed");
    }

    // 5) src_port
    rc = sqlite3_bind_int(conn->insert_stmt, 5, it->src_port);
    check_sqlite(rc, conn->db, "bind src_port failed");

    // 6) dst_port
    rc = sqlite3_bind_int(conn->insert_stmt, 6, it->dst_port);
    check_sqlite(rc, conn->db, "bind dst_port failed");

    // 7) packet_length
    rc = sqlite3_bind_int(conn->insert_stmt, 7, it->packet_length);
    check_sqlite(rc, conn->db, "bind packet_length failed");

    // 8) protocol_name
    rc = sqlite3_bind_text(conn->insert_stmt, 8, it->protocol_name, -1, SQLITE_TRANSIENT);
    check_sqlite(rc, conn->db, "bind protocol_name failed");

    // Выполняем INSERT
    rc = sqlite3_step(conn->insert_stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "sqlite3_step failed: %s\n", sqlite3_errmsg(conn->db));
        exit(EXIT_FAILURE);
    }

    // Сбрасываем состояние stmt, чтобы можно было биндать новые параметры
    rc = sqlite3_reset(conn->insert_stmt);
    check_sqlite(rc, conn->db, "sqlite3_reset failed");

    rc = sqlite3_clear_bindings(conn->insert_stmt);
    check_sqlite(rc, conn->db, "sqlite3_clear_bindings failed");
}
