#ifndef DB_WRITER_H
#define DB_WRITER_H

#include <stddef.h>
#include <capture.h>
#include "packet_processor.h"

// Потоковая функция для записи в БД
void* db_flusher_thread(void *arg); 

// Инициализация базы данных (создаёт таблицу, если нужно)
int db_writer_init(const CaptureOptions *opts);

// Сохраняет пачку записей в БД
int db_writer_insert_batch(const PacketLogEntry *entries, size_t count);

// Завершает работу с БД (закрывает соединение)

void db_writer_close(void);

#endif // DB_WRITER_H
