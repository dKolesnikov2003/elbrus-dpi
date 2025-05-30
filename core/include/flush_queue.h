#ifndef FLUSH_QUEUE_H
#define FLUSH_QUEUE_H

#include <netinet/in.h>
#include <pthread.h>

// Структура записи в главной таблице
typedef struct {
    uint64_t timestamp_ms;
    uint8_t ip_version;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip_src;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip_dst;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_length;
    char protocol_name[64];  // Название обнаруженного протокола/приложения (например, "HTTP")
} DPIResultFlushQueueItem;

typedef struct {
    uint64_t timestamp_ms;  // Время в миллисекундах
    uint32_t session_id;    // Идентификатор сессии
    uint32_t packet_length; // Длина пакета
    uint64_t pcap_file_offset; // Смещение в pcap файле
}  RawPacketsLogFlushQueueItem;

// Очередь для хранения результатов nDPI для последующей записи в БД
typedef struct {
    DPIResultFlushQueueItem *items;                     // массив элементов
    size_t count;                    // Текущее количество элементов
    size_t capacity;                 // Вместимость массива
    int front;
    int rear;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
    int8_t is_finished;              // Флаг завершения работы очереди (0 - не завершена, 1 - завершена)
} DPIResultFlushQueue;

typedef struct {
    RawPacketsLogFlushQueueItem *items;                     // массив элементов
    size_t count;                    // Текущее количество элементов
    size_t capacity;                 // Вместимость массива
    int front;
    int rear;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
    int8_t is_finished;              // Флаг завершения работы очереди (0 - не завершена, 1 - завершена)
} RawPacketsLogFlushQueue;

// Функции работы с очередью
void init_DPI_res_flush_queue(DPIResultFlushQueue *q);
void init_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q);
void destroy_DPI_res_flush_queue(DPIResultFlushQueue *q);
void destroy_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q);
int enqueue_DPI_res_flush_queue(DPIResultFlushQueue *q, DPIResultFlushQueueItem item);
int enqueue_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q, RawPacketsLogFlushQueueItem item);
DPIResultFlushQueueItem dequeue_record(DPIResultFlushQueue *q);
RawPacketsLogFlushQueueItem dequeue_raw_record(RawPacketsLogFlushQueue *q);
void DPI_res_flush_queue_finish(DPIResultFlushQueue *q);
void raw_packs_log_queue_finish(RawPacketsLogFlushQueue *q);

#endif // FLUSH_QUEUE_H