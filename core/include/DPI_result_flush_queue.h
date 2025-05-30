#ifndef DPI_RESULT_FLUSH_QUEUE_H
#define DPI_RESULT_FLUSH_QUEUE_H

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

// Функции работы с очередью
void init_DPI_res_flush_queue(DPIResultFlushQueue *q);
void destroy_DPI_res_flush_queue(DPIResultFlushQueue *q);
int enqueue_DPI_res_flush_queue(DPIResultFlushQueue *q, DPIResultFlushQueueItem item);
DPIResultFlushQueueItem dequeue_DPI_res_flush_queue(DPIResultFlushQueue *q);
void DPI_res_flush_queue_finish(DPIResultFlushQueue *q);

#endif // DPI_RESULT_FLUSH_QUEUE_H