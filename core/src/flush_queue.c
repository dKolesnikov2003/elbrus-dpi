#include "flush_queue.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "common.h"


void init_DPI_res_flush_queue(DPIResultFlushQueue *q) {
    q->capacity = 1024 * THREAD_COUNT;
    q->items = malloc(q->capacity * sizeof(DPIResultFlushQueueItem));
    q->count = 0;
    q->front = 0;
    q->rear = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_nonempty, NULL);
    pthread_cond_init(&q->cond_nonfull, NULL);
    q->is_finished = 0; // Очередь не завершена
}

void init_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q) {
    q->capacity = 1024 * THREAD_COUNT;
    q->items = malloc(q->capacity * sizeof(RawPacketsLogFlushQueueItem));
    q->count = 0;
    q->front = 0;
    q->rear = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_nonempty, NULL);
    pthread_cond_init(&q->cond_nonfull, NULL);
    q->is_finished = 0; // Очередь не завершена
}

void destroy_DPI_res_flush_queue(DPIResultFlushQueue *q) {
    free(q->items);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_nonempty);
    pthread_cond_destroy(&q->cond_nonfull);
}

void destroy_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q) {
    free(q->items);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_nonempty);
    pthread_cond_destroy(&q->cond_nonfull);
}

int enqueue_DPI_res_flush_queue(DPIResultFlushQueue *q, DPIResultFlushQueueItem item) {
    pthread_mutex_lock(&q->mutex);
    // Если очередь полна, ждем освобождения места
    while(q->count == q->capacity) {
        pthread_cond_wait(&q->cond_nonfull, &q->mutex);
    }
    // Если очередь помечена как завершённая — не даём писать
    if (q->is_finished) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    // Вставляем элемент в конец очереди
    q->items[q->rear] = item;
    q->rear = (q->rear + 1) % q->capacity;
    q->count++;
    // Сигнализируем, что очередь не пуста
    pthread_cond_signal(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int enqueue_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q, RawPacketsLogFlushQueueItem item) {
    pthread_mutex_lock(&q->mutex);
    // Если очередь полна, ждем освобождения места
    while(q->count == q->capacity) {
        pthread_cond_wait(&q->cond_nonfull, &q->mutex);
    }
    // Если очередь помечена как завершённая — не даём писать
    if (q->is_finished) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    // Вставляем элемент в конец очереди
    q->items[q->rear] = item;
    q->rear = (q->rear + 1) % q->capacity;
    q->count++;
    // Сигнализируем, что очередь не пуста
    pthread_cond_signal(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

DPIResultFlushQueueItem dequeue_DPI_res_flush_queue(DPIResultFlushQueue *q) {
    pthread_mutex_lock(&q->mutex);
    // Ждем, пока в очереди появится элемент
    while(q->count == 0 && !q->is_finished) {
        pthread_cond_wait(&q->cond_nonempty, &q->mutex);
    }
    // Если очередь завершена и пустая, возвращаем NULL
    if (q->is_finished && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return (DPIResultFlushQueueItem){0}; // Возвращаем пустой элемент
    }
    // Берем элемент из начала очереди
    DPIResultFlushQueueItem item = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->count--;
    // Сигнализируем, что появилось свободное место
    pthread_cond_signal(&q->cond_nonfull);
    pthread_mutex_unlock(&q->mutex);
    return item;
}

RawPacketsLogFlushQueueItem dequeue_raw_packs_log_flush_queue(RawPacketsLogFlushQueue *q) {
    pthread_mutex_lock(&q->mutex);
    // Ждем, пока в очереди появится элемент
    while(q->count == 0 && !q->is_finished) {
        pthread_cond_wait(&q->cond_nonempty, &q->mutex);
    }
    // Если очередь завершена и пустая, возвращаем NULL
    if (q->is_finished && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return (RawPacketsLogFlushQueueItem){0}; // Возвращаем пустой элемент
    }
    // Берем элемент из начала очереди
    RawPacketsLogFlushQueueItem item = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->count--;
    // Сигнализируем, что появилось свободное место
    pthread_cond_signal(&q->cond_nonfull);
    pthread_mutex_unlock(&q->mutex);
    return item;
}

void DPI_res_flush_queue_finish(DPIResultFlushQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->is_finished = 1; // Сигнализируем, что продюсеры завершили работу
    pthread_cond_broadcast(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
}

void raw_packs_log_flush_queue_finish(RawPacketsLogFlushQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->is_finished = 1; // Сигнализируем, что продюсеры завершили работу
    pthread_cond_broadcast(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
}