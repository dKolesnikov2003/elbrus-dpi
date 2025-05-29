#include "packet_queue.h"

#include <string.h>
#include <pthread.h>


// Инициализация очереди пакетов
void init_queue(PacketQueue *q) {
    q->capacity = 1024;  // начальный размер очереди
    q->items = (PacketQueueItem*)malloc(q->capacity * sizeof(PacketQueueItem));
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_nonempty, NULL);
    pthread_cond_init(&q->cond_nonfull, NULL);
}

// Уничтожение очереди пакетов (освобождение памяти и ресурсов синхронизации)
void destroy_queue(PacketQueue *q) {
    free(q->items);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_nonempty);
    pthread_cond_destroy(&q->cond_nonfull);
}

// Поместить пакет в очередь (с блокировкой, если очередь заполнена)
void enqueue_packet(PacketQueue *q, PacketQueueItem item) {
    pthread_mutex_lock(&q->mutex);
    // Если очередь полна, ждем освобождения места
    while(q->count == q->capacity) {
        pthread_cond_wait(&q->cond_nonfull, &q->mutex);
    }
    // Вставляем элемент в конец очереди
    q->items[q->rear] = item;
    q->rear = (q->rear + 1) % q->capacity;
    q->count++;
    // Сигнализируем, что очередь не пуста
    pthread_cond_signal(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
}

// Извлечь пакет из очереди (блокируется, если очередь пуста)
// Возвращает PacketQueueItem; если data == NULL, значит получен сигнал завершения
PacketQueueItem dequeue_packet(PacketQueue *q) {
    pthread_mutex_lock(&q->mutex);
    // Ждем, пока в очереди появится элемент
    while(q->count == 0) {
        pthread_cond_wait(&q->cond_nonempty, &q->mutex);
    }
    // Берем элемент из начала очереди
    PacketQueueItem item = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->count--;
    // Сигнализируем, что появилось свободное место
    pthread_cond_signal(&q->cond_nonfull);
    pthread_mutex_unlock(&q->mutex);
    return item;
}

// Добавить в очередь специальный "терминатор", сигнализирующий о завершении ввода
void enqueue_terminate(PacketQueue *q) {
    PacketQueueItem term;
    memset(&term, 0, sizeof(term));
    term.data = NULL; // null-указатель будет признаком окончания
    enqueue_packet(q, term);
}