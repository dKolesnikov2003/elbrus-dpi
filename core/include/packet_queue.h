#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdlib.h>
#include <pthread.h>

#include <pcap.h>


// Структура для элемента очереди пакетов
typedef struct {
    struct pcap_pkthdr header;  // Заголовок pcap (время, длины)
    unsigned char *data;        // Указатель на данные пакета (скопированный буфер)
} PacketQueueItem;

// Очередь пакетов с поддержкой синхронизации между потоками
typedef struct {
    PacketQueueItem *items;
    int capacity;
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
} PacketQueue;

// Функции работы с очередью пакетов
void init_queue(PacketQueue *q);
void destroy_queue(PacketQueue *q);
void enqueue_packet(PacketQueue *q, PacketQueueItem item);
PacketQueueItem dequeue_packet(PacketQueue *q);
void enqueue_terminate(PacketQueue *q);  // поставить специальный элемент-заглушку, сигнализирующий об окончании

#endif // PACKET_QUEUE_H