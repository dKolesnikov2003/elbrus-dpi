#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>
#include <pthread.h>
#include <pcap.h>
#include <ndpi/ndpi_api.h>   // Заголовок библиотеки nDPI

// Структура для элемента очереди пакетов
typedef struct {
    struct pcap_pkthdr header;  // Заголовок pcap (время, длины)
    u_char *data;               // Указатель на данные пакета (скопированный буфер)
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

// Ключ (идентификатор) сетевого потока (Flow) для хеш-таблицы
typedef struct {
    uint8_t ip_version;  // 4 для IPv4, 6 для IPv6
    union {
        struct { uint32_t src_ip, dst_ip; } v4;
        struct { uint64_t src_ip[2], dst_ip[2]; } v6;
    } ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;       // протокол верхнего уровня (TCP/UDP/ICMP и т.д.)
} FlowKey;

// Структура записи в итоговом логе
typedef struct {
    uint8_t ip_version;
    union { struct in_addr v4; struct in6_addr v6; } ip_src;
    union { struct in_addr v4; struct in6_addr v6; } ip_dst;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_length;
    uint64_t timestamp_ms;    
    char protocol_name[64];
} PacketLogEntry;

typedef enum { DPI_RES_ONLY = 0, RAW_DATA_IDX = 1 } FlushQueuePurpose;

typedef struct FlushBuffer {
    FlushQueuePurpose purpose; // цель очереди: только результаты или с индексами на сырые данные
    PacketLogEntry *entries;
    size_t count;
    struct FlushBuffer *next;
} FlushBuffer;

typedef struct {
    FlushBuffer *head;
    FlushBuffer *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    int terminate;
} FlushQueue;

// Информация о потоке обработки, включая nDPI и результаты
typedef struct {
    struct ndpi_detection_module_struct *ndpi_struct;  // локальная структура nDPI для потока
    // Хеш-таблица для отслеживания потоков (flows) данного потока обработки
    void *flow_table[8192];  // Используем как массив указателей на FlowNode (определяется внутри .c)
    PacketLogEntry *results; // динамический массив результатов (лог записей) данного потока
    size_t result_count;
    size_t result_capacity;
    FlushQueue *flush_queue;
    pthread_mutex_t results_mutex; 
} NDPI_ThreadInfo;

// Параметры, передаваемые в поток
typedef struct {
    int thread_id;
    pcap_t *pcap_handle;
    PacketQueue *queue;
    NDPI_ThreadInfo *ndpi_info;
} ThreadParam;


// Функции работы с очередью пакетов
void init_queue(PacketQueue *q);
void destroy_queue(PacketQueue *q);
void enqueue_packet(PacketQueue *q, PacketQueueItem item);
PacketQueueItem dequeue_packet(PacketQueue *q);
void enqueue_terminate(PacketQueue *q);  // поставить специальный элемент-заглушку, сигнализирующий об окончании

// Функции для работы с nDPI и потоками
int init_ndpi_detection(NDPI_ThreadInfo *info);
void free_thread_resources(NDPI_ThreadInfo *info);
int select_thread_for_packet(const u_char *packet, uint32_t caplen);
void *packet_processor_thread(void *arg);

// Функции для работы с очередью буферов
void flush_queue_init(FlushQueue *fq);
void flush_queue_push(FlushQueue *fq, FlushBuffer *buf);
FlushBuffer* flush_queue_pop(FlushQueue *fq);
void flush_queue_terminate(FlushQueue *fq);
void flush_queue_destroy(FlushQueue *fq);

// Функция сравнения для сортировки результатов по имени протокола
int compare_by_protocol(const void *a, const void *b);

#endif // PACKET_PROCESSOR_H
