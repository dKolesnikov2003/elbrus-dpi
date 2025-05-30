#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>

#include <pcap.h>
#include <ndpi/ndpi_api.h>

#include "packet_queue.h"
#include "flush_queue.h"


// Ключ (идентификатор) сетевого потока (Flow) для хеш-таблицы
typedef struct {
    uint8_t ip_version;  // 4 для IPv4, 6 для IPv6
    union {
        struct { uint32_t src_ip, dst_ip; } v4;
        struct { uint64_t src_ip[2], dst_ip[2]; } v6;
    } ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;          // протокол транспортного уровня (TCP/UDP/ICMP и т.д.)
} FlowKey;

// Информация о потоке обработки, включая nDPI и результаты
typedef struct {
    struct ndpi_detection_module_struct *ndpi_struct;  // локальная структура nDPI для потока
    // Хеш-таблица для отслеживания потоков (flows) данного потока обработки
    void *flow_table[8192];  // Используем как массив указателей на FlowNode (определяется внутри .c)
    DPIResultFlushQueue *resultsQueue; //  Очередь для хранения результатов обнаружения
    RawPacketsLogFlushQueue *rawPacketsLogQueue; // Очередь для хранения информации о смещении пакетов в pcap файле
} NDPI_ThreadInfo;

// Параметры, передаваемые в поток (определены в main.c)
typedef struct {
    int thread_id;
    pcap_t *pcap_handle;
    PacketQueue *queue;
    NDPI_ThreadInfo *ndpi_info;
} ThreadParam;

// Функции для работы с nDPI и потоками
int init_ndpi_detection(NDPI_ThreadInfo *info);
void free_thread_resources(NDPI_ThreadInfo *info);
int select_thread_for_packet(const u_char *packet, uint32_t caplen);
void *packet_processor_thread(void *arg);

#endif // PACKET_PROCESSOR_H
