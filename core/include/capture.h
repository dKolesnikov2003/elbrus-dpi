#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

#include "elbrus_dpi_api.h"
#include "packet_processor.h"

extern char file_and_table_name_pattern[128];

typedef struct {
    uint64_t timestamp_ms;
    int64_t pcap_file_offset; // смещение в файле pcap
    int32_t packet_length;
} RawDataIndexLogEntry;

typedef struct {
    pcap_t *pcap_handle;
    PacketQueue *queues;
    RawDataIndexLogEntry *pcap_file_offsets; // динамический массив лог записей данного потока
    size_t result_count;
    size_t result_capacity;
    FlushQueue *flush_queue;
    pthread_mutex_t results_mutex;
} CaptureThreadArgs;

// Инициализация pcap (возвращает pcap_t* или NULL, опционально bpf-фильтр)
pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len, void (*sigint_handler)(int), FlushQueue *flush_queue);

// Захват пакетов с распределением по очередям
int distribute_packets(pcap_t *pcap, PacketQueue queues[]);

// Поток захвата (аргумент: CaptureThreadArgs*)
void *capture_thread_func(void *arg);

#endif // CAPTURE_H
