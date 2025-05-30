#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

#include "packet_processor.h"


extern char file_and_table_name_pattern[128];

typedef struct {
    pcap_t *pcap_handle;
    PacketQueue *queues;
} CaptureThreadArgs;

// Инициализация pcap (возвращает pcap_t* или NULL, опционально bpf-фильтр)
pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len);

// Захват пакетов с распределением по очередям
int distribute_packets(pcap_t *pcap, PacketQueue queues[]);

// Поток захвата (аргумент: CaptureThreadArgs*)
void *capture_thread_func(void *arg);

#endif // CAPTURE_H
