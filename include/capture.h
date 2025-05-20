#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "packet_processor.h"

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CaptureMode;

typedef struct {
    CaptureMode mode;       /* файл или интерфейс */
    const char *source;     /* имя pcap или интерфейса */
    const char *bpf;        /* -b фильтр (опц.) */
} CaptureOptions;

typedef struct {
    pcap_t *pcap_handle;
    PacketQueue *queues;
} CaptureThreadArgs;

// Парсинг аргументов командной строки
int parse_args(int argc, char **argv, CaptureOptions *opt);

// Инициализация pcap (возвращает pcap_t* или NULL, опционально bpf-фильтр)
pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len, void (*sigint_handler)(int));

// Захват пакетов с распределением по очередям
int distribute_packets(pcap_t *pcap, PacketQueue queues[]);

// Поток захвата (аргумент: CaptureThreadArgs*)
void *capture_thread_func(void *arg);

#endif // CAPTURE_H
