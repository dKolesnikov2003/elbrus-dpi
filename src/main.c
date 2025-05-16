#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#include "packet_processor.h"

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CaptureMode;

typedef struct {
    CaptureMode mode;       /* файл или интерфейс */
    const char *source;     /* имя pcap или интерфейса */
    const char *logfile;    /* -o лог */
    const char *bpf;        /* -b фильтр (опц.) */
} CaptureOptions;

static volatile sig_atomic_t stop_capture = 0;
static pcap_t *g_pcap_handle = NULL;

static void handle_sigint(int signo) {
    (void)signo;
    stop_capture = 1;
    if(g_pcap_handle) pcap_breakloop(g_pcap_handle);
}

/* CLI:  -f <file> | -i <iface>  [-o <log>] [-b "bpf"] */
static int parse_args(int argc, char **argv, CaptureOptions *opt) {
    memset(opt, 0, sizeof(*opt));
    opt->mode = -1;
    for(int i = 1; i < argc; ++i) {
        if(strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if(++i >= argc) { fprintf(stderr, "-f требует аргумент\n"); return -1; }
            opt->mode = CAP_SRC_FILE;
            opt->source = argv[i];
        } else if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if(++i >= argc) { fprintf(stderr, "-i требует аргумент\n"); return -1; }
            opt->mode = CAP_SRC_IFACE;
            opt->source = argv[i];
        } else if(strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if(++i >= argc) { fprintf(stderr, "-o требует аргумент\n"); return -1; }
            opt->logfile = argv[i];
        } else if(strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bpf") == 0) {
            if(++i >= argc) { fprintf(stderr, "-b требует аргумент\n"); return -1; }
            opt->bpf = argv[i];
        } else {
            fprintf(stderr, "Неизвестный параметр: %s\n", argv[i]);
            return -1;
        }
    }
    if(opt->mode == -1) {
        fprintf(stderr, "Обязателен -f <pcap> или -i <iface>\n");
        return -1;
    }
    return 0;
}


// Количество потоков обработки (по умолчанию 8 для Эльбрус-8C)
#define THREAD_COUNT 8

// Структура для передачи параметров потоку обработки

// Глобальный массив параметров потоков и дескрипторов потоков
static ThreadParam thread_params[THREAD_COUNT];
static pthread_t threads[THREAD_COUNT];


// Функция чтения пакетов из pcap и распределения по потокам
int distribute_packets(pcap_t *pcap, PacketQueue queues[]) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int status;
    uint64_t packet_count = 0;
    // Читаем пакеты из pcap файла по одному
    while((status = pcap_next_ex(pcap, &header, &pkt_data)) >= 0) {
        if(status == 0) {
            // таймаут
            continue;
        }
        packet_count++;
        // Копируем данные пакета, т.к. pcap_next_ex возвращает указатель на внутренний буфер
        u_char *data_copy = (u_char*)malloc(header->caplen);
        if(data_copy == NULL) {
            fprintf(stderr, "Ошибка: недостаточно памяти для копирования пакета\n");
            return -1;
        }
        memcpy(data_copy, pkt_data, header->caplen);
        // Определяем, к какому потоку отнести пакет (хешируем по IP/портам)
        int thread_id = select_thread_for_packet(data_copy, header->caplen);
        // Создаем структуру пакета для очереди
        PacketQueueItem item;
        item.header = *header;
        item.data = data_copy;
        // Добавляем пакет в соответствующую очередь
        enqueue_packet(&queues[thread_id], item);
    }
    if(status == PCAP_ERROR_BREAK || stop_capture) {
        /* Захват прерван (Ctrl‑C) */
        fprintf(stderr, "Захват прерван: %s\n", pcap_geterr(pcap));
        return -1;
    } else if(status == -1) {
        fprintf(stderr, "Ошибка pcap: %s\n", pcap_geterr(pcap));
        return -1;
     }
    // Завершаем очереди, добавляя сигнал окончания (sentinel) для каждого потока
    for(int i = 0; i < THREAD_COUNT; ++i) {
        enqueue_terminate(&queues[i]);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    CaptureOptions opts;
    if(parse_args(argc, argv, &opts) != 0) {
        fprintf(stderr, "Использование: %s -f <pcap> | -i <iface> [-o log] [-b 'bpf']\n", argv[0]);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;
    if(opts.mode == CAP_SRC_FILE) {
        pcap_handle = pcap_open_offline(opts.source, errbuf);
    } else {
        pcap_handle = pcap_open_live(opts.source, 65535, 1, 1000, errbuf);
        signal(SIGINT, handle_sigint);
        if(opts.bpf && pcap_handle) {
            struct bpf_program prog;
            if(pcap_compile(pcap_handle, &prog, opts.bpf, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
               pcap_setfilter(pcap_handle, &prog) == -1) {
                fprintf(stderr, "BPF ошибка: %s\n", pcap_geterr(pcap_handle));
            }
            pcap_freecode(&prog);
        }
    }
    if(pcap_handle == NULL) {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    g_pcap_handle = pcap_handle;
    
    const char *log_filename = opts.logfile;
    const char *capture_name = opts.source;

    // Создаем очереди для каждого потока и инициализируем nDPI для каждого потока
    PacketQueue queues[THREAD_COUNT];
    NDPI_ThreadInfo ndpi_infos[THREAD_COUNT];
    for(int i = 0; i < THREAD_COUNT; ++i) {
        init_queue(&queues[i]);
        if(init_ndpi_detection(&ndpi_infos[i]) != 0) {
            fprintf(stderr, "Ошибка инициализации nDPI для потока %d\n", i);
            return EXIT_FAILURE;
        }
        // Заполняем параметры для потока
        thread_params[i].thread_id = i;
        thread_params[i].pcap_handle = pcap_handle;
        thread_params[i].queue = &queues[i];
        thread_params[i].ndpi_info = &ndpi_infos[i];
        // Запускаем поток обработки
        if(pthread_create(&threads[i], NULL, packet_processor_thread, &thread_params[i]) != 0) {
            fprintf(stderr, "Ошибка: не удалось создать поток %d\n", i);
            return EXIT_FAILURE;
        }
    }

    // В главном потоке распределяем пакеты по очередям
    if(distribute_packets(pcap_handle, queues) != 0) {
        // Если произошла ошибка при чтении пакетов
        // Посылаем сигнал всем потокам завершиться
        for(int i = 0; i < THREAD_COUNT; ++i) {
            enqueue_terminate(&queues[i]);
        }
    }

    // Ожидаем завершения всех потоков
    for(int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Теперь собираем результаты из всех потоков и выводим их
    // Объединяем все записи в один список для сортировки
    PacketLogEntry *all_results = NULL;
    size_t total_results = 0;
    for(int i = 0; i < THREAD_COUNT; ++i) {
        total_results += ndpi_infos[i].result_count;
    }
    all_results = (PacketLogEntry*)malloc(total_results * sizeof(PacketLogEntry));
    if(all_results == NULL) {
        fprintf(stderr, "Ошибка: недостаточно памяти для объединения результатов\n");
        // Освобождаем ресурсы и завершаем
        for(int i = 0; i < THREAD_COUNT; ++i) {
            free_thread_resources(&ndpi_infos[i]);
            destroy_queue(&queues[i]);
        }
        pcap_close(pcap_handle);
        return EXIT_FAILURE;
    }
    size_t offset = 0;
    for(int i = 0; i < THREAD_COUNT; ++i) {
        // Копируем результаты потока i в общий массив
        memcpy(all_results + offset, ndpi_infos[i].results, ndpi_infos[i].result_count * sizeof(PacketLogEntry));
        offset += ndpi_infos[i].result_count;
    }

    // Сортируем результаты по имени протокола (алфавитно) для группировки по протоколам
    qsort(all_results, total_results, sizeof(PacketLogEntry), compare_by_protocol);

    // Открываем файл лога, если указан, иначе будем писать в stdout
    FILE *out = stdout;
    if(log_filename != NULL) {
        out = fopen(log_filename, "w");
        if(out == NULL) {
            fprintf(stderr, "Не удалось открыть файл лога %s для записи: %s\n", log_filename, strerror(errno));
            out = stdout;
        }
    }

    // Выводим заголовок лога
    fprintf(out, "Результаты анализа источника \"%s\":\n", capture_name);
    fprintf(out, "Всего классифицированных пакетов: %zu\n\n", total_results);
    // Выводим записи, уже отсортированные по протоколам
    for(size_t i = 0; i < total_results; ++i) {
        PacketLogEntry *entry = &all_results[i];
        // Формируем человекочитаемые адреса
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        if(entry->ip_version == 4) {
            inet_ntop(AF_INET, &entry->ip_src.v4, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &entry->ip_dst.v4, dst_str, sizeof(dst_str));
        } else if(entry->ip_version == 6) {
            inet_ntop(AF_INET6, &entry->ip_src.v6, src_str, sizeof(src_str));
            inet_ntop(AF_INET6, &entry->ip_dst.v6, dst_str, sizeof(dst_str));
        } else {
            strcpy(src_str, "N/A");
            strcpy(dst_str, "N/A");
        }
        fprintf(out, "[%s] %s:%u -> %s:%u (len=%u)\n",
                entry->protocol_name,
                src_str, entry->src_port,
                dst_str, entry->dst_port,
                entry->packet_length);
    }

    // Освобождаем ресурсы: закрываем файл вывода, освобождаем память, закрываем pcap
    if(out != stdout) {
        fclose(out);
    }
    free(all_results);
    for(int i = 0; i < THREAD_COUNT; ++i) {
        free_thread_resources(&ndpi_infos[i]);
        destroy_queue(&queues[i]);
    }
    pcap_close(pcap_handle);

    return EXIT_SUCCESS;
}
