#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>
#include <signal.h>

#include "packet_processor.h"
#include "config.h"
#include "db_writer.h"

// Глобальный массив параметров потоков и дескрипторов потоков
static ThreadParam thread_params[THREAD_COUNT];
static pthread_t threads[THREAD_COUNT];

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

static volatile sig_atomic_t stop_capture = 0;
static pcap_t *g_pcap_handle = NULL;

static void handle_sigint(int signo) {
    (void)signo;
    stop_capture = 1;
    if(g_pcap_handle) pcap_breakloop(g_pcap_handle);
}

/* CLI:  -f <file> | -i <iface>  [-b "bpf"] */
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

    return 0;
}

void *capture_thread_func(void *arg) {
    CaptureThreadArgs *args = (CaptureThreadArgs *)arg;
    // Здесь захват + отправка в очереди
    distribute_packets(args->pcap_handle, args->queues);

    // Когда захват завершён — посылаем сигнал завершения обработчикам
    for (int i = 0; i < THREAD_COUNT; ++i) {
        enqueue_terminate(&args->queues[i]);
    }
    return NULL;
}

void* db_flusher_thread(void *arg) {
    FlushQueue *fq = (FlushQueue*)arg;
    FlushBuffer *buf;

    // Имя БД (или получите из параметров/глобальной переменной)
    static int db_initialized = 0;
    if(!db_initialized) {
        db_writer_init("results.db");
        db_initialized = 1;
    }

    while ((buf = flush_queue_pop(fq)) != NULL) {
        db_writer_insert_batch(buf->entries, buf->count);
        free(buf->entries);
        free(buf);
    }
    db_writer_close();
    return NULL;
}

void flush_queue_destroy(FlushQueue *fq) {
    pthread_mutex_destroy(&fq->mutex);
    pthread_cond_destroy(&fq->cond_nonempty);
}

int main(int argc, char *argv[]) {
    CaptureOptions opts;
    if(parse_args(argc, argv, &opts) != 0) {
        fprintf(stderr, "Использование: %s -f <pcap> | -i <iface> [-b 'bpf']\n", argv[0]);
        return EXIT_FAILURE;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;
    if(opts.mode == CAP_SRC_FILE) {
        pcap_handle = pcap_open_offline(opts.source, errbuf);
    } else if(opts.mode == CAP_SRC_IFACE) {
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

    // Создаем очереди для каждого потока и инициализируем nDPI для каждого потока
    PacketQueue queues[THREAD_COUNT];
    NDPI_ThreadInfo ndpi_infos[THREAD_COUNT];
    FlushQueue flush_queue;
    flush_queue_init(&flush_queue);

    for(int i = 0; i < THREAD_COUNT; ++i) {
        init_queue(&queues[i]);
        if(init_ndpi_detection(&ndpi_infos[i]) != 0) {
            fprintf(stderr, "Ошибка инициализации nDPI для потока %d\n", i);
            return EXIT_FAILURE;
        }
        pthread_mutex_init(&ndpi_infos[i].results_mutex, NULL);
        // Заполняем параметры для потока
        ndpi_infos[i].flush_queue = &flush_queue;
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
    // Поток захвата
    pthread_t capture_thread;
    CaptureThreadArgs capture_args = {
        .pcap_handle = pcap_handle,
        .queues = queues
    };
    if (pthread_create(&capture_thread, NULL, capture_thread_func, &capture_args) != 0) {
        fprintf(stderr, "Ошибка: не удалось создать поток захвата\n");
        return EXIT_FAILURE;
    }
    // Поток для сброса результатов в базу данных
    pthread_t flusher_thread;
    pthread_create(&flusher_thread, NULL, db_flusher_thread, &flush_queue);

    // Ожидаем завершения всех потоков
    pthread_join(capture_thread, NULL);
    for(int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Финальный flush всех потоков в очередь
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_mutex_lock(&ndpi_infos[i].results_mutex);
        if (ndpi_infos[i].result_count > 0) {
            FlushBuffer *flush_buf = malloc(sizeof(FlushBuffer));
            flush_buf->entries = ndpi_infos[i].results;
            flush_buf->count = ndpi_infos[i].result_count;
            flush_queue_push(&flush_queue, flush_buf);
            ndpi_infos[i].results = NULL;
            ndpi_infos[i].result_count = 0;
        } else {
            free(ndpi_infos[i].results);
        }
        pthread_mutex_unlock(&ndpi_infos[i].results_mutex);
    }

    // Сигнализируем потоку-сбросчику, что больше буферов не будет
    flush_queue_terminate(&flush_queue);

    // Ожидаем завершения потока-сбросчика
    pthread_join(flusher_thread, NULL);

    // Освобождаем ресурсы: освобождаем память, закрываем pcap

    flush_queue_destroy(&flush_queue);
    for(int i = 0; i < THREAD_COUNT; ++i) {
        pthread_mutex_destroy(&ndpi_infos[i].results_mutex);
        free_thread_resources(&ndpi_infos[i]);
        destroy_queue(&queues[i]);
    }
    pcap_close(pcap_handle);

    return EXIT_SUCCESS;
}
