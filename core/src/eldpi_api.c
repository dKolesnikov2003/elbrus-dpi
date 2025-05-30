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

#include "eldpi_api.h"
#include "common.h"
#include "capture.h"
#include "packet_processor.h"
#include "packet_queue.h"
#include "DPI_result_flush_queue.h"
#include "raw_packets_log_flush_queue.h"
#include "db_writer.h"
#include "flusher.h"


// Функция парсинга аргументов командной строки
int parse_args(int argc, char **argv, CaptureOptions *opt) {
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


const char *get_DB_file_name(void) {
    return DB_FILE_NAME;
}

const char *get_DB_folder(void) {
    return DB_FOLDER;
}

const char *get_DB_path(void) {
    return DB_FILE_PATH;
}

int start_analysis(const CaptureOptions *opts) {
    DPIResultFlushQueue results_queue;
    init_DPI_res_flush_queue(&results_queue);
    // Инициализируем очередь для логов пакетов
    RawPacketsLogFlushQueue raw_log_queue;
    init_raw_packs_log_flush_queue(&raw_log_queue);
    // Инициализируем pcap захват
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = capture_init(opts, errbuf, sizeof(errbuf));
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (dpi_db_init(opts) != 0)
    {
        fprintf(stderr, "Не удалось открыть/создать БД '%s'\n", get_DB_path());
        return EXIT_FAILURE;
    }

    // Глобальный массив параметров потоков и дескрипторов потоков
    ThreadParam thread_params[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    PacketQueue queues[THREAD_COUNT];
    NDPI_ThreadInfo ndpi_infos[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        init_queue(&queues[i]);
        if (init_ndpi_detection(&ndpi_infos[i]) != 0)
        {
            fprintf(stderr, "Ошибка инициализации nDPI для потока %d\n", i);
            return EXIT_FAILURE;
        }
        
        // Заполняем параметры для потока
        ndpi_infos[i].resultsQueue = &results_queue;
        thread_params[i].thread_id = i;
        thread_params[i].pcap_handle = pcap_handle;
        thread_params[i].queue = &queues[i];
        thread_params[i].ndpi_info = &ndpi_infos[i];
        // Запускаем поток обработки
        if (pthread_create(&threads[i], NULL, packet_processor_thread, &thread_params[i]) != 0)
        {
            fprintf(stderr, "Ошибка: не удалось создать поток %d\n", i);
            return EXIT_FAILURE;
        }
    }    
    pthread_t capture_thread;
    CaptureThreadArgs capture_args = {
        .pcap_handle = pcap_handle,
        .queues = queues};
    if (pthread_create(&capture_thread, NULL, capture_thread_func, &capture_args) != 0)
    {
        fprintf(stderr, "Ошибка: не удалось создать поток захвата\n");
        return EXIT_FAILURE;
    }
    // Поток для сброса результатов в базу данных
    pthread_t flusher_tid;;
    pthread_create(&flusher_tid, NULL, flusher_thread, &results_queue);

    // Ожидаем завершения всех потоков
    pthread_join(capture_thread, NULL);
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    // Финальный flush всех потоков в очередь
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        free_thread_resources(&ndpi_infos[i]);
    }

    // Сигнализируем потоку-сбросчику, что больше буферов не будет
    DPI_res_flush_queue_finish(&results_queue);

    // Ожидаем завершения потока-сбросчика
    pthread_join(flusher_tid, NULL);

    // Освобождаем ресурсы
    destroy_DPI_res_flush_queue(&results_queue);
    destroy_raw_packs_log_flush_queue(&raw_log_queue);
    
    pcap_close(pcap_handle);
    return EXIT_SUCCESS;
}

// int main(int argc, char *argv[]) {
//     const char *log_filename;
//     const char *pcap_filename = parse_args(argc, argv, &log_filename);
//     if(pcap_filename == NULL) {
//         return EXIT_FAILURE;
//     }
//     // Открываем pcap-файл для оффлайн чтения
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t *pcap_handle = pcap_open_offline(pcap_filename, errbuf);
//     if(pcap_handle == NULL) {
//         fprintf(stderr, "Не удалось открыть pcap-файл: %s\n", errbuf);
//         return EXIT_FAILURE;
//     }

//     // Создаем очереди для каждого потока и инициализируем nDPI для каждого потока
//     PacketQueue queues[THREAD_COUNT];
//     NDPI_ThreadInfo ndpi_infos[THREAD_COUNT];
//     for(int i = 0; i < THREAD_COUNT; ++i) {
//         init_queue(&queues[i]);
//         if(init_ndpi_detection(&ndpi_infos[i]) != 0) {
//             fprintf(stderr, "Ошибка инициализации nDPI для потока %d\n", i);
//             return EXIT_FAILURE;
//         }
//         // Заполняем параметры для потока
//         thread_params[i].thread_id = i;
//         thread_params[i].pcap_handle = pcap_handle;
//         thread_params[i].queue = &queues[i];
//         thread_params[i].ndpi_info = &ndpi_infos[i];
//         // Запускаем поток обработки
//         if(pthread_create(&threads[i], NULL, packet_processor_thread, &thread_params[i]) != 0) {
//             fprintf(stderr, "Ошибка: не удалось создать поток %d\n", i);
//             return EXIT_FAILURE;
//         }
//     }

//     // В главном потоке распределяем пакеты по очередям
//     if(distribute_packets(pcap_handle, queues) != 0) {
//         // Если произошла ошибка при чтении пакетов
//         // Посылаем сигнал всем потокам завершиться
//         for(int i = 0; i < THREAD_COUNT; ++i) {
//             enqueue_terminate(&queues[i]);
//         }
//     }

//     // Ожидаем завершения всех потоков
//     for(int i = 0; i < THREAD_COUNT; ++i) {
//         pthread_join(threads[i], NULL);
//     }

//     // Теперь собираем результаты из всех потоков и выводим их
//     // Объединяем все записи в один список для сортировки
//     PacketLogEntry *all_results = NULL;
//     size_t total_results = 0;
//     for(int i = 0; i < THREAD_COUNT; ++i) {
//         total_results += ndpi_infos[i].result_count;
//     }
//     all_results = (PacketLogEntry*)malloc(total_results * sizeof(PacketLogEntry));
//     if(all_results == NULL) {
//         fprintf(stderr, "Ошибка: недостаточно памяти для объединения результатов\n");
//         // Освобождаем ресурсы и завершаем
//         for(int i = 0; i < THREAD_COUNT; ++i) {
//             free_thread_resources(&ndpi_infos[i]);
//             destroy_queue(&queues[i]);
//         }
//         pcap_close(pcap_handle);
//         return EXIT_FAILURE;
//     }
//     size_t offset = 0;
//     for(int i = 0; i < THREAD_COUNT; ++i) {
//         // Копируем результаты потока i в общий массив
//         memcpy(all_results + offset, ndpi_infos[i].results, ndpi_infos[i].result_count * sizeof(PacketLogEntry));
//         offset += ndpi_infos[i].result_count;
//     }

//     // Открываем файл лога, если указан, иначе будем писать в stdout
//     FILE *out = stdout;
//     if(log_filename != NULL) {
//         out = fopen(log_filename, "w");
//         if(out == NULL) {
//             fprintf(stderr, "Не удалось открыть файл лога %s для записи: %s\n", log_filename, strerror(errno));
//             out = stdout;
//         }
//     }

//     // Выводим заголовок лога
//     fprintf(out, "Результаты анализа pcap-файла \"%s\":\n", pcap_filename);
//     fprintf(out, "Всего классифицированных пакетов: %zu\n\n", total_results);
//     // Выводим записи, уже отсортированные по протоколам
//     for(size_t i = 0; i < total_results; ++i) {
//         PacketLogEntry *entry = &all_results[i];
//         // Формируем человекочитаемые адреса
//         char src_str[INET6_ADDRSTRLEN];
//         char dst_str[INET6_ADDRSTRLEN];
//         if(entry->ip_version == 4) {
//             inet_ntop(AF_INET, &entry->ip_src.v4, src_str, sizeof(src_str));
//             inet_ntop(AF_INET, &entry->ip_dst.v4, dst_str, sizeof(dst_str));
//         } else if(entry->ip_version == 6) {
//             inet_ntop(AF_INET6, &entry->ip_src.v6, src_str, sizeof(src_str));
//             inet_ntop(AF_INET6, &entry->ip_dst.v6, dst_str, sizeof(dst_str));
//         } else {
//             strcpy(src_str, "N/A");
//             strcpy(dst_str, "N/A");
//         }
//         fprintf(out, "[%s] %s:%u -> %s:%u (len=%u)\n",
//                 entry->protocol_name,
//                 src_str, entry->src_port,
//                 dst_str, entry->dst_port,
//                 entry->packet_length);
//     }

//     // Освобождаем ресурсы: закрываем файл вывода, освобождаем память, закрываем pcap
//     if(out != stdout) {
//         fclose(out);
//     }
//     free(all_results);
//     pcap_close(pcap_handle);

//     return EXIT_SUCCESS;
// }
