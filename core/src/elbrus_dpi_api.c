#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>

#include "config.h"
#include "capture.h"
#include "packet_processor.h"
#include "db_writer.h"

// Глобальный массив параметров потоков и дескрипторов потоков
static ThreadParam thread_params[THREAD_COUNT];
static pthread_t threads[THREAD_COUNT];

const char *get_default_db_path(void)
{
    return DEFAULT_DB_PATH_AND_FILENAME;
}

const char *get_relative_db_path(void) 
{
    return RELATIVE_DB_PATH;
}

int start_analysis(const CaptureOptions *opts)
{
    FlushQueue flush_queue;
    flush_queue_init(&flush_queue);
    pthread_mutex_init(&flush_queue.mutex, NULL);
    pthread_cond_init(&flush_queue.cond_nonempty, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = capture_init(opts, errbuf, sizeof(errbuf), NULL, &flush_queue);
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (db_writer_init(opts) != 0)
    {
        fprintf(stderr, "Не удалось открыть/создать БД '%s'\n", opts->db_name);
        return EXIT_FAILURE;
    }

    // Создаем очереди для каждого потока и инициализируем nDPI для каждого потока
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
        ndpi_infos[i].flush_queue = &flush_queue;
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
    // Поток захвата
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
    pthread_t flusher_thread;
    pthread_create(&flusher_thread, NULL, db_flusher_thread, &flush_queue);

    // Ожидаем завершения всех потоков
    pthread_join(capture_thread, NULL);
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    // Финальный flush всех потоков в очередь
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        pthread_mutex_lock(&ndpi_infos[i].results_mutex);
        if (ndpi_infos[i].result_count > 0)
        {
            FlushBuffer *flush_buf = malloc(sizeof(FlushBuffer));
            flush_buf->entries = ndpi_infos[i].results;
            flush_buf->count = ndpi_infos[i].result_count;
            flush_queue_push(&flush_queue, flush_buf);
            ndpi_infos[i].results = NULL;
            ndpi_infos[i].result_count = 0;
        }
        else if (ndpi_infos[i].results != NULL)
        {
            free(ndpi_infos[i].results);
            ndpi_infos[i].results = NULL;
        }
        pthread_mutex_unlock(&ndpi_infos[i].results_mutex);
    }

    // Сигнализируем потоку-сбросчику, что больше буферов не будет
    flush_queue_terminate(&flush_queue);

    // Ожидаем завершения потока-сбросчика
    pthread_join(flusher_thread, NULL);

    // Освобождаем ресурсы
    pthread_mutex_destroy(&flush_queue.mutex);
    pthread_cond_destroy(&flush_queue.cond_nonempty);
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        pthread_mutex_destroy(&ndpi_infos[i].results_mutex);
        free_thread_resources(&ndpi_infos[i]);
        destroy_queue(&queues[i]);
    }
    pcap_close(pcap_handle);
    return EXIT_SUCCESS;
}