#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <pcap.h>

#include "capture.h"
#include "config.h"
#include "elbrus_dpi_api.h"
#include "packet_processor.h"

static volatile sig_atomic_t stop_capture = 0;
static pcap_t *g_pcap_handle = NULL;

char file_and_table_name_pattern[128];

static void default_sigint_handler(int signo) {
    (void)signo;
    stop_capture = 1;
    const char *msg = "\nПрерывание захвата (Ctrl+C)...\n";
    write(STDERR_FILENO, msg, strlen(msg));
    if(g_pcap_handle) pcap_breakloop(g_pcap_handle);
}

pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len, void (*sigint_handler)(int), FlushQueue *flush_queue) {
    pcap_t *pcap_handle = NULL;
    errbuf[0] = 0;
    if(opt->mode == CAP_SRC_FILE) {
        pcap_handle = pcap_open_offline(opt->source, errbuf);
    } else if(opt->mode == CAP_SRC_IFACE) {
        pcap_handle = pcap_open_live(opt->source, 65535, 1, 1000, errbuf);
        if(opt->bpf && pcap_handle) {
            struct bpf_program prog;
            if(pcap_compile(pcap_handle, &prog, opt->bpf, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
               pcap_setfilter(pcap_handle, &prog) == -1) {
                fprintf(stderr, "BPF ошибка: %s\n", pcap_geterr(pcap_handle));
            }
            pcap_freecode(&prog);
        }
    }
    if(opt->mode == CAP_SRC_FILE && !access(opt->source, F_OK)) {
        fprintf(stdout, "Захват из файла: %s\n", opt->source);
    } else if(opt->mode == CAP_SRC_IFACE && if_nametoindex(opt->source)) {
        fprintf(stdout, "Захват с интерфейса: %s\n", opt->source);
    }     

    time_t now    = time(NULL);
    struct tm tm  = *localtime(&now);
    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d_%H-%M-%S", &tm);

    const char *src_base = basename((char *)opt->source); 

    snprintf(file_and_table_name_pattern, sizeof(file_and_table_name_pattern),
                "%c-%s-%s",
                (opt->mode == CAP_SRC_FILE ? 'f' : 'i'),
                src_base, datebuf);

    g_pcap_handle = pcap_handle;
    signal(SIGINT, default_sigint_handler);
    return pcap_handle;
}

static void add_raw_data_log_to_flush_queue(FlushQueue *flush_queue, const u_char *data, size_t len) {
    //pthread_mutex_lock(&info->results_mutex);

    //pthread_mutex_unlock(&info->results_mutex);
}

int distribute_packets(pcap_t *pcap, PacketQueue queues[]) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int status;
    
    // Подготавлеваем имя файла для сохранения
    char file_full_path[256];
    snprintf(file_full_path, sizeof(file_full_path), "%s%s.pcap", get_relative_db_path(), file_and_table_name_pattern);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, file_full_path);
    if (dumper == NULL) {
        fprintf(stderr, "Не удалось открыть pcap файл для записи: %s\n", pcap_geterr(pcap));
        return -1;
    }

    uint64_t packet_count = 0;
    // Читаем пакеты по одному
    while((status = pcap_next_ex(pcap, &header, &pkt_data)) >= 0) {
        if(status == 0) continue;
        else if(status == -1) return -1;
        packet_count++;       
        u_char *data_copy = (u_char*)malloc(header->caplen);
        if(data_copy == NULL) {
            fprintf(stderr, "Ошибка: недостаточно памяти для копирования пакета\n");
            return -1;
        }
        memcpy(data_copy, pkt_data, header->caplen);
        // Сохраняем пакет в pcap файл
        pcap_dump((u_char *)dumper, header, pkt_data);
        int thread_id = select_thread_for_packet(data_copy, header->caplen);
        PacketQueueItem item;
        item.header = *header;
        item.data = data_copy;
        enqueue_packet(&queues[thread_id], item);
    }
    pcap_dump_close(dumper);
    return 0;
}

void *capture_thread_func(void *arg) {
    CaptureThreadArgs *args = (CaptureThreadArgs *)arg;
    distribute_packets(args->pcap_handle, args->queues);
    for (int i = 0; i < THREAD_COUNT; ++i) {
        enqueue_terminate(&args->queues[i]);
    }
    return NULL;
}
