#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <pcap.h>

#include "capture.h"
#include "config.h"
#include "packet_processor.h"

static volatile sig_atomic_t stop_capture = 0;
static pcap_t *g_pcap_handle = NULL;

static void default_sigint_handler(int signo) {
    (void)signo;
    stop_capture = 1;
    const char *msg = "\nПрерывание захвата (Ctrl+C)...\n";
    write(STDERR_FILENO, msg, strlen(msg));
    if(g_pcap_handle) pcap_breakloop(g_pcap_handle);
}

int parse_args(int argc, char **argv, CaptureOptions *opt) {
    memset(opt, 0, sizeof(*opt));
    opt->mode = -1;
    opt->db_name = DEFAULT_DB_FILENAME;
    signal(SIGINT, default_sigint_handler);
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
        } else if(strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--db") == 0) {
            if(++i >= argc) { fprintf(stderr, "-d требует аргумент\n"); return -1; }
            opt->db_name = argv[i];
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

pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len, void (*sigint_handler)(int)) {
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
    g_pcap_handle = pcap_handle;
    return pcap_handle;
}

int distribute_packets(pcap_t *pcap, PacketQueue queues[]) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int status;
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
        int thread_id = select_thread_for_packet(data_copy, header->caplen);
        PacketQueueItem item;
        item.header = *header;
        item.data = data_copy;
        enqueue_packet(&queues[thread_id], item);
    }

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
