
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

#include "common.h"
#include "packet_queue.h"


char file_and_table_name_pattern[128]; // Глобальная переменная для хранения шаблона имени файла и таблицы

// Выбирает ID потока (0..THREAD_COUNT-1) по содержимому пакета (используется в главном потоке)
int select_thread_for_packet(const unsigned char *packet, uint32_t caplen) {
    // Анализируем заголовок канального уровня (Ethernet) для определения протокола L3
    if(caplen < 14) {
        return 0; // пакет слишком мал, отправим в поток 0 (например)
    }
    uint16_t ethertype = ntohs(*(uint16_t*)(packet + 12));
    unsigned int offset = 14;
    // Обработка VLAN-тегов 802.1Q (если есть)
    if(ethertype == 0x8100 || ethertype == 0x88A8) {
        // Если пакет содержит VLAN, смещаем указатель на 4 байта (TPID+TCI)
        if(caplen < 18) {
            return 0;
        }
        ethertype = ntohs(*(uint16_t*)(packet + 16));
        offset = 18;
        // Примечание: Для нескольких вложенных VLAN (QinQ) потребуется дополнительное смещение
        if(ethertype == 0x8100 || ethertype == 0x88A8) {
            // Простейшая обработка второго VLAN-тега
            if(caplen < 22) {
                return 0;
            }
            ethertype = ntohs(*(uint16_t*)(packet + 20));
            offset = 22;
        }
    }
    // Переменные для IP адресов и портов
    uint32_t src_ip = 0, dst_ip = 0;
    uint64_t src_ip6[2] = {0,0}, dst_ip6[2] = {0,0};
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    // Определяем тип сетевого протокола
    if(ethertype == 0x0800 && caplen >= offset + sizeof(struct iphdr)) {
        // IPv4
        struct iphdr *ip = (struct iphdr*)(packet + offset);
        if(ip->ihl < 5) {
            // Неверная длина заголовка IPv4
            return 0;
        }
        uint32_t ip_hdr_len = ip->ihl * 4;
        if(caplen < offset + ip_hdr_len) {
            return 0;
        }
        src_ip = ip->saddr;
        dst_ip = ip->daddr;
        proto = ip->protocol;
        // Определяем порты для TCP/UDP
        if(proto == IPPROTO_TCP && caplen >= offset + ip_hdr_len + sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr*)(packet + offset + ip_hdr_len);
            src_port = ntohs(tcp->source);
            dst_port = ntohs(tcp->dest);
        } else if(proto == IPPROTO_UDP && caplen >= offset + ip_hdr_len + sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr*)(packet + offset + ip_hdr_len);
            src_port = ntohs(udp->source);
            dst_port = ntohs(udp->dest);
        } else {
            src_port = dst_port = 0;
        }
        // Для симметричности потоков (чтобы прямой и обратный трафик попал в один поток) 
        // используем минимальный IP и максимальный порт при расчёте
        uint32_t min_ip = src_ip < dst_ip ? src_ip : dst_ip;
        uint32_t max_port = src_port > dst_port ? src_port : dst_port;
        // Вычисляем простой хеш
        uint64_t key = min_ip;
        key += proto;
        key += max_port;
        // Выбираем поток на основе хеша
        int thread = key % THREAD_COUNT;
        return thread;
    } else if(ethertype == 0x86DD && caplen >= offset + sizeof(struct ip6_hdr)) {
        // IPv6
        struct ip6_hdr *ip6 = (struct ip6_hdr*)(packet + offset);
        // IPv6 заголовок длиной 40 байт
        if(caplen < offset + sizeof(struct ip6_hdr)) {
            return 0;
        }
        // Копируем адреса IPv6 (128 бит каждый)
        memcpy(src_ip6, &ip6->ip6_src, 16);
        memcpy(dst_ip6, &ip6->ip6_dst, 16);
        proto = ip6->ip6_nxt;
        // Определяем порты для TCP/UDP (если следующий заголовок - TCP или UDP и без экст. заголовков)
        if(proto == IPPROTO_TCP) {
            size_t l4_offset = offset + sizeof(struct ip6_hdr);
            if(caplen >= l4_offset + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr*)(packet + l4_offset);
                src_port = ntohs(tcp->source);
                dst_port = ntohs(tcp->dest);
            }
        } else if(proto == IPPROTO_UDP) {
            size_t l4_offset = offset + sizeof(struct ip6_hdr);
            if(caplen >= l4_offset + sizeof(struct udphdr)) {
                struct udphdr *udp = (struct udphdr*)(packet + l4_offset);
                src_port = ntohs(udp->source);
                dst_port = ntohs(udp->dest);
            }
        } else {
            src_port = dst_port = 0;
        }
        // Для симметричности IPv6: используем меньший адрес (лексикографически) и больший порт
        // Сравниваем пару 128-битных адресов
        int use_src = 0;
        if(memcmp(src_ip6, dst_ip6, 16) < 0) {
            use_src = 1;
        }
        uint64_t min_addr_sum = 0;
        if(use_src) {
            min_addr_sum = src_ip6[0] + src_ip6[1];
        } else {
            min_addr_sum = dst_ip6[0] + dst_ip6[1];
        }
        uint16_t max_port = src_port > dst_port ? src_port : dst_port;
        uint64_t key = min_addr_sum;
        key += proto;
        key += max_port;
        int thread = key % THREAD_COUNT;
        return thread;
    } else {
        // Неподдерживаемый тип фрейма (например ARP), отправляем в поток 0
        return 0;
    }
}

// Функция чтения пакетов из pcap и распределения по потокам
int distribute_packets(pcap_t *pcap, PacketQueue queues[]) {
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;
    int status;
    int error_occurred = 0;
    uint64_t packet_count = 0;
    // Читаем пакеты из pcap файла по одному
    while((status = pcap_next_ex(pcap, &header, &pkt_data)) >= 0) {
        if(status == 0) {
            // 0 означает таймаут (для оффлайн не должно быть, но на всякий случай)
            continue;
        }
        packet_count++;
        // Копируем данные пакета, т.к. pcap_next_ex возвращает указатель на внутренний буфер
        unsigned char *data_copy = (unsigned char*)malloc(header->caplen);
        if(data_copy == NULL) {
            fprintf(stderr, "Ошибка: недостаточно памяти для копирования пакета\n");
            error_occurred = 1;
            break;
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
    if(status == -1) {
        // Ошибка чтения pcap
        fprintf(stderr, "Ошибка pcap: %s\n", pcap_geterr(pcap));
        error_occurred = 1;
    }
    // Завершаем очереди, добавляя сигнал окончания (sentinel) для каждого потока
    for(int i = 0; i < THREAD_COUNT; ++i) {
        enqueue_terminate(&queues[i]);
    }
    return error_occurred ? -1 : 0;
}

pcap_t *capture_init(const CaptureOptions *opt, char *errbuf, size_t errbuf_len) {
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

    return pcap_handle;
}

void *capture_thread_func(void *arg) {
    CaptureThreadArgs *args = (CaptureThreadArgs *)arg;
    distribute_packets(args->pcap_handle, args->queues);
    for (int i = 0; i < THREAD_COUNT; ++i) {
        enqueue_terminate(&args->queues[i]);
    }
    return NULL;
}