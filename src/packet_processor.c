#include "packet_processor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "config.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Константы для хеш-таблицы потоков в каждом потоке
#define FLOW_HASH_SIZE 8192  // размер таблицы хеширования потоков (должна быть степенью 2 для эффективности)

// Внутренняя структура для узла хеш-таблицы потоков (flows)
typedef struct FlowNode {
    FlowKey key;
    struct ndpi_flow_struct *ndpi_flow;
    struct FlowNode *next;
} FlowNode;

// Функция вычисления хеша по ключу потока (FlowKey)
static inline uint32_t flow_hash(const FlowKey *key) {
    uint64_t hash64 = 0;
    if(key->ip_version == 4) {
        // Для IPv4: суммируем адреса, порты и протокол
        hash64 = key->ip.v4.src_ip;
        hash64 += key->ip.v4.dst_ip;
        hash64 += (uint64_t)key->src_port << 16 | key->dst_port;
        hash64 += key->proto;
    } else if(key->ip_version == 6) {
        // Для IPv6: суммируем части адресов, порты и протокол
        hash64 = key->ip.v6.src_ip[0] ^ key->ip.v6.src_ip[1];
        hash64 ^= key->ip.v6.dst_ip[0] ^ key->ip.v6.dst_ip[1];
        hash64 += ((uint64_t)key->src_port << 16) | key->dst_port;
        hash64 += key->proto;
    }
    // Преобразуем 64-битный хеш в 32-битный индекс
    uint32_t hash32 = (uint32_t)(hash64 ^ (hash64 >> 32));
    return hash32 & (FLOW_HASH_SIZE - 1);
}

// Функция сравнения ключей потоков (для поиска в цепочке хеш-таблицы)
static inline int flow_key_equal(const FlowKey *a, const FlowKey *b) {
    if(a->ip_version != b->ip_version) return 0;
    if(a->src_port != b->src_port || a->dst_port != b->dst_port || a->proto != b->proto) return 0;
    if(a->ip_version == 4) {
        return (a->ip.v4.src_ip == b->ip.v4.src_ip && a->ip.v4.dst_ip == b->ip.v4.dst_ip);
    } else if(a->ip_version == 6) {
        return (a->ip.v6.src_ip[0] == b->ip.v6.src_ip[0] && 
                a->ip.v6.src_ip[1] == b->ip.v6.src_ip[1] &&
                a->ip.v6.dst_ip[0] == b->ip.v6.dst_ip[0] &&
                a->ip.v6.dst_ip[1] == b->ip.v6.dst_ip[1]);
    }
    return 0;
}

// Инициализация nDPI для потока
int init_ndpi_detection(NDPI_ThreadInfo *info) {
    // Инициализируем модуль обнаружения (без глобального контекста, NULL)
    info->ndpi_struct = ndpi_init_detection_module(NULL);
    if(info->ndpi_struct == NULL) {
        fprintf(stderr, "nDPI: не удалось инициализировать структуру обнаружения\n");
        return -1;
    }
    // Включаем распознавание всех поддерживаемых протоколов
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(info->ndpi_struct, &all);
    // Завершаем инициализацию (загружаем все сигнатуры)
    if(ndpi_finalize_initialization(info->ndpi_struct) != 0) {
        fprintf(stderr, "nDPI: ошибка finalize_initialization\n");
        return -1;
    }
    // Выделяем память под результаты (начально 0 записей, память будет увеличиваться по мере необходимости)
    info->result_capacity = 1024; // или другой разумный размер, не 0!
    info->results = malloc(info->result_capacity * sizeof(PacketLogEntry));
    if (!info->results) {
        fprintf(stderr, "Ошибка: не удалось выделить память для буфера результатов\n");
        ndpi_exit_detection_module(info->ndpi_struct);
        return -1;
    }
    info->result_count = 0;
    // Инициализируем хеш-таблицу потоков (изначально все бакеты пустые)
    memset(info->flow_table, 0, sizeof(info->flow_table));
    return 0;
}

// Освобождение ресурсов nDPI для потока (очистка памяти)
void free_thread_resources(NDPI_ThreadInfo *info) {
    if(info->results != NULL) {
        free(info->results);
        info->results = NULL;
    }
    // Освобождаем все потоки (flows) и их структуры
    for(int i = 0; i < FLOW_HASH_SIZE; ++i) {
        FlowNode *node = info->flow_table[i];
        while(node) {
            FlowNode *next = node->next;
            if(node->ndpi_flow) {
                ndpi_flow_free(node->ndpi_flow);   /* освобождает и вложенные данные, и саму struct ndpi_flow */
                node->ndpi_flow = NULL;            /* ← обнуляем, чтобы исключить случайные повторные вызовы */
            }
            free(node);
            node = next;
        }
        info->flow_table[i] = NULL;
    }
    // Освобождаем структуру обнаружения nDPI
    if(info->ndpi_struct) {
        ndpi_exit_detection_module(info->ndpi_struct);
        info->ndpi_struct = NULL;
    }
}

// Вспомогательная функция для добавления записи результата (лог) в массив результатов потока
static void add_result_entry(NDPI_ThreadInfo *info, PacketLogEntry *entry) {
    pthread_mutex_lock(&info->results_mutex);

    if (info->result_count == info->result_capacity) {
        FlushBuffer *flush_buf = malloc(sizeof(FlushBuffer));
        if (!flush_buf) {
            fprintf(stderr, "Ошибка: не удалось выделить память для FlushBuffer\n");
            pthread_mutex_unlock(&info->results_mutex);
            return;
        }

        flush_buf->entries = info->results;
        flush_buf->count = info->result_count;

        info->results = malloc(info->result_capacity * sizeof(PacketLogEntry));
        if (!info->results) {
            fprintf(stderr, "Ошибка: не удалось выделить память для нового буфера результатов\n");
            // мы уже отдали старый буфер на flush, поэтому не освобождаем!
            pthread_mutex_unlock(&info->results_mutex);
            return;
        }

        info->result_count = 0;

        flush_queue_push(info->flush_queue, flush_buf);
    }
    
    info->results[info->result_count++] = *entry;

    pthread_mutex_unlock(&info->results_mutex);
}

// Выбирает ID потока (0..THREAD_COUNT-1) по содержимому пакета (используется в главном потоке)
int select_thread_for_packet(const u_char *packet, uint32_t caplen) {
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

// Функция обработчика пакетов (потоковая функция)
void *packet_processor_thread(void *arg) {
    ThreadParam *param = (ThreadParam*)arg;
    int thread_id = param->thread_id;
    PacketQueue *queue = param->queue;
    NDPI_ThreadInfo *info = param->ndpi_info;

    // Бесконечный цикл ожидания пакетов в очереди
    while(1) {
        // Извлекаем следующий пакет из очереди (блокируется, если очередь пуста)
        PacketQueueItem item = dequeue_packet(queue);
        if(item.data == NULL) {
            // Получен сигнал завершения (sentinel)
            break;
        }
        // Выполняем анализ пакета с помощью nDPI
        // Вычисляем смещение до L3
        uint16_t ethertype = 0;
        unsigned int offset = 14;
        if(item.header.caplen >= 14) {
            ethertype = ntohs(*(uint16_t*)(item.data + 12));
            if(ethertype == 0x8100 || ethertype == 0x88A8) {
                if(item.header.caplen >= 18) {
                    ethertype = ntohs(*(uint16_t*)(item.data + 16));
                    offset = 18;
                    if(ethertype == 0x8100 || ethertype == 0x88A8) {
                        if(item.header.caplen >= 22) {
                            ethertype = ntohs(*(uint16_t*)(item.data + 20));
                            offset = 22;
                        }
                    }
                }
            }
        }
        // Подготовим структуру ключа потока для поиска/добавления в хеш-таблицу
        FlowKey key;
        memset(&key, 0, sizeof(key));
        // Указатель на начало L3 (IP) данных
        const uint8_t *l3_ptr = NULL;
        uint32_t l3_len = 0;
        if(ethertype == 0x0800 && item.header.caplen >= offset + sizeof(struct iphdr)) {
            // IPv4 пакет
            key.ip_version = 4;
            struct iphdr *ip = (struct iphdr*)(item.data + offset);
            if(ip->ihl < 5) {
                // Пропускаем некорректный IP
                free(item.data);
                continue;
            }
            uint32_t ip_hdr_len = ip->ihl * 4;
            if(item.header.caplen < offset + ip_hdr_len) {
                free(item.data);
                continue;
            }
            key.ip.v4.src_ip = ip->saddr;
            key.ip.v4.dst_ip = ip->daddr;
            key.proto = ip->protocol;
            // Задаем порты (для ключа потока тоже симметрично не обязательно, т.к. уникальный поток и так идентифицируется 5-ю составляющими)
            if(ip->protocol == IPPROTO_TCP && item.header.caplen >= offset + ip_hdr_len + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr*)(item.data + offset + ip_hdr_len);
                key.src_port = ntohs(tcp->source);
                key.dst_port = ntohs(tcp->dest);
            } else if(ip->protocol == IPPROTO_UDP && item.header.caplen >= offset + ip_hdr_len + sizeof(struct udphdr)) {
                struct udphdr *udp = (struct udphdr*)(item.data + offset + ip_hdr_len);
                key.src_port = ntohs(udp->source);
                key.dst_port = ntohs(udp->dest);
            } else {
                key.src_port = key.dst_port = 0;
            }
            l3_ptr = item.data + offset;
            l3_len = item.header.caplen - offset;
        } else if(ethertype == 0x86DD && item.header.caplen >= offset + sizeof(struct ip6_hdr)) {
            // IPv6 пакет
            key.ip_version = 6;
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(item.data + offset);
            if(item.header.caplen < offset + sizeof(struct ip6_hdr)) {
                free(item.data);
                continue;
            }
            // Копируем IPv6 адреса в ключ
            memcpy(key.ip.v6.src_ip, &ip6->ip6_src, 16);
            memcpy(key.ip.v6.dst_ip, &ip6->ip6_dst, 16);
            key.proto = ip6->ip6_nxt;
            // Порты для TCP/UDP (если без расширенных заголовков)
            if(key.proto == IPPROTO_TCP && item.header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr*)(item.data + offset + sizeof(struct ip6_hdr));
                key.src_port = ntohs(tcp->source);
                key.dst_port = ntohs(tcp->dest);
            } else if(key.proto == IPPROTO_UDP && item.header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                struct udphdr *udp = (struct udphdr*)(item.data + offset + sizeof(struct ip6_hdr));
                key.src_port = ntohs(udp->source);
                key.dst_port = ntohs(udp->dest);
            } else {
                key.src_port = key.dst_port = 0;
            }
            l3_ptr = item.data + offset;
            l3_len = item.header.caplen - offset;
        } else {
            // Неподдерживаемый L3 (например, ARP или слишком короткий) - пропускаем
            free(item.data);
            continue;
        }

        // Ищем или создаем flow в хеш-таблице потоков для данного ключа
        uint32_t index = flow_hash(&key);
        FlowNode *node = info->flow_table[index];
        FlowNode *found = NULL;
        while(node != NULL) {
            if(flow_key_equal(&node->key, &key)) {
                found = node;
                break;
            }
            node = node->next;
        }
        if(found == NULL) {
            // Не найден существующий поток, создаём новый
            FlowNode *new_node = (FlowNode*)malloc(sizeof(FlowNode));
            if(new_node == NULL) {
                fprintf(stderr, "Поток %d: недостаточно памяти для FlowNode\n", thread_id);
                free(item.data);
                continue;
            }
            new_node->key = key;
            new_node->next = info->flow_table[index];
            // Выделяем память под структуру ndpi_flow_struct
            new_node->ndpi_flow = (struct ndpi_flow_struct*)calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
            if(new_node->ndpi_flow == NULL) {
                fprintf(stderr, "Поток %d: недостаточно памяти для ndpi_flow_struct\n", thread_id);
                free(new_node);
                free(item.data);
                continue;
            }
            // Вставляем новый узел в таблицу
            info->flow_table[index] = new_node;
            found = new_node;
        }
        // Подготовим информацию о направлении потока для nDPI (необязательно для базового определения)
        struct ndpi_flow_struct *flow = found->ndpi_flow;
        // Время пакета в миллисекундах (на основе метки времени pcap)
        uint64_t time_ms = (uint64_t)item.header.ts.tv_sec * 1000 + item.header.ts.tv_usec / 1000;
        // Запускаем определение протокола для пакета
        ndpi_protocol detected_protocol = ndpi_detection_process_packet(
            info->ndpi_struct,
            flow,
            (uint8_t*)l3_ptr,
            l3_len,
            time_ms,
            NULL // входная информация о направлении не используется в базовой реализации
        );
        // Проверяем, был ли протокол обнаружен
        const char *proto_name = "Unknown";
        if(ndpi_is_protocol_detected(detected_protocol) && 
           (detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
            // Получаем имя протокола высшего уровня (приложения) или, если неизвестен, имя мастер-протокола
            if(detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
                proto_name = ndpi_get_proto_name(info->ndpi_struct, detected_protocol.proto.app_protocol);
            } else {
                proto_name = ndpi_get_proto_name(info->ndpi_struct, detected_protocol.proto.master_protocol);
            }
        }
        // Создаем запись для лога
        PacketLogEntry entry;
        entry.ip_version = key.ip_version;
        if(entry.ip_version == 4) {
            entry.ip_src.v4 = *(struct in_addr*)&key.ip.v4.src_ip;
            entry.ip_dst.v4 = *(struct in_addr*)&key.ip.v4.dst_ip;
        } else if(entry.ip_version == 6) {
            // struct in6_addr уже содержит 16 байт, копируем напрямую
            memcpy(&entry.ip_src.v6, key.ip.v6.src_ip, 16);
            memcpy(&entry.ip_dst.v6, key.ip.v6.dst_ip, 16);
        } else {
            // На случай непредвиденного
            memset(&entry.ip_src, 0, sizeof(entry.ip_src));
            memset(&entry.ip_dst, 0, sizeof(entry.ip_dst));
        }
        entry.src_port = key.src_port;
        entry.dst_port = key.dst_port;
        entry.packet_length = item.header.len;
        // Копируем имя протокола в структуру (оно может быть константой в nDPI, но скопируем для независимости)
        strncpy(entry.protocol_name, proto_name, sizeof(entry.protocol_name) - 1);
        entry.protocol_name[sizeof(entry.protocol_name) - 1] = '\0';
        // Добавляем запись в список результатов потока
        add_result_entry(info, &entry);

        // Освобождаем буфер пакета
        free(item.data);
    }

    return NULL;
}

// Инициализация очереди пакетов
void init_queue(PacketQueue *q) {
    q->capacity = 1024;  // начальный размер очереди
    q->items = (PacketQueueItem*)malloc(q->capacity * sizeof(PacketQueueItem));
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_nonempty, NULL);
    pthread_cond_init(&q->cond_nonfull, NULL);
}

// Уничтожение очереди пакетов (освобождение памяти и ресурсов синхронизации)
void destroy_queue(PacketQueue *q) {
    free(q->items);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_nonempty);
    pthread_cond_destroy(&q->cond_nonfull);
}

// Поместить пакет в очередь (с блокировкой, если очередь заполнена)
void enqueue_packet(PacketQueue *q, PacketQueueItem item) {
    pthread_mutex_lock(&q->mutex);
    // Если очередь полна, ждем освобождения места
    while(q->count == q->capacity) {
        pthread_cond_wait(&q->cond_nonfull, &q->mutex);
    }
    // Вставляем элемент в конец очереди
    q->items[q->rear] = item;
    q->rear = (q->rear + 1) % q->capacity;
    q->count++;
    // Сигнализируем, что очередь не пуста
    pthread_cond_signal(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
}

// Извлечь пакет из очереди (блокируется, если очередь пуста)
// Возвращает PacketQueueItem; если data == NULL, значит получен сигнал завершения
PacketQueueItem dequeue_packet(PacketQueue *q) {
    pthread_mutex_lock(&q->mutex);
    // Ждем, пока в очереди появится элемент
    while(q->count == 0) {
        pthread_cond_wait(&q->cond_nonempty, &q->mutex);
    }
    // Берем элемент из начала очереди
    PacketQueueItem item = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->count--;
    // Сигнализируем, что появилось свободное место
    pthread_cond_signal(&q->cond_nonfull);
    pthread_mutex_unlock(&q->mutex);
    return item;
}

// Добавить в очередь специальный "терминатор", сигнализирующий о завершении ввода
void enqueue_terminate(PacketQueue *q) {
    PacketQueueItem term;
    memset(&term, 0, sizeof(term));
    term.data = NULL; // null-указатель будет признаком окончания
    enqueue_packet(q, term);
}

void flush_queue_init(FlushQueue *fq) {
    fq->head = fq->tail = NULL;
    fq->terminate = 0;
    pthread_mutex_init(&fq->mutex, NULL);
    pthread_cond_init(&fq->cond_nonempty, NULL);
}

void flush_queue_push(FlushQueue *fq, FlushBuffer *buf) {
    buf->next = NULL;
    pthread_mutex_lock(&fq->mutex);
    if (fq->tail) fq->tail->next = buf;
    else fq->head = buf;
    fq->tail = buf;
    pthread_cond_signal(&fq->cond_nonempty);
    pthread_mutex_unlock(&fq->mutex);
}

FlushBuffer* flush_queue_pop(FlushQueue *fq) {
    pthread_mutex_lock(&fq->mutex);
    while (!fq->head && !fq->terminate)
        pthread_cond_wait(&fq->cond_nonempty, &fq->mutex);
    FlushBuffer *buf = fq->head;
    if (buf) {
        fq->head = buf->next;
        if (!fq->head) fq->tail = NULL;
    }
    pthread_mutex_unlock(&fq->mutex);
    return buf;
}

void flush_queue_terminate(FlushQueue *fq) {
    pthread_mutex_lock(&fq->mutex);
    fq->terminate = 1;
    pthread_cond_broadcast(&fq->cond_nonempty);
    pthread_mutex_unlock(&fq->mutex);
}

// Функция сравнения для сортировки записей по имени протокола (алфавитно)
int compare_by_protocol(const void *a, const void *b) {
    const PacketLogEntry *entryA = (const PacketLogEntry*)a;
    const PacketLogEntry *entryB = (const PacketLogEntry*)b;
    // Сравниваем строки с именами протоколов
    int cmp = strcmp(entryA->protocol_name, entryB->protocol_name);
    if(cmp != 0) {
        return cmp;
    }
    // Если протоколы одинаковые, для устойчивости сортировки можно сравнить IP или порты (не принципиально)
    if(entryA->ip_version != entryB->ip_version) {
        return entryA->ip_version - entryB->ip_version;
    }
    // Сравнение по исходному IP (для IPv4 и IPv6 отдельно)
    if(entryA->ip_version == 4) {
        if(entryA->ip_src.v4.s_addr != entryB->ip_src.v4.s_addr) {
            return (entryA->ip_src.v4.s_addr < entryB->ip_src.v4.s_addr) ? -1 : 1;
        }
        if(entryA->ip_dst.v4.s_addr != entryB->ip_dst.v4.s_addr) {
            return (entryA->ip_dst.v4.s_addr < entryB->ip_dst.v4.s_addr) ? -1 : 1;
        }
    } else if(entryA->ip_version == 6) {
        int cmp6 = memcmp(&entryA->ip_src.v6, &entryB->ip_src.v6, sizeof(struct in6_addr));
        if(cmp6 != 0) return cmp6;
        cmp6 = memcmp(&entryA->ip_dst.v6, &entryB->ip_dst.v6, sizeof(struct in6_addr));
        if(cmp6 != 0) return cmp6;
    }
    // Наконец сравним порты
    if(entryA->src_port != entryB->src_port) {
        return entryA->src_port - entryB->src_port;
    }
    if(entryA->dst_port != entryB->dst_port) {
        return entryA->dst_port - entryB->dst_port;
    }
    return 0;
}
