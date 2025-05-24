#ifndef ELBRUS_DPI_H
#define ELBRUS_DPI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>

/* Источник трафика */
typedef enum {
    ELBRUS_DPI_SRC_FILE,   /* путь к pcap‑файлу */
    ELBRUS_DPI_SRC_IFACE   /* название сетевого интерфейса */
} elbrus_dpi_source_mode_t;

/* Параметры запуска */
typedef struct {
    elbrus_dpi_source_mode_t mode;          /* способ захвата */
    const char             *source;        /* pcap или iface */
    const char             *bpf_filter;    /* фильтр BPF      */
    const char             *db_path;       /* файл SQLite     */
    unsigned                thread_count;  /* 0 => значение по умолчанию */
} elbrus_dpi_config_t;

/* Opaque handle */
typedef struct elbrus_dpi_handle elbrus_dpi_handle_t;

/* API */
int  elbrus_dpi_init (const elbrus_dpi_config_t *cfg,
                      elbrus_dpi_handle_t      **out_handle);
int  elbrus_dpi_start(elbrus_dpi_handle_t *handle);
void elbrus_dpi_stop (elbrus_dpi_handle_t *handle);
void elbrus_dpi_join (elbrus_dpi_handle_t *handle);
void elbrus_dpi_destroy(elbrus_dpi_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* ELBRUS_DPI_H */
