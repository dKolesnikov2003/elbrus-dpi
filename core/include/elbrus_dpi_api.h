#ifndef ELBRUS_DPI_API_H
#define ELBRUS_DPI_API_H

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CaptureMode;

typedef struct {
    CaptureMode mode;       /* файл или интерфейс */
    const char *source;     /* имя pcap или интерфейса */
    const char *bpf;        /* -b фильтр (опц.) */
    const char *db_name;    /* имя файла БД внутри data/ */
} CaptureOptions;

int start_analysis(const CaptureOptions *opts);

const char *get_default_db_path(void);
const char *get_relative_db_path(void);

#endif // ELBRUS_DPI_API_H
