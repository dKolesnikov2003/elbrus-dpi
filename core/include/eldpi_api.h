#ifndef ELBRUS_DPI_API_H
#define ELBRUS_DPI_API_H

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CaptureMode;

typedef struct {
    CaptureMode mode;       /* файл или интерфейс */
    const char *source;     /* имя pcap или интерфейса */
    const char *bpf;        /* -b фильтр (опц.) */
} CaptureOptions;

int start_analysis(const CaptureOptions *opts);
void stop_analysis(void);

const char *get_DB_file_name(void);
const char *get_DB_folder(void);
const char *get_DB_path(void);

#endif // ELBRUS_DPI_API_H