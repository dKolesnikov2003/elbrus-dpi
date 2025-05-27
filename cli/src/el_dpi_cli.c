#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elbrus_dpi_api.h"

int parse_args(int argc, char **argv, CaptureOptions *opt) {
    memset(opt, 0, sizeof(*opt));
    opt->mode = -1;
    opt->db_name = get_default_db_path();

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

int main(int argc, char *argv[])
{
    CaptureOptions opts;
    if (parse_args(argc, argv, &opts) != 0)
    {
        fprintf(stderr, "Использование: %s -f <pcap> | -i <iface> [-b 'bpf'] [-d 'file.db']\n", argv[0]);
        return EXIT_FAILURE;
    }

    return start_analysis(&opts);
}
