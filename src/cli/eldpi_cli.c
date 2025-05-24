#include "elbrus_dpi_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

static elbrus_dpi_handle_t *dpi_handle = NULL;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Использование: %s -f <pcap> | -i <iface> [-b 'bpf'] [-d 'database.file']\n",
            prog);
}

static void on_signal(int sig)
{
    (void)sig;
    if (dpi_handle)
        elbrus_dpi_stop(dpi_handle);
}

int main(int argc, char *argv[])
{
    const char *pcap_file = NULL;
    const char *iface = NULL;
    const char *bpf_filter = NULL;
    const char *db_path = "data/traffic.sqlite";

    int opt;
    while ((opt = getopt(argc, argv, "f:i:b:d:h")) != -1)
    {
        switch (opt)
        {
        case 'f':
            pcap_file = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'b':
            bpf_filter = optarg;
            break;
        case 'd':
            db_path = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Exactly one of -f or -i must be provided */
    if (!((pcap_file != NULL) ^ (iface != NULL)))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    elbrus_dpi_config_t cfg = {
        .mode = pcap_file ? ELBRUS_DPI_SRC_FILE : ELBRUS_DPI_SRC_IFACE,
        .source = pcap_file ? pcap_file : iface,
        .bpf_filter = bpf_filter,
        .db_path = db_path,
        .thread_count = 0};

    if (elbrus_dpi_init(&cfg, &dpi_handle) != 0)
    {
        fprintf(stderr, "elbrus_dpi_init() failed");
        return EXIT_FAILURE;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (elbrus_dpi_start(dpi_handle) != 0)
    {
        fprintf(stderr, "elbrus_dpi_start() failed");
        return EXIT_FAILURE;
    }

    elbrus_dpi_join(dpi_handle);
    elbrus_dpi_destroy(dpi_handle);
    return EXIT_SUCCESS;
}