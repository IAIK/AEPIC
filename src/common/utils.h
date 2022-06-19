#pragma once

// no time to filter
#include <condition_variable>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

inline void set_cpu_mask(int mask) {
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    int j = 0;
    while ( mask ) {
        if ( mask & 0x1 ) {
            CPU_SET(j, &cpuset);
        }
        mask >>= 1;
        j++;
    }

    int status = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
    if ( status != 0 ) {
        printf("error while setting cpu mask!\n");
    }
}

#define COLOR_BLACK   "\x1b[31m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"

#define COLOR_BG_BLACK   "\x1b[41m"
#define COLOR_BG_RED     "\x1b[41m"
#define COLOR_BG_GREEN   "\x1b[42m"
#define COLOR_BG_YELLOW  "\x1b[43m"
#define COLOR_BG_BLUE    "\x1b[44m"
#define COLOR_BG_MAGENTA "\x1b[45m"
#define COLOR_BG_CYAN    "\x1b[46m"
#define COLOR_BG_WHITE   "\x1b[47m"

#define COLOR_RESET "\x1b[0m"

#define SAVE_COURSOR() printf("\x1b[s");
#define LOAD_COURSOR() printf("\x1b[u");
#define CLEAR_LINE()   printf("\x1b[K");

class signal_t {
    std::mutex              mtx;
    std::condition_variable cv;
    bool                    flag   = false;
    bool                    killed = false;

  public:
    void signal() {
        std::lock_guard lock { mtx };
        flag = true;
        cv.notify_one();
    }

    void wait() {
        std::unique_lock lock { mtx };
        cv.wait(lock, [&] {
            return flag || killed;
        });
        flag = false;
    }

    void kill() {
        {
            std::lock_guard lock { mtx };
            killed = true;
        }
        cv.notify_all();
    }
};