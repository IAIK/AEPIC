#include "enclave_t.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define PALIGN __attribute__((aligned(4096)))

int printf(const char *fmt, ...) {
    char    buf[5000] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

int puts(const char *buf) {
    char buffer[1000];
    snprintf(buffer, sizeof(buffer), "%s\n", buf);
    ocall_print_string(buffer);
    return 0;
}

#define LOAD_XMM(_xmm, _data)      \
    "mov     $" #_data ", %%edi\n" \
    "movd    %%edi, %%" #_xmm "\n" \
    "pshufd  $0, %%" #_xmm ", %%" #_xmm "\n"

static void __attribute__((aligned(4096), naked)) victim_function() {

    asm volatile(LOAD_XMM(xmm8, 0x386D6D78) //
                 R"(
        pxor  %%xmm0, %%xmm1
        pxor  %%xmm1, %%xmm0
        pxor  %%xmm0, %%xmm1
        ret
    .align 4096
        nop
    )" ::);
}

void ecall_init(void) {
    printf("enclave init!\n");

    asm volatile(LOAD_XMM(xmm0, 0)           //
                 LOAD_XMM(xmm1, 0x316D6D78)  //
                 LOAD_XMM(xmm2, 0x326D6D78)  //
                 LOAD_XMM(xmm3, 0x336D6D78)  //
                 LOAD_XMM(xmm4, 0x346D6D78)  //
                 LOAD_XMM(xmm5, 0x356D6D78)  //
                 LOAD_XMM(xmm6, 0x366D6D78)  //
                 LOAD_XMM(xmm7, 0x376D6D78)  //
                 LOAD_XMM(xmm8, 0x386D6D78)  //
                 LOAD_XMM(xmm9, 0x396D6D78)  //
                 LOAD_XMM(xmm10, 0x416D6D78) //
                 LOAD_XMM(xmm11, 0x426D6D78) //
                 LOAD_XMM(xmm12, 0x436D6D78) //
                 LOAD_XMM(xmm13, 0x446D6D78) //
                 LOAD_XMM(xmm14, 0x456D6D78) //
                 LOAD_XMM(xmm15, 0x466D6D78) //
                 "mov $0x786172, %%rax\n"
                 "mov $0x786272, %%rbx\n"
                 "mov $0x786372, %%rcx\n"
                 "mov $0x786472, %%rdx\n"
                 "mov $0x787372, %%rsi\n"
                 "call victim_function\n"

                 :
                 :
                 : "rax", "rbx", "rdx", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9",
                   "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15");
}
