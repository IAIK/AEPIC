#include "enclave_t.h"
#include <sgx_trts.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define PALIGN __attribute__((aligned(4096)))

PALIGN unsigned char secret[0x1000];

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


void ecall_init(void) {
    printf("enclave init!\n");

    sgx_read_rand(secret, 0x1000);
}
