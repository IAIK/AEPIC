#include "enclave_u.h"

#include <errno.h>
#include <stdio.h>

// sgx id

sgx_enclave_id_t __attribute__((visibility("hidden"))) global_eid = 0;

typedef struct ms_ocall_print_string_t {
    const char *ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void *pms) {
    ms_ocall_print_string_t *ms = SGX_CAST(ms_ocall_print_string_t *, pms);
    ocall_print_string(ms->ms_str);

    return SGX_SUCCESS;
}

static const struct {
    size_t nr_ocall;
    void * table[1];
} ocall_table_enclave = { 1,
                          {
                              (void *)enclave_ocall_print_string,
                          } };
sgx_status_t ecall_init(sgx_enclave_id_t eid) {
    sgx_status_t status;
    status = sgx_ecall(eid, 0, &ocall_table_enclave, NULL);
    return status;
}

void ocall_print_string(const char *str) {
    printf("[enclave] %s", str);
}
