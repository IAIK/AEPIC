#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> /* for size_t */
#include <string.h>
#include <wchar.h>

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char *str));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

void ocall_print_string(const char *str);

extern sgx_enclave_id_t global_eid;

#endif
