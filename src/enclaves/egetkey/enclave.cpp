#include "../common/gdb_markers.h"
#include "enclave_t.h"
#include "ippcp.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PALIGN __attribute__((aligned(4096)))

int printf(const char *fmt, ...) {
    return 0;
    char    buf[5000] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

int puts(const char *buf) {
    return 0;
    char buffer[1000];
    snprintf(buffer, sizeof(buffer), "%s\n", buf);
    ocall_print_string(buffer);
    return 0;
}

char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "aad mac text";

// intel example
sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t data_size) {
    uint32_t sealed_data_size =
        sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
    if ( sealed_data_size == UINT32_MAX )
        return SGX_ERROR_UNEXPECTED;
    if ( sealed_data_size > data_size )
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if ( temp_sealed_buf == NULL )
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err =
        sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, (uint32_t)strlen(encrypt_data),
                      (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if ( err == SGX_SUCCESS ) {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size) {
    uint32_t mac_text_len     = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if ( mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX )
        return SGX_ERROR_UNEXPECTED;
    if ( mac_text_len > data_size || decrypt_data_len > data_size )
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text = (uint8_t *)malloc(mac_text_len);
    if ( de_mac_text == NULL )
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if ( decrypt_data == NULL ) {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, decrypt_data,
                                       &decrypt_data_len);
    if ( ret != SGX_SUCCESS ) {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    if ( memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text)) ||
         memcmp(decrypt_data, encrypt_data, strlen(encrypt_data)) )
    {
        ret = SGX_ERROR_UNEXPECTED;
    }

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

void ecall_init() {
    mark_begin();
    printf("enclave init!\n");

    unsigned char buffer[1000] = "Test";

    if ( seal_data(buffer, sizeof(buffer)) == SGX_SUCCESS ) {
        printf("successfully sealed data!\n");
    }
    

    if ( unseal_data(buffer, sizeof(buffer)) == SGX_SUCCESS ) {
        printf("successfully sealed data!\n");
    }

    mark_end();
}
