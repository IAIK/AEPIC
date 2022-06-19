#include "../common/gdb_markers.h"
#include "enclave_t.h"
#include "ippcp.h"


#include <sgx_trts.h>

#include <stdarg.h>
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

#define PRINT_EXAMPLE_STATUS(function_name, description, success_condition)       \
    printf("+--------------------------------------------------------------|\n"); \
    printf(" Function: %s\n", function_name);                                     \
    printf(" Description: %s\n", description);                                    \
    if ( success_condition ) {                                                    \
        printf(" Status: PASSED!\n");                                             \
    }                                                                             \
    else {                                                                        \
        printf(" Status: FAILED!\n");                                             \
    }                                                                             \
    printf("+--------------------------------------------------------------|\n");

static int checkStatus(const char *funcName, IppStatus expectedStatus, IppStatus status) {
    if ( expectedStatus != status ) {
        printf("%s: unexpected return status\n", funcName);
        printf("Expected: %s\n", ippcpGetStatusString(expectedStatus));
        printf("Received: %s\n", ippcpGetStatusString(status));
        return 0;
    }
    return 1;
}

/*! AES block size in bytes */
static const int AES_BLOCK_SIZE = 16;

/*! Key size in bytes */
static const int KEY_SIZE = 16;

/*! Message size in bytes */
static const int SRC_LEN = 16;

/*! Plain text */
static Ipp8u plainText[SRC_LEN] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

/*! Cipher text */
static Ipp8u cipherText[SRC_LEN] = { 0x61, 0x3c, 0x72, 0xaa, 0xfb, 0x93, 0x97, 0xbd,
                                     0x3f, 0x7d, 0xd8, 0x4e, 0x37, 0x57, 0x0c, 0x19 };

/*! 256-bit secret key */
static Ipp8u key256[KEY_SIZE] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                                  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81 };

/*! Initial counter for CTR mode.
 *  Size of counter for AES-CTR shall be equal to the size of AES block (16 bytes).
 */
static Ipp8u initialCounter[AES_BLOCK_SIZE] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

void ecall_init() {
    mark_begin();

    sgx_read_rand(key256,KEY_SIZE);
     
    char buffer[1000];
    int byte_idx = 0;
    snprintf(buffer,5,"key:");
    int i = 4;
    while(byte_idx != KEY_SIZE)
    {	
      snprintf(buffer+i,3, "%02X",key256[byte_idx]);
      i += 2;
      byte_idx++;
    }
    buffer[i] = '\n';
    buffer[i+1] = '\x00';
    ocall_print_string(buffer);
    printf("enclave init!\n");
     
    /* Length of changeable bits in a counter (can be value starting from 1 till block size 128) */
    const Ipp32u counterLen = 128;

    /* Size of AES context structure. It will be set up in ippsAESGetSize(). */
    int ctxSize = 0;

    Ipp8u pOut[SRC_LEN]            = {};
    Ipp8u pCounter[AES_BLOCK_SIZE] = {};

    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Pointer to AES context structure */
    IppsAESSpec *pAES = 0;

    do {
        /* 1. Get size needed for AES context structure */
        status = ippsAESGetSize(&ctxSize);
        if ( !checkStatus("ippsAESGetSize", ippStsNoErr, status) ) {
            printf("ERROR: checkStatus\n");
            return;
        }

        /* 2. Allocate memory for AES context structure */
        pAES = (IppsAESSpec *)(new Ipp8u[ctxSize]);
        if ( NULL == pAES ) {
            printf("ERROR: Cannot allocate memory (%d bytes) for AES context\n", ctxSize);
            return;
        }

        /* 3. Initialize AES context */
        status = ippsAESInit(key256, KEY_SIZE, pAES, ctxSize);
        if ( !checkStatus("ippsAESInit", ippStsNoErr, status) )
            break;

        /* Initialize counter before decryption.
         * An updated counter value will be stored here after ippsAESDecryptCTR finishes.
         */
        memcpy(pCounter, initialCounter, sizeof(initialCounter));

        /* 4. Decryption */
        status = ippsAESDecryptCTR(cipherText, pOut, sizeof(cipherText), pAES, pCounter, counterLen);
        if ( !checkStatus("ippsAESDecryptCTR", ippStsNoErr, status) )
            break;

        /* Compare decrypted message and original text */
        if ( 0 != memcmp(pOut, plainText, sizeof(plainText)) ) {
            printf("ERROR: Decrypted and plain text messages do not match\n");
            break;
        }
    } while ( 0 );

    /* 5. Remove secret and release resources */
    ippsAESInit(0, KEY_SIZE, pAES, ctxSize);
    if ( pAES )
        delete[](Ipp8u *) pAES;

    PRINT_EXAMPLE_STATUS("ippsAESDecryptCTR", "AES-CTR 256 Decryption", !status);

    mark_end();
}
