
#include "aepic_interface.h"
#include "enclave_u.h"
#include "sgx_urts.h"

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    sgx_launch_token_t token   = { 0 };
    sgx_status_t       ret     = SGX_ERROR_UNEXPECTED;
    int                updated = 0;

    if ( argc != 2 && argc != 3 ) {
        printf("[runner ] usage %s enclave_path [dump_file]\n", argv[0]);
        return -1;
    }

    // Create enclave
    if ( sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) != SGX_SUCCESS ) {
        printf("[runner ] Failed to start enclave! sudo /opt/intel/sgx-aesm-service/startup.sh ?\n");
        return -1;
    }

    ecall_init(global_eid);

    printf("[runner ] waiting for user input ot termiante!\n");
    getc(stdin);

    if ( argc == 3 ) {
        printf("[runner ] dumping enclave\n");

        isgx = open("/dev/isgx", O_RDWR);
        if ( isgx < 0 ) {
            printf("[runner ] could not open isgx driver: sudo?\n");
            exit(-1);
        }

        auto data = aepic_get_data_pid(getpid());

        printf("[runner ] found %llu enclaves\n", data.enclaves);

        char * encl_base = (char *)data.enclave_ids[0];
        size_t encl_size = data.enclave_sizes[0];

        FILE *f = fopen(argv[2], "wb");

        for ( size_t o = 0; o < encl_size; o += 0x1000 ) {
            char target[4096];
            memset(target, -1, 0x1000);
            aepic_edbgrd(encl_base + o, target, 4096);
            fwrite(target, 0x1000, 1, f);
        }
        fclose(f);
    }

    // Destroy enclave
    sgx_destroy_enclave(global_eid);

    return 0;
}
