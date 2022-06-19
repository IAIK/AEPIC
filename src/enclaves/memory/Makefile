######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk

App_C_Flags := -fPIC -Wno-attributes -Ibuild -I$(SGX_SDK)/include -DDEBUG -UNDEBUG -UEDEBUG -g3 -D_GNU_SOURCE -pthread -Wno-pointer-arith -mavx2 -mavx512f -std=c++2a
App_Link_Flags := -pthread 

Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -Ibuild -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -g

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := -g -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=../common/enclave.lds

all: build enclave.signed.so

build:
	@-mkdir build

######## Trusted ########

build/enclave_t.c: ../common/enclave.edl
	@$(SGX_SDK)/bin/x64/sgx_edger8r --trusted ../common/enclave.edl --search-path . --search-path $(SGX_SDK)/include
	@mv enclave_t.c build/enclave_t.c
	@mv enclave_t.h build/enclave_t.h

build/enclave_t.o: build/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

build/enclave.o: enclave.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

build/enclave.so: build/enclave_t.o build/enclave.o
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)

enclave.signed.so: build/enclave.so
	@$(SGX_SDK)/bin/x64/sgx_sign sign -key ../common/key.pem -enclave $< -out $@ -config ../common/config.xml > /dev/null

.PHONY: clean

clean:
	@-rm -r build
	@rm -f enclave.so enclave.signed.so *.o *_t.c *_t.h *_u.c *_u.h
