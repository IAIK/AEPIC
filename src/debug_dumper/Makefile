SGX_SDK ?= /opt/intel/sgxsdk

all:
	@g++ -std=c++2a main.cpp ../common/aepic_leak.cpp ../enclaves/common/enclave_u.c -I../common -o debug_dumper -I$(SGX_SDK)/include -I../enclaves/common  -lsgx_urts -pthread

clean:
	@-rm debug_dumper