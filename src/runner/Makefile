SGX_SDK ?= /opt/intel/sgxsdk

all:
	@g++ -std=c++2a main.cpp ../enclaves/common/enclave_u.c -I../common -o runner -I$(SGX_SDK)/include -I../enclaves/common  -lsgx_urts

clean:
	@-rm runner