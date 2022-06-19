SGX_SDK ?= /opt/intel/sgxsdk

all:
	@g++ -std=c++2a main.cpp ../common/aepic_leak.cpp -o dumper -I../common -I$(SGX_SDK)/include -lsgx_urts  -pthread

clean:
	@-rm dumper