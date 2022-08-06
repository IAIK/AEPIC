SGX_SDK ?= /opt/intel/sgxsdk
SGX_STEP ?= ../../sgx-step

INCLUDES=-I../enclaves/common -I../common -I$(SGX_SDK)/include -I$(SGX_STEP)


all:
	@g++ -Wno-pointer-arith -std=c++2a main.cpp ../enclaves/common/enclave_u.c ../common/aepic_leak.cpp -o stepper -I../enclaves/common -I../common -I$(SGX_SDK)/include -I$(SGX_STEP) -L$(SGX_SDK)/lib64 -lsgx_urts -L$(SGX_STEP)/libsgxstep -lsgx-step -pthread -ldl



library:
	@g++-10 $(INCLUDES) -Wno-pointer-arith -std=c++20 -fPIE -fPIC -c main.cpp -o build/main.o
	@g++-10 $(INCLUDES) -Wno-pointer-arith -std=c++20 -fPIE -fPIC -c ../common/aepic_leak.cpp -o build/aepic_leak.o
	@g++-10 $(INCLUDES) -Wno-pointer-arith -std=c++20 -fPIE -fPIC -c ../enclaves/common/enclave_u.c -o build/enclave_u.o
	@g++-10 -fvisibility=hidden  -shared build/main.o build/aepic_leak.o build/enclave_u.o -lsgx_urts -L$(SGX_STEP)/libsgxstep -lsgx-step -pthread -o libstepper.so
	


	#@g++-10   -fvisibility=hidden  -shared -Wno-pointer-arith -std=c++20 main.cpp ../enclaves/common/enclave_u.c ../common/aepic_leak.cpp   -o libstepper.so -I../enclaves/common -I../common -I$(SGX_SDK)/include -I$(SGX_STEP) -lsgx_urts -L$(SGX_STEP)/libsgxstep -lsgx-step -pthread 


clean:
	@-rm stepper libstepper.so