ifneq ($(KERNELRELEASE),)
	isgx-y := \
		sgx_main.o \
		sgx_page_cache.o \
		sgx_ioctl.o \
		sgx_vma.o \
		sgx_util.o\
		sgx_encl.o \
		sgx_encl2.o
	obj-m += isgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	depmod -A
	sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"

load: default
	-sudo /opt/intel/sgx-aesm-service/cleanup.sh     
	-sudo /opt/intel/sgxpsw/cleanup.sh     
	-sudo rmmod isgx
	sudo insmod isgx.ko
	-sudo /opt/intel/sgx-aesm-service/startup.sh     
	-sudo /opt/intel/sgxpsw/startup.sh     

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd *.mod
