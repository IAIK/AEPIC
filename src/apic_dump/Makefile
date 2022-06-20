
obj-m += apic_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

load: all
	sudo rmmod apic_module || true
	sudo insmod apic_module.ko

run: load
	taskset -c 0 sudo cat /dev/apic_device | xxd

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean