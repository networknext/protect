
obj-m += next_module.o

module: next_module.c hydrogen.c hydrogen.h
	@echo building network next kernel module
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
	rm -f *.o
	rm -f *.ko
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	sudo rmmod -f next_module >/dev/null 2>&1; echo
	sudo insmod next_module.ko; echo
