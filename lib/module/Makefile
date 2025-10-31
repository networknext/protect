
KERNEL = $(shell uname -r)

obj-m += next_module.o

module: next_module.c
	@echo building network next kernel module
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
	rm -f *.o
	rm -f *.ko
	make -C /lib/modules/$(KERNEL)/build M=$(shell pwd) modules
#	sudo modprobe chacha20
#	sudo modprobe poly1305
	sudo rmmod -f next_module >/dev/null 2>&1; echo
	sudo insmod next_module.ko; echo
