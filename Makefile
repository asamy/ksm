obj-m += ksmlinux.o
ksmlinux-objs := exit.o htable.o ksm.o kprotect.o page.o vcpu.o main_linux.o x64.o
ccflags-y := -Wno-format -Wno-declaration-after-statement -Wno-unused-function -DDBG -std=gnu99

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build
PWD := $(shell pwd)
MAKEFLAGS += --no-print-directory

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

load:
	insmod ksmlinux.ko

unload:
	rmmod ksmlinux.ko

