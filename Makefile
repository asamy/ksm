obj-m += ksmlinux.o
ksmlinux-objs := exit.o htable.o ksm.o kprotect.o page.o vcpu.o main_linux.o x64.o
ccflags-y := -Wno-format -Wno-declaration-after-statement -Wno-unused-function -DDBG -std=gnu99
KVERSION := $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

load:
	insmod ksm.ko

unload:
	rmmod ksm.ko

install:
	make modules_install ksm.ko

