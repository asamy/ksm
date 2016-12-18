#
# ksm - a really simple and fast x64 hypervisor
# Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
#
# Makefile for the Linux kernel module only.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
obj-m += ksmlinux.o
ksmlinux-objs := exit.o htable.o ksm.o kprotect.o page.o vcpu.o main_linux.o x64.o
ccflags-y := -Wno-format -Wno-declaration-after-statement -Wno-unused-function -DDBG -DEPAGE_HOOK -std=gnu99
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

