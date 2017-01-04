#
# ksm - a really simple and fast x64 hypervisor
# Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
#
# Makefile for the Linux kernel module only.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; If not, see <http://www.gnu.org/licenses/>.
obj-m += ksmlinux.o
ksmlinux-objs := exit.o htable.o hotplug.o ksm.o page.o resubv.o vcpu.o mm.o main_linux.o vmx.o
ccflags-y := -Wno-format -Wno-declaration-after-statement -Wno-unused-function -DDBG -DENABLE_PRINT -std=gnu99

BIN := ksmlinux.ko
KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)
KBUILD := $(KDIR)/build
PWD := $(shell pwd)
MAKEFLAGS += --no-print-directory

all:
	@make -C $(KBUILD) M=$(PWD) modules

clean:
	@make -C $(KBUILD) M=$(PWD) clean

install: $(BIN)
	@cp $(BIN) $(KDIR)

load:
	@echo Loading $(BIN)
	@insmod $(BIN)

unload:
	@echo Unloading $(BIN)
	@rmmod $(BIN)

