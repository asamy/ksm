#
# ksm - a really simple and fast x64 hypervisor
# Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
#
# Makefile for MinGW and others.
# 	To cross-compile, pass C=1:
# 		make C=1
# 	to compile under native MinGW:
# 		mingw32-make
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

# See if we are cross compiling.
ifeq ("$(origin C)", "command line")
	CROSS_BUILD ?= x86_64-w64-mingw32-
	CROSS_INC ?= /usr/x86_64-w64-mingw32/include/ddk
	CROSS_LIB ?= /usr/x86_64-w64-mingw32/lib
else
	CROSS_BUILD ?=
	CROSS_INC ?=
	CROSS_LIB ?=
endif

ifeq ("$(origin V)", "command line")
	VERBOSE=$(V)
else
	VERBOSE=1
endif

CC = $(CROSS_BUILD)gcc
STRIP = $(CROSS_BUILD)strip
OBJCOPY = $(CROSS_BUILD)objcopy --only-keep-debug

# Windows versions:
# 	0x0601 = Windows 7
# 	0x0602 = Windows 8
# 	0x0603 = Windows 8.1
# 	0x0A00 = Windows 10
WINVER=0x0601

DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$*.d
DBGFLAGS = -DDBG -O0 -ggdb
CFLAGS = -I$(CROSS_INC) $(DBGFLAGS) -D_WIN32_WINNT=$(WINVER) -DENABLE_DBGPRINT \
	 -std=c99 -Wno-multichar -municode -fno-stack-protector -fms-extensions -fno-stack-check \
	 -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-pic
LDFLAGS = -shared -Wl,--subsystem,native -Wl,--dynamicbase -Wl,--stack=0x6000 \
	  -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	  -Wl,--entry,DriverEntry -Wl,--nxcompat -Wl,--exclude-all-symbols \
	  -Wl,--enable-stdcall-fixup -nostartfiles -nostdlib
LIBS = -L$(CROSS_LIB) -lntoskrnl -lhal -lmingwex

SRC = acpi.c exit.c htable.c ksm.c kprotect.c main.c page.c print.c vcpu.c
ASM = x64.S

BIN_DIR = bin
OBJ_DIR = obj
DEP_DIR = dep
DEP  = $(SRC:%.c=$(DEP_DIR)/%.d)
OBJ  = $(SRC:%.c=$(OBJ_DIR)/%.o)
OBJ += $(ASM:%.S=$(OBJ_DIR)/%.o)

TARGET = $(BIN_DIR)/ksm.sys
SYMBOL = $(BIN_DIR)/ksm.dbg

ifeq ($(VERBOSE), 1)
	PREPEND ?=
	CEXTRA ?=
	AEXTRA ?=
	LEXTRA ?=
else
	PREPEND ?= @
	CEXTRA ?= @echo "  CC $@"
	AEXTRA ?= @echo "  AS $@"
	LEXTRA ?= @echo "  LD $@"
endif

.PHONY: all clean
.PRECIOUS: $(DEP_DIR)/%.d

all: $(TARGET)
clean:
	$(RM) $(TARGET) $(SYMBOL) $(OBJ) $(DEP)

$(TARGET): $(BIN_DIR) $(DEP_DIR) $(OBJ_DIR) $(OBJ) $(DEP)
	$(PREPEND)$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)
	$(PREPEND)$(OBJCOPY) $@ $(SYMBOL)
	$(PREPEND)$(STRIP) $@
	$(LEXTRA)

$(OBJ_DIR)/%.o: %.c $(DEP_DIR)/%.d
	$(PREPEND)$(CC) -c $(CFLAGS) $(DEPFLAGS) -o $@ $<
	$(CEXTRA)

$(OBJ_DIR)/%.o: %.S
	$(PREPEND)$(CC) -c $(CFLAGS) -o $@ $<
	$(AEXTRA)

-include $(DEP)
$(DEP_DIR)/%.d: ;

$(DEP_DIR):
	@mkdir -p $(DEP_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

