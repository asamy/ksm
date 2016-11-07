ifeq ("$(origin C)", "command line")
	CROSS_BUILD ?= x86_64-w64-mingw32-
	CROSS_INC ?= /usr/x86_64-w64-mingw32/include/ddk
	CROSS_LIB ?= /usr/x86_64-w64-mingw32/lib
else
	CROSS_BUILD ?=
	CROSS_INC ?=
	CROSS_LIB ?=
endif

TARGET = ksm.sys
CC = $(CROSS_BUILD)gcc
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$*.d
CFLAGS = -I$(CROSS_INC) -DMINGW -DDBG -D_WIN32_WINNT=0x0601 -std=c99 \
	 -Wno-multichar -fno-stack-protector -fms-extensions $(DEPFLAGS)
LDFLAGS = -m64 -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 \
	  -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	  -Wl,--entry,DriverEntry@8 -Wl,--stack,0x6000 -Wl,--dynamicbase -Wl,--nxcompat \
	  -Wl,--enable-stdcall-fixup -nostartfiles -nostdlib
LIBS = -L$(CROSS_LIB) -lntoskrnl -lhal -lmingwex

SRC = acpi.c ept.c exit.c htable.c ksm.c main.c page.c vcpu.c
ASM = x64.S

OBJ_DIR = obj
DEP_DIR = dep
DEP  = $(SRC:%.c=$(DEP_DIR)/%.d)
OBJ  = $(SRC:%.c=$(OBJ_DIR)/%.o)
OBJ += $(ASM:%.S=$(OBJ_DIR)/%.o)

.PHONY: all clean
.PRECIOUS: $(DEP_DIR)/%.d

all: $(TARGET)
clean:
	$(RM) $(TARGET) $(OBJ) $(DEP)

$(TARGET): $(DEP_DIR) $(OBJ_DIR) $(OBJ) $(DEP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

$(OBJ_DIR)/%.o: %.c $(DEP_DIR)/%.d
	$(CC) -c $(CFLAGS) -o $@ $<

-include $(DEP)
$(DEP_DIR)/%.d: ;

$(DEP_DIR):
	@mkdir -p $(DEP_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

