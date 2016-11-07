CROSS_BUILD = x86_64-w64-mingw32-
CROSS_INC = /usr/x86_64-w64-mingw32/include/ddk

TARGET = ksm.sys
CC = $(CROSS_BUILD)gcc
CFLAGS = -I$(CROSS_INC) -DMINGW -DDBG -D_WIN32_WINNT=0x0601 -std=c99 \
	 -Wno-multichar -fno-stack-protector
LDFLAGS = -m64 -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 \
	  -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	  -Wl,--entry,DriverEntry@8 -Wl,--stack,0x6000 -Wl,--dynamicbase -Wl,--nxcompat \
	  -Wl,--enable-stdcall-fixup -nostartfiles -nostdlib
LIBS = -lntoskrnl -lhal

SRC = acpi.c ept.c exit.c htable.c ksm.c main.c page.c vcpu.c
OBJ = $(SRC:%.c=%.o)

ASM = x64.S
OBJ += $(ASM:%.S=%.o)

all: $(TARGET)
clean:
	$(RM) $(TARGET) $(OBJ)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

