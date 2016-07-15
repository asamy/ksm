CROSS_BUILD = x86_64-w64-mingw32-
CROSS_INC = /usr/x86_64-w64-mingw32/include/ddk

TARGET = ksm.sys
CC = $(CROSS_BUILD)gcc
CFLAGS = -I$(CROSS_INC) -DMINGW -D_WIN32_WINNT=0x0601 -std=c99
LDFLAGS = -m64 -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 \
	  -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	  -Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
	  -nostartfiles -nostdlib
LIBS = -lntoskrnl -lhal

SRC = ept.c exit.c ksm.c ldasm.c main.c page.c power.c vcpu.c
OBJ = $(SRC:%.c=%.o)

all: $(TARGET)
clean:
	$(RM) $(TARGET) $(OBJ)

$(TARGET): $(OBJ) $(OBA)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

