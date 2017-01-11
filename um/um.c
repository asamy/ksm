#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
typedef unsigned int u32;
#endif

#define UM
#include "um.h"
#include "../compiler.h"

#ifdef _WIN32
extern NTSTATUS NTAPI ZwDeviceIoControlFile(HANDLE h, HANDLE hEvent, PIO_APC_ROUTINE apc, void *apc_ctx,
					    PIO_STATUS_BLOCK status_block, u32 ctl_code,
					    void *input, u32 in_len, void *output, u32 out_len);
#pragma comment(lib, "ntdll.lib")
typedef HANDLE devfd_t;
typedef DWORD pidtype_t;
#else
typedef int devfd_t;
typedef unsigned long pidtype_t;
#endif

static inline devfd_t open_device(void)
{
#ifdef _WIN32
	return CreateFileW(UM_DEVICE_PATH,
			   GENERIC_READ | GENERIC_WRITE,
			   FILE_SHARE_READ | FILE_SHARE_WRITE,
			   NULL, OPEN_EXISTING, 0, NULL);
#else
	return open(UM_DEVICE_PATH, O_RDWR);
#endif
}

static inline void close_device(devfd_t device)
{
#ifdef _WIN32
	CloseHandle(device);
#else
	close(device);
#endif
}

static inline int do_ioctl(devfd_t device, unsigned int cmd, void *param, u32 len)
{
#ifdef _WIN32
	IO_STATUS_BLOCK blk;
	return ZwDeviceIoControlFile(device, NULL, NULL, NULL, &blk,
				     cmd, param, len,
				     0, 0);
#else
	return ioctl(device, cmd, param);
#endif
}

static inline pidtype_t __get_pid(void)
{
#ifdef _WIN32
	return (pidtype_t)GetCurrentProcessId();
#else
	return getpid();
#endif
}

static inline bool getchr(char *o)
{
	while (scanf("%c", o) == 1) {
		if (*o == '\n' || isspace(*o))
			continue;

		return true;
	}

	return false;
}

int main(int ac, char *av[])
{
	devfd_t dev;
	int ret;
	int pid;
	u32 cmd;
	char c;
	struct watch_ioctl w;

	dev = open_device();
	if (dev < 0) {
		perror("open device");
		goto err;
	}

	ret = do_ioctl(dev, KSM_IOCTL_SUBVERT, NULL, 0);
	if (ret < 0) {
		perror("subvert");
		goto out;
	}

	printf("Our pid: %d\n", __get_pid());
	printf("i = introspect, s = sandbox, q = quit\n");
	while (1) {
		printf("Say request> ");
		if (!getchr(&c))
			continue;

		switch (c) {
		case 'q':
			puts("Quit");
			goto unsub;
		case 'i':
			printf("s = start, d = stop, a = add, r = remove\n");
			printf("Introspect> ");
			if (!getchr(&c))
				goto unsub;

			switch (c) {
			case 's':
				ret = do_ioctl(dev, KSM_IOCTL_INTRO_START, NULL, 0);
				break;
			case 'd':
				ret = do_ioctl(dev, KSM_IOCTL_INTRO_STOP, NULL, 0);
				break;
			case 'a':
				printf("Type addr then access (i.e. 0x1000 0x2 to remove write-access): ");
				if (scanf("%I64X %X", &w.addr, &w.access) != 2)
					break;

				printf("Watching %I64X on %X access\n", w.addr, w.access);
				if (w.access & ~7) {
					printf("invalid access bits: %X\n", w.access);
					break;
				}

				ret = do_ioctl(dev, KSM_IOCTL_INTRO_WATCH, &w, sizeof(w));
				break;
			case 'r':
				printf("Address> ");
				if (!scanf("%I64X", &w.addr))
					break;

				printf("Unwatching %I64X\n", w.addr);
				ret = do_ioctl(dev, KSM_IOCTL_INTRO_UNWATCH, &w, sizeof(w));
				break;
			default:
				ret = -EINVAL;
				printf("unknown request: %c\n", c);
				break;
			}

			printf("ret: 0x%08X\n", ret);
			break;
		case 's':
			printf("Pid (Negative to unbox)> ");
			if (!scanf("%d", &pid))
				goto unsub;

			if (pid < 0) {
				pid = -pid;
				cmd = KSM_IOCTL_UNBOX;
				printf("Unsandboxing %d... ", pid);
			} else {
				cmd = KSM_IOCTL_SANDBOX;
				printf("Sandboxing %d... ", pid);
			}

			ret = do_ioctl(dev, cmd, &pid, sizeof(pid));
			printf("0x%08X (%s)\n", ret, ret == 0 ? "OK" : "FAILED");
			break;
		default:
			printf("unknown request: %c\n", c);
			break;
		}
	}

unsub:
	printf("unsubverting now\n");
	ret = do_ioctl(dev, KSM_IOCTL_UNSUBVERT, NULL, 0);
out:
	close_device(dev);
err:
	printf("ret: 0x%08X\n", ret);
	return ret;
}
