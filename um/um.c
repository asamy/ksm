#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

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
typedef HANDLE pidtype_t;
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

static inline int do_ioctl(devfd_t device, unsigned int cmd, void *param)
{
#ifdef _WIN32
	IO_STATUS_BLOCK blk;
	return ZwDeviceIoControlFile(device, NULL, NULL, NULL, &blk,
				     cmd, param, sizeof(void *),
				     0, 0);
#else
	return ioctl(device, cmd, param);
#endif
}

static inline pidtype_t __get_pid(void)
{
#ifdef _WIN32
	return GetCurrentProcessId();
#else
	return getpid();
#endif
}

int main(int ac, char *av[])
{
	devfd_t dev;
	int ret;
	int pid;
	u32 cmd;
	char *prep = "";

	dev = open_device();
	if (dev < 0) {
		perror("open");
		return -1;
	}

	ret = do_ioctl(dev, KSM_IOCTL_SUBVERT, &dev);
	if (ret < 0)
		goto out;

	printf("(%d) Pid> ", __get_pid());
	while (scanf("%d", &pid) == 1) {
		printf("pid: %d\n", pid);
		if (pid == -1) {
			printf("invalid pid: %d\n", pid);
			break;
		}

		cmd = KSM_IOCTL_SANDBOX;
		prep = "";
		if (pid < 0) {
			pid = -pid;
			cmd = KSM_IOCTL_UNBOX;
			prep = "un";
		}

		ret = do_ioctl(dev, cmd, &pid);
		printf("%ssbox %d, ret: %d\n", prep, pid, ret);
		printf("Pid> ");
		fflush(stdout);
	}

	printf("unsubverting now\n");
	ret = do_ioctl(dev, KSM_IOCTL_UNSUBVERT, &dev);

out:
	close_device(dev);
	return ret;
}
