#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>

typedef unsigned char u8;
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
typedef int pidtype_t;
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
				     param, len);
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

static void print_hex_ascii_line(const u8 *payload, size_t len, size_t offset)
{
	size_t i, gap;
	u8 ch;

	printf("%05zd   ", offset);
	/* hex  */
	for (ch = *payload, i = 0; i < len; ch = payload[++i]) {
		printf("%02X ", ch);
		if (i == 7)
			putchar(' ');
	}
	if (len < 8)
		putchar(' ');

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; ++i)
			printf("   ");
	}
	printf("   ");

	/* ascii (if printable)  */
	for (ch = *payload, i = 0; i < len; ch = payload[++i]) {
		if (isprint(ch))
			putchar(ch);
		else
			putchar('.');
	}

	putchar('\n');
}

static void print_payload(const u8 *payload, size_t len)
{
	size_t len_rem = len;
	size_t line_width = 16;
	size_t line_len;
	size_t offset = 0;
	const u8 *ch = payload;

	if (len <= 0)
		return;

	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for (;;) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}

int main(int ac, char *av[])
{
	devfd_t dev;
	int ret;
	int pid;
	u32 cmd;
	char c;
	struct watch_ioctl *w = malloc(sizeof(*w));

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
			printf("s = start, d = stop, a = add, r = remove, e = stats\n");
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
				if (scanf("%llX %hX", &w->addr, &w->access) != 2)
					break;

				printf("Watching 0x%016llX on %hX access\n", w->addr, w->access);
				if (w->access & ~7) {
					printf("invalid access bits: 0x%02hX\n", w->access);
					break;
				}

				ret = do_ioctl(dev, KSM_IOCTL_INTRO_WATCH, w, sizeof(*w));
				break;
			case 'r':
				printf("Address> ");
				if (!scanf("%llX", &w->addr))
					break;

				printf("Unwatching 0x%016llX\n", w->addr);
				ret = do_ioctl(dev, KSM_IOCTL_INTRO_UNWATCH, w, sizeof(*w));
				break;
			case 'e':
				printf("Address> ");
				if (!scanf("%llX", &w->addr))
					break;

				ret = do_ioctl(dev, KSM_IOCTL_INTRO_STATS, w, sizeof(*w));
				if (ret == 0) {
					printf("Stats for 0x%016llX\n", w->addr);
					printf("\tHits: %d\n", w->hits);
					printf("\tMisses: %d\n", w->miss);
					printf("Buffer:\n");
					print_payload((const u8 *)w->buf, 0x1000);
				}
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
	free(w);
	printf("ret: 0x%08X\n", ret);
	return ret;
}
