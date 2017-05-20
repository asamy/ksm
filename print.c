/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Windows only.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
*/
#if defined(ENABLE_DBGPRINT) || defined(ENABLE_FILEPRINT)

/*
 * A stupid kernel debug printing interface so that we don't hang
 * the kernel when we are inside VMX root.
 * 
 * Fileprint: workaround stupid error due to ntifs under MinGW-w64:
 *	ntifs.h: error flexible array in union
 *
 * As far as I know, the only fix would be editing the ntifs.h file
 * itself by and just replacing [] with [0] will fix it.
*/
#ifdef ENABLE_FILEPRINT
#include <ntifs.h>
#else
#include <ntddk.h>
#endif

#include <intrin.h>
#ifdef _MSC_VER
#include <ntstrsafe.h>
#endif

#include "ksm.h"

#define PRINT_FLUSH_DELAY	500
#define PRINT_BUF_ATONCE	512
#define PRINT_BUF_BUFFERS	2
#define PRINT_BUF_SHIFT		PAGE_SHIFT
#define PRINT_BUF_STRIDE	(1 << PRINT_BUF_SHIFT)
#define PRINT_BUF_SIZE		(PRINT_BUF_STRIDE * PRINT_BUF_BUFFERS)

#ifdef ENABLE_FILEPRINT
#define FILE_PATH		L"\\SystemRoot\\ksm.log"
#endif

/*
 * @head_use - points to the head of the buffer we should be buffering to
 * @next_use - points to next buffering location
 * @next - specifies next index of the buffer slice to use
 * @next_off - specifies next offset to print off the current buffer slice,
 *	       since DbgPrint() only allows up to 512 chars.
 *
 * head_use is switched between buf + 0 and buf + PRINT_BUF_STRIDE, to avoid
 * confusions and to make it better in terms of performance, between do_print()
 * and print_thread().
 *
 * The spin lock is used to synchronize updates to @head_use and @next_use.
 * For synchronization of writes, a barrier is used to make sure that print_thread()
 * will see the head being updated.
 */
static volatile bool do_exit = false;
static volatile bool exited = false;
static volatile bool work = false;
static char buf[PRINT_BUF_SIZE];
static char *head_use = buf;
static char *next_use = buf;
static size_t next = 0;
static size_t next_off = 0;
static KSPIN_LOCK lock;
#ifdef ENABLE_FILEPRINT
static ERESOURCE resource;
static HANDLE file;
#endif

#ifndef _MSC_VER
/*
 * Taken from:
 * 	https://searchcode.com/codesearch/view/20802857/
 *
 * public domain.
*/
typedef char *STRSAFE_LPSTR;
typedef const char *STRSAFE_LPCSTR;

#ifndef NTSTRSAFE_MAX_CCH
#define NTSTRSAFE_MAX_CCH 2147483647
#endif
#define NTSTRSAFEAPI	static __inline NTSTATUS NTAPI

/* Exported by ntoskrnl  */
extern int __cdecl _vsnprintf(char *, size_t, const char *, va_list);

NTSTRSAFEAPI RtlStringVPrintfWorkerA(STRSAFE_LPSTR pszDest, size_t cchDest, STRSAFE_LPCSTR pszFormat, va_list argList)
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (cchDest == 0)
		Status = STATUS_INVALID_PARAMETER;
	else {
		int iRet;
		size_t cchMax;
		cchMax = cchDest - 1;
		iRet = _vsnprintf(pszDest, cchMax, pszFormat, argList);
		if ((iRet < 0) || (((size_t)iRet) > cchMax)) {
			pszDest += cchMax;
			*pszDest = '\0';
			Status = STATUS_BUFFER_OVERFLOW;
		} else
			if (((size_t)iRet) == cchMax) {
				pszDest += cchMax;
				*pszDest = '\0';
			}
	}
	return Status;
}

NTSTRSAFEAPI RtlStringCchVPrintfA(STRSAFE_LPSTR pszDest, size_t cchDest, STRSAFE_LPCSTR pszFormat, va_list argList)
{
	if (cchDest > NTSTRSAFE_MAX_CCH)
		return STATUS_INVALID_PARAMETER;
	return RtlStringVPrintfWorkerA(pszDest, cchDest, pszFormat, argList);
}
#endif

static inline int sleep_ms(s32 ms)
{
	return KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER) {
		.QuadPart = -(10000 * ms)
	});
}

static inline char *stpcpy(char *dst, const char *src)
{
	const size_t len = strlen(src);
	return (char *)memcpy(dst, src, len + 1) + len;
}

static inline void print_flush(void)
{
	char on_stack[PRINT_BUF_ATONCE + 1];
	char *printbuf;
	size_t max;
	size_t rem;
	size_t len;
	KLOCK_QUEUE_HANDLE q;
#ifdef ENABLE_FILEPRINT
	IO_STATUS_BLOCK sblk;
#endif

	smp_rmb();
	KeAcquireInStackQueuedSpinLock(&lock, &q);
	printbuf = buf + next_off + ((next & (PRINT_BUF_BUFFERS - 1)) << PRINT_BUF_SHIFT);
	max = next_use - head_use;

	strncpy(on_stack, printbuf, PRINT_BUF_ATONCE);
	on_stack[PRINT_BUF_ATONCE] = '\0';
	len = strlen(on_stack);
	next_off += len;
	rem = max - next_off;

	if (rem == 0) {
		head_use = buf + ((++next & (PRINT_BUF_BUFFERS - 1)) << PRINT_BUF_SHIFT);
		next_use = head_use;
		next_off = 0;
		smp_wmb();
	}
	KeReleaseInStackQueuedSpinLock(&q);

#ifdef ENABLE_DBGPRINT
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", on_stack);
#endif
#ifdef ENABLE_FILEPRINT
	ExEnterCriticalRegionAndAcquireResourceExclusive(&resource);
	ZwWriteFile(file, NULL, NULL, NULL,
		    &sblk, on_stack, (u32)len,
		    NULL, NULL);
	ExReleaseResourceAndLeaveCriticalRegion(&resource);
#endif
}

static void print_thread(void)
{
	/*
	 * Note: This thread most of the time (if not all) will be running
	 * on a different processor other than the caller of do_print().
	 *
	 * We need this to sort of "queue" debug prints to avoid windbg
	 * hanging around because DbgPrintEx() needs to do IPI and stuff
	 * so it needs to be called with interrupts enabled, which in our
	 * case, they are mostly not especially inside VM exit.
	 */
	while (!do_exit) {
		while (next_use == head_use && !do_exit)
			sleep_ms(PRINT_FLUSH_DELAY);

		print_flush();
		cpu_relax();
	}

	if (next_use != head_use)
		print_flush();

#ifdef _MSC_VER
	InterlockedExchange8((char *)&exited, true);
#else
	__sync_bool_compare_and_swap(&exited, false, true);
#endif
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS print_init(void)
{
	HANDLE hThread;
	CLIENT_ID cid;
	NTSTATUS status;
#ifdef ENABLE_FILEPRINT
	IO_STATUS_BLOCK sblk;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING path;

	RtlInitUnicodeString(&path, FILE_PATH);
	InitializeObjectAttributes(&oa, &path,
				   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
				   NULL, NULL);
	status = ZwCreateFile(&file, FILE_APPEND_DATA | SYNCHRONIZE,
			      &oa, &sblk, NULL, FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ, FILE_OPEN_IF,
			      FILE_SYNCHRONOUS_IO_ALERT | FILE_NON_DIRECTORY_FILE,
			      NULL, 0);
	if (!NT_SUCCESS(status))
		return status;

	if (!NT_SUCCESS(status = ExInitializeResourceLite(&resource)))
		goto err_file;
#endif

	KeInitializeSpinLock(&lock);
	if (NT_SUCCESS(status = PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL,
						     NULL, NULL, &cid,
						     (PKSTART_ROUTINE)print_thread, NULL))) {
		ZwClose(hThread);
		return status;
	}

#ifdef ENABLE_FILEPRINT
	ExDeleteResourceLite(&resource);
err_file:
	ZwClose(file);
#endif
	return status;
}

void print_exit(void)
{
#ifdef _MSC_VER
	InterlockedExchange8((char *)&do_exit, true);
#else
	__sync_bool_compare_and_swap(&do_exit, false, true);
#endif
	while (!exited)
		cpu_relax();

#ifdef ENABLE_FILEPRINT
	ExDeleteResourceLite(&resource);
	ZwClose(file);
#endif
}

void do_print(const char *fmt, ...)
{
	char buffer[PRINT_BUF_ATONCE];
	va_list va;
	size_t len;
	size_t pos;
	NTSTATUS status;
	KLOCK_QUEUE_HANDLE q;

	va_start(va, fmt);
	status = RtlStringCchVPrintfA(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	if (NT_SUCCESS(status)) {
		if (__readeflags() & X86_EFLAGS_IF) {
			/*
			 * No need to queue, DbgPrint uses IPIs to do some stuff, we can
			 * use it safely here.
			 *
			 * This will not branch inside a VM-exit, simply because the IF flag
			 * is clear for obvious reasons.
			 */
#ifdef ENABLE_FILEPRINT
			IO_STATUS_BLOCK sblk;
			if (!KeAreAllApcsDisabled() && NT_SUCCESS(ZwWriteFile(file, NULL, NULL, NULL,
									      &sblk, buffer, (ULONG)strlen(buffer),
									      NULL, NULL)))
				ZwFlushBuffersFile(file, &sblk);
#endif
#ifdef ENABLE_DBGPRINT
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", buffer);
#endif
		} else {
			KeAcquireInStackQueuedSpinLock(&lock, &q);

			len = strlen(buffer);
			pos = next_use - head_use;
			if (pos + len < PRINT_BUF_STRIDE) {
				next_use = stpcpy(next_use, buffer);
				smp_wmb();
			}

			KeReleaseInStackQueuedSpinLock(&q);
		}
	}
}
#endif
