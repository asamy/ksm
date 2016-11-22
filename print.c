/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifdef DBG

/*
 * A stupid kernel debug printing interface so that we don't hang
 * the kernel when we are inside VMX root.
*/
#include "ksm.h"

#ifdef _MSC_VER
#include <ntstrsafe.h>
#endif
#include <intrin.h>

#define PRINT_BUF_STRIDE	PAGE_SIZE
#define PRINT_BUF_SIZE		(PRINT_BUF_STRIDE << 1)

static volatile bool do_exit = false;
static volatile bool exited = false;
static volatile bool work = false;
static char buf[PRINT_BUF_SIZE];
static char *head_use = buf;
static char *next_use = buf;
static size_t next = 0;
static KSPIN_LOCK lock;

#ifndef _MSC_VER
/*
 * Taken from:
 * 	https://searchcode.com/codesearch/view/20802857/
*/
typedef char *STRSAFE_LPSTR;
typedef const char *STRSAFE_LPCSTR;

#ifndef NTSTRSAFE_MAX_CCH
#define NTSTRSAFE_MAX_CCH 2147483647
#endif
#define NTSTRSAFEAPI	static __inline NTSTATUS NTAPI

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

static inline char *stpcpy(char *dst, const char *src)
{
	const size_t len = strlen(src);
	return (char *)memcpy(dst, src, len + 1) + len;
}

static inline void print_flush(void)
{
	KLOCK_QUEUE_HANDLE q;
	KeAcquireInStackQueuedSpinLock(&lock, &q);

	char *printbuf = buf + ((next & 1) << PAGE_SHIFT);
	head_use = buf + ((++next & 1) << PAGE_SHIFT);
	next_use = head_use;
	barrier();

	KeReleaseInStackQueuedSpinLock(&q);
	if (KeGetCurrentIrql() < CLOCK_LEVEL)
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", printbuf);
}

static void print_thread(void)
{
	while (!do_exit) {
		while (next_use == head_use && !do_exit)
			sleep_ms(50);

		print_flush();
	}

	if (next_use != head_use)
		print_flush();

#ifdef _MSC_VER
	InterlockedExchange8(&exited, true);
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

	KeInitializeSpinLock(&lock);
	if (!NT_SUCCESS(status = PsCreateSystemThread(&hThread,
						      STANDARD_RIGHTS_ALL,
						      NULL,
						      NULL,
						      &cid,
						      (PKSTART_ROUTINE)print_thread,
						      NULL)))
		return status;

	ZwClose(hThread);
	return status;
}

void print_exit(void)
{
#ifdef _MSC_VER
	InterlockedExchange8(&do_exit, true);
#else
	__sync_bool_compare_and_swap(&do_exit, false, true);
#endif
	while (!exited)
		cpu_relax();
}

void do_print(const char *fmt, ...)
{
	char buffer[1 << PAGE_SHIFT];
	va_list va;
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
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", buffer);
			return;
		}

		KeAcquireInStackQueuedSpinLock(&lock, &q);
		next_use = stpcpy(next_use, buffer);
		barrier();
		KeReleaseInStackQueuedSpinLock(&q);
	}
}

#endif
