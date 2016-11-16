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
#include <ntifs.h>
#include <ntstrsafe.h>

#include "ksm.h"

#define PRINT_BUF_PAGES		6
#define PRINT_BUF_SIZE		(PAGE_SIZE * PRINT_BUF_PAGES)

static bool do_exit = false;
static bool do_work = false;
static bool exited = false;
static char buf[PRINT_BUF_SIZE];
static size_t curr_pos = 0;
static KSPIN_LOCK lock;

static void print_flush(void)
{
	buf[curr_pos] = '\0';
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", buf);
	curr_pos = 0;
}

static NTSTATUS print_thread(void)
{
	while (!do_exit) {
		while (!do_work)
			_mm_pause();

		KLOCK_QUEUE_HANDLE q;
		KeAcquireInStackQueuedSpinLock(&lock, &q);
		print_flush();
		InterlockedExchange8(&do_work, false);
		KeReleaseInStackQueuedSpinLock(&q);

		if (do_exit)
			break;
	}

	if (curr_pos != 0)
		print_flush();

	exited = true;
	return STATUS_SUCCESS;
}

NTSTATUS print_init(void)
{
	HANDLE hThread;
	CLIENT_ID cid;
	NTSTATUS status;

	KeInitializeSpinLock(&lock);
	memset(&buf[0], 0x00, sizeof(buf));

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
	InterlockedExchange8(&do_exit, true);
	while (!exited)
		_mm_pause();
}

void do_print(const char *fmt, ...)
{
	if (do_exit || curr_pos >= PRINT_BUF_SIZE)
		return;

	va_list va;
	va_start(va, fmt);

	char buffer[1024];
	NTSTATUS status = RtlStringCchVPrintfA(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	if (!NT_SUCCESS(status))
		return;

	KLOCK_QUEUE_HANDLE q;
	KeAcquireInStackQueuedSpinLockForDpc(&lock, &q); {
		size_t len = strlen(buffer);
		memcpy(&buf[curr_pos], &buffer[0], len);
		curr_pos += len;
	} KeReleaseInStackQueuedSpinLockFromDpcLevel(&q);
	InterlockedExchange8(&do_work, 1);
}

#endif
