/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Main windows kernel driver entry point.
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
#include <ntddk.h>
#include <intrin.h>

#include "ksm.h"
#include "um/um.h"

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifndef __GNUC__
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)
#endif

PLIST_ENTRY PsLoadedModuleList;
uintptr_t g_driver_base;
uintptr_t g_driver_size;

uintptr_t pxe_base = 0xfffff6fb7dbed000ull;
uintptr_t ppe_base = 0xfffff6fb7da00000ull;
uintptr_t pde_base = 0xfffff6fb40000000ull;
uintptr_t pte_base = 0xfffff68000000000ull;

/* Master process cr3  */
static uintptr_t caller_cr3 = 0;

static inline NTSTATUS check_dynamic_pgtables(void)
{
	/* On Windows 10 build 14316+ Page table base addresses are not static.  */
	RTL_OSVERSIONINFOW osv;
	osv.dwOSVersionInfoSize = sizeof(osv);

	NTSTATUS status = RtlGetVersion(&osv);
	if (!NT_SUCCESS(status))
		return status;

	if (osv.dwMajorVersion >= 10 && osv.dwBuildNumber >= 14316) {
		static const u8 pattern[] = {
			0x48, 0x8b, 0x04, 0xd0,  // mov     rax, [rax+rdx*8]
			0x48, 0xc1, 0xe0, 0x19,  // shl     rax, 19h
			0x48, 0xba,              // mov     rdx, ????????`????????  ; PTE_BASE
		};

		u8 *base = (u8 *)MmGetVirtualForPhysical;
		bool found = false;
		for (size_t i = 0; i <= 0x50 - sizeof(pattern); ++i) {
			if (RtlCompareMemory(pattern, &base[i], sizeof(pattern)) == sizeof(pattern)) {
				pte_base = *(uintptr_t *)(base + i + sizeof(pattern));

				uintptr_t idx = (pte_base >> PGD_SHIFT_P) & PTX_MASK;
				pde_base = pte_base | (idx << PUD_SHIFT_P);
				ppe_base = pde_base | (idx << PMD_SHIFT_P);
				pxe_base = ppe_base | (idx << PTE_SHIFT_P);
				found = true;
				break;
			}
		}

		if (!found)
			return STATUS_NOT_FOUND;

		uintptr_t tmp = (uintptr_t)MmGetVirtualForPhysical;
		KSM_DEBUG("PXE: %p PPE %p PDE %p PTE %p\n", pxe_base, ppe_base, pde_base, pte_base);
		KSM_DEBUG("Addr 0x%X 0x%X\n", __pa((uintptr_t *)tmp), va_to_pa(tmp));
	}

	return STATUS_SUCCESS;
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
	int ret;
	UNICODE_STRING deviceLink;

	UNREFERENCED_PARAMETER(driverObject);
	RtlInitUnicodeString(&deviceLink, KSM_DOS_NAME);

	ret = ksm_free(ksm);
	KSM_DEBUG("ret: 0x%08X\n", ret);
#ifdef ENABLE_PRINT
	print_exit();
#endif
	IoDeleteSymbolicLink(&deviceLink);
	IoUnregisterShutdownNotification(driverObject->DeviceObject);
	IoDeleteDevice(driverObject->DeviceObject);
}

static NTSTATUS DriverDispatch(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack;
	void *buf;
	u32 inlen;
	u32 ioctl;

	stack = IoGetCurrentIrpStackLocation(irp);
	switch (stack->MajorFunction) {
	case IRP_MJ_DEVICE_CONTROL:
		buf = irp->AssociatedIrp.SystemBuffer;
		ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
		inlen = stack->Parameters.DeviceIoControl.InputBufferLength;
		KSM_DEBUG("%s: IOCTL: 0x%08X of length: %d\n", proc_name(), ioctl, inlen);

		if (caller_cr3 != 0 && caller_cr3 != __readcr3()) {
			KSM_DEBUG("%s: not processing ioctl\n", proc_name());
			status = STATUS_ABANDONED;
			break;
		}

		switch (ioctl) {
#ifdef PMEM_SANDBOX
		case KSM_IOCTL_SANDBOX:
			if (inlen < 4)
				status = STATUS_INFO_LENGTH_MISMATCH;
			else
				status = ksm_sandbox(ksm, (pid_t)(*(int *)buf));
			break;
		case KSM_IOCTL_UNBOX:
			if (inlen < 4)
				status = STATUS_INFO_LENGTH_MISMATCH;
			else
				status = ksm_unbox(ksm, (pid_t)(*(int *)buf));
			break;
#endif
		case KSM_IOCTL_SUBVERT:
			caller_cr3 = __readcr3();
			status = ksm_subvert(ksm);
			break;
		case KSM_IOCTL_UNSUBVERT:
			status = ksm_unsubvert(ksm);
			if (NT_SUCCESS(status))
				caller_cr3 = 0;
			break;
#ifdef INTROSPECT_ENGINE
		case KSM_IOCTL_INTRO_START:
			status = ksm_introspect_start(ksm);
			break;
		case KSM_IOCTL_INTRO_STOP:
			status = ksm_introspect_stop(ksm);
			break;
		case KSM_IOCTL_INTRO_WATCH:
			if (inlen < sizeof(struct watch_ioctl))
				status = STATUS_INFO_LENGTH_MISMATCH;
			else
				status = ksm_introspect_add_watch(ksm, (struct watch_ioctl *)buf);
			break;
		case KSM_IOCTL_INTRO_UNWATCH:
			if (inlen < sizeof(struct watch_ioctl))
				status = STATUS_INFO_LENGTH_MISMATCH;
			else
				status = ksm_introspect_rem_watch(ksm, (struct watch_ioctl *)buf);
			break;
		case KSM_IOCTL_INTRO_STATS:
			if (inlen < sizeof(struct watch_ioctl))
				status = STATUS_INFO_LENGTH_MISMATCH;
			else if (NT_SUCCESS(status = ksm_introspect_collect(ksm, (struct watch_ioctl *)buf)))
				irp->IoStatus.Information = sizeof(struct watch_ioctl);
			break;
#endif
		default:
			status = STATUS_NOT_SUPPORTED;
			break;
		}
		break;
	case IRP_MJ_SHUTDOWN:
		/* Ignore return value  */
		ksm_unsubvert(ksm);
		break;
	case IRP_MJ_CREATE:
		KSM_DEBUG("open from %s\n", proc_name());
		break;
	case IRP_MJ_CLOSE:
		KSM_DEBUG("close from %s\n", proc_name());
		break;
	default:
		KSM_DEBUG("unhandled func %X\n", stack->MajorFunction);
		break;
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	LDR_DATA_TABLE_ENTRY *entry;
	UNICODE_STRING deviceName;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING deviceLink;

#ifdef ENABLE_PRINT
	/* Stupid printing interface  */
	if (!NT_SUCCESS(status = print_init())) {
		DbgPrint("failed to initialize log: 0x%08X\n", status);
		return status;
	}
#endif

	if (!NT_SUCCESS(status = check_dynamic_pgtables()))
		goto err;

	entry = driverObject->DriverSection;
	PsLoadedModuleList = entry->InLoadOrderLinks.Flink;

	KSM_DEBUG("We're mapped at %p (size: %d bytes (%d KB), on %d pages)\n",
		  entry->DllBase, entry->SizeOfImage,
		  entry->SizeOfImage / 1024, entry->SizeOfImage / PAGE_SIZE);
	g_driver_base = (uintptr_t)entry->DllBase;
	g_driver_size = entry->SizeOfImage;

	if (!NT_SUCCESS(status = ksm_init(&ksm)))
		goto err;

	RtlInitUnicodeString(&deviceName, KSM_DEVICE_NAME);
	status = IoCreateDevice(driverObject, 0, &deviceName,
				KSM_DEVICE_MAGIC, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
		goto exit;

	if (!NT_SUCCESS(IoRegisterShutdownNotification(deviceObject)))
		goto err2;

	driverObject->DriverUnload = DriverUnload;
	driverObject->MajorFunction[IRP_MJ_SHUTDOWN] =
	driverObject->MajorFunction[IRP_MJ_CREATE] =
		driverObject->MajorFunction[IRP_MJ_CLOSE] =
		driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

	RtlInitUnicodeString(&deviceLink, KSM_DOS_NAME);
	if (NT_SUCCESS(status = IoCreateSymbolicLink(&deviceLink, &deviceName))) {
		KSM_DEBUG_RAW("ready\n");
		ksm->host_pgd = __readcr3();
		goto out;
	}

	IoUnregisterShutdownNotification(deviceObject);
err2:
	IoDeleteDevice(deviceObject);
exit:
	ksm_free(ksm);
err:
#ifdef ENABLE_PRINT
	print_exit();
#endif
out:
	KSM_DEBUG("ret: 0x%08X\n", status);
	return status;
}
