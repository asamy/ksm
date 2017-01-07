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

				uintptr_t idx = (pte_base >> PXI_SHIFT) & PTX_MASK;
				pde_base = pte_base | (idx << PPI_SHIFT);
				ppe_base = pde_base | (idx << PDI_SHIFT);
				pxe_base = ppe_base | (idx << PTI_SHIFT);
				found = true;
				break;
			}
		}

		if (!found)
			return STATUS_NOT_FOUND;

		uintptr_t tmp = (uintptr_t)MmGetVirtualForPhysical;
		VCPU_DEBUG("PXE: %p PPE %p PDE %p PTE %p\n", pxe_base, ppe_base, pde_base, pte_base);
		VCPU_DEBUG("Addr 0x%X 0x%X\n", __pa((uintptr_t *)tmp), va_to_pa(tmp));
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
	VCPU_DEBUG("ret: 0x%08X\n", ret);
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
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	void *buf = irp->AssociatedIrp.SystemBuffer;
	u32 inlen = stack->Parameters.DeviceIoControl.InputBufferLength;
	u32 ioctl;

	switch (stack->MajorFunction) {
	case IRP_MJ_DEVICE_CONTROL:	
		ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
		VCPU_DEBUG("%s: IOCTL: 0x%08X\n", proc_name(), ioctl);

		switch (ioctl) {
#ifdef PMEM_SANDBOX
		case KSM_IOCTL_SANDBOX:
			status = ksm_sandbox(ksm, (pid_t)(*(int *)buf));
			break;
		case KSM_IOCTL_UNBOX:
			status = ksm_unbox(ksm, (pid_t)(*(int *)buf));
			break;
#endif
		case KSM_IOCTL_SUBVERT:
			status = ksm_subvert(ksm);
			break;
		case KSM_IOCTL_UNSUBVERT:
			status = ksm_unsubvert(ksm);
			break;
		default:
			status = STATUS_NOT_SUPPORTED;
			break;
		}
		break;
	case IRP_MJ_SHUTDOWN:
		/* Ignore return value  */
		ksm_free(ksm);
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

	VCPU_DEBUG("We're mapped at %p (size: %d bytes (%d KB), on %d pages)\n",
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
	driverObject->MajorFunction[IRP_MJ_CREATE] =
		driverObject->MajorFunction[IRP_MJ_CLOSE] =
		driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

	RtlInitUnicodeString(&deviceLink, KSM_DOS_NAME);
	if (NT_SUCCESS(status = IoCreateSymbolicLink(&deviceLink, &deviceName))) {
		VCPU_DEBUG_RAW("ready\n");
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
	VCPU_DEBUG("ret: 0x%08X\n", status);
	return status;
}
