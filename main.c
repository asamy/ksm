#include "ksm.h"
#include "dpc.h"
#include "acpi.h"
#include "pe.h"

static DEV_EXT g_dev_ext = { NULL, NULL };
static HANDLE hThread;
static CLIENT_ID cid;

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

PLIST_ENTRY PsLoadedModuleList;
void *g_kernel_base = NULL;

static NTSTATUS sleep_ms(int ms)
{
	LARGE_INTEGER ival;
	ival.QuadPart = -(10000 * ms);

	return KeDelayExecutionThread(KernelMode, FALSE, &ival);
}

typedef PVOID(*MmMapLockedPagesSpecifyCache_t)(_In_     PMDLX               MemoryDescriptorList,
					       _In_     KPROCESSOR_MODE     AccessMode,
					       _In_     MEMORY_CACHING_TYPE CacheType,
					       _In_opt_ PVOID               BaseAddress,
					       _In_     ULONG               BugCheckOnFailure,
					       _In_     MM_PAGE_PRIORITY    Priority);
static PVOID hk_MmMapLockedPagesSpecifyCache(_In_     PMDLX               MemoryDescriptorList,
					     _In_     KPROCESSOR_MODE     AccessMode,
					     _In_     MEMORY_CACHING_TYPE CacheType,
					     _In_opt_ PVOID               BaseAddress,
					     _In_     ULONG               BugCheckOnFailure,
					     _In_     MM_PAGE_PRIORITY    Priority)
{
	PVOID ret = ((MmMapLockedPagesSpecifyCache_t)(uintptr_t)ksm_find_page(MmMapLockedPagesSpecifyCache)->data)(MemoryDescriptorList,
														   AccessMode,
														   CacheType,
														   BaseAddress,
														   BugCheckOnFailure,
														   Priority);
	PEPROCESS process = PsGetCurrentProcess();
	VCPU_DEBUG("%d(%s): Bytecount 0x%X SysVA %p StartVA %p Size 0x%X\n",
		   PsGetProcessId(process), PsGetProcessImageFileName(process),
		   MemoryDescriptorList->ByteCount, MemoryDescriptorList->MappedSystemVa,
		   MemoryDescriptorList->StartVa, MemoryDescriptorList->Size);
	return ret;
}

static NTSTATUS sys_thread(void *null)
{
	VCPU_DEBUG_RAW("waiting a bit\n");
	sleep_ms(2000);

	NTSTATUS status = ksm_hook_epage(MmMapLockedPagesSpecifyCache, hk_MmMapLockedPagesSpecifyCache);
	if (!NT_SUCCESS(status))
		return status;

	VCPU_DEBUG_RAW("Done hooked MmMapLockedPagesSepcifyCache\n");
	return status;
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	deregister_power_callback(&g_dev_ext);
	ksm_unhook_page(MmMapLockedPagesSpecifyCache);
	VCPU_DEBUG("ret: 0x%08X\n", ksm_exit());
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	LDR_DATA_TABLE_ENTRY *entry = driverObject->DriverSection;
	PsLoadedModuleList = entry->InLoadOrderLinks.Flink;
	driverObject->DriverUnload = DriverUnload;

	VCPU_DEBUG("We're mapped at %p (size: %d bytes (%d KB), on %d pages)\n",
		   entry->DllBase, entry->SizeOfImage, entry->SizeOfImage / 1024, entry->SizeOfImage / PAGE_SIZE);
	LDR_DATA_TABLE_ENTRY *kentry = container_of(PsLoadedModuleList->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	g_kernel_base = kentry->DllBase;

	VCPU_DEBUG("Kernel: %p -> %p (size: 0x%X pages: %d) path: %wS\n",
		   kentry->DllBase, (uintptr_t)kentry->DllBase + kentry->SizeOfImage,
		   kentry->SizeOfImage, BYTES_TO_PAGES(kentry->SizeOfImage),
		   kentry->FullDllName.Buffer);
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	NTSTATUS status = ksm_init();
	if (NT_SUCCESS(status))
		status = register_power_callback(&g_dev_ext);

//	Uncomment to enable the small hooking example
	if (NT_SUCCESS(status))
		status = PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, &cid, (PKSTART_ROUTINE)sys_thread, NULL);

	VCPU_DEBUG("ret: 0x%08X\n", status);
	return status;
}
