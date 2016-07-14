#include "vcpu.h"
#include "dpc.h"
#include "power.h"

static DEV_EXT g_dev_ext;
static HANDLE hThread;
static CLIENT_ID cid;

typedef struct {
	LIST_ENTRY in_load_links;
	LIST_ENTRY in_memory_links;
	LIST_ENTRY in_init_links;
	void *base;
	void *ep;
	u32 size;
	UNICODE_STRING path;
} LdrDataTableEntry;

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
	if (MemoryDescriptorList == (PMDLX)0xdeadbeef)
		return (PVOID)0xbaadf00d;

	VCPU_DEBUG("Mapping via MDL %p Mode %d base: %p\n", MemoryDescriptorList, AccessMode, BaseAddress);
	return ((MmMapLockedPagesSpecifyCache_t)(uintptr_t)ksm_find_hook(0)->data)(MemoryDescriptorList,
										   AccessMode,
										   CacheType,
										   BaseAddress,
										   BugCheckOnFailure,
										   Priority);
}

static NTSTATUS sys_thread(void *null)
{
	VCPU_DEBUG_RAW("waiting a bit\n");
	sleep_ms(2000);

	int m = ksm_hook_page(MmMapLockedPagesSpecifyCache, hk_MmMapLockedPagesSpecifyCache);
	if (m >= 0) {
		VCPU_DEBUG("hooked: %d\n", m);
		if (MmMapLockedPagesSpecifyCache((PMDLX)0xdeadbeef,
						 KernelMode,
						 MmNonCached,
						 (PVOID)0x00000000,
						 TRUE,
						 NormalPagePriority) == (PVOID)0xbaadf00d)
			VCPU_DEBUG_RAW("We succeeded\n");
		else
			VCPU_DEBUG_RAW("we failed\n");
		sleep_ms(2000);

		/* Trigger #VE  */
		struct page_hook_info *phi = ksm_find_hook(m);
		u8 *r = (u8 *)(uintptr_t)MmMapLockedPagesSpecifyCache;
		VCPU_DEBUG("Equality: %d\n", memcmp(r, phi->data, phi->size));
		return ksm_unhook_page(m);
	}

	return -m;
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	deregister_power_callback(&g_dev_ext);
	VCPU_DEBUG("ret: 0x%08X\n", ksm_exit());
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	LdrDataTableEntry *entry = driverObject->DriverSection;
	PsLoadedModuleList = entry->in_load_links.Flink;
	driverObject->DriverUnload = DriverUnload;

	VCPU_DEBUG("We're mapped at %p (size: %d bytes (%d KB), on %d pages)\n",
		   entry->base, entry->size, entry->size / 1024, entry->size / PAGE_SIZE);
	LdrDataTableEntry *kentry = container_of(PsLoadedModuleList->Flink, LdrDataTableEntry, in_load_links);
	g_kernel_base = kentry->base;

	VCPU_DEBUG("Kernel: %p -> %p (size: 0x%X pages: %d) path: %wS\n",
		   kentry->base, (uintptr_t)kentry->base + kentry->size,
		   kentry->size, BYTES_TO_PAGES(kentry->size),
		   kentry->path.Buffer);
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	NTSTATUS status = ksm_init();
	if (NT_SUCCESS(status))
		status = register_power_callback(&g_dev_ext);

	if (NT_SUCCESS(status))
		status = PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, &cid, (PKSTART_ROUTINE)sys_thread, NULL);

	VCPU_DEBUG("ret: 0x%08X\n", status);
	return status;
}
