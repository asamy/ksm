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

static int hk_page_idx;
typedef PVOID (*ExAllocatePoolWithTag_t) (_In_ POOL_TYPE PoolType,
					  _In_ SIZE_T    NumberOfBytes,
					  _In_ ULONG     Tag);
static PVOID hk_ExAllocatePoolWithTag(_In_ POOL_TYPE PoolType, _In_ SIZE_T    NumberOfBytes, _In_ ULONG     Tag)
{
	VCPU_DEBUG("ExAllocatePoolWithTAg: %d %d %d\n", PoolType, NumberOfBytes, Tag);

	struct page_hook_info *phi = ksm_find_hook(hk_page_idx);
	if (phi)
		return ((ExAllocatePoolWithTag_t)(uintptr_t)phi->data)(PoolType, NumberOfBytes, Tag);

	VCPU_DEBUG_RAW("You derped\n");
	return NULL;
}

static NTSTATUS sys_thread(void *null)
{
	VCPU_DEBUG_RAW("waiting a bit\n");
	sleep_ms(2000);

	int m = ksm_hook_page(ExAllocatePoolWithTag, hk_ExAllocatePoolWithTag);
	if (m >= 0) {
		hk_page_idx = m;

		VCPU_DEBUG("hooked: %d\n", m);
		sleep_ms(2000);

		void *pool = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 0);
		if (pool)
			ExFreePoolWithTag(pool, 0);
		sleep_ms(500);

		/* Trigger #VE  */
		struct page_hook_info *phi = ksm_find_hook(m);
		u8 *r = (u8 *)(uintptr_t)ExAllocatePoolWithTag;
		for (u32 i = 0; i < phi->size; ++i)
			VCPU_DEBUG("0x%X - 0x%X (eq: %s)\n", 
				   r[i], phi->data[i], r[i] == phi->data[i] ? "yes" : "no");
		VCPU_DEBUG_RAW("unhooking\n");
		ksm_unhook_page(hk_page_idx);
	}

	return STATUS_SUCCESS;
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
