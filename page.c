#include "vcpu.h"
#include "dpc.h"
#include "ldasm.h"

extern struct kum kum;

static int find_free_page(void)
{
	for (unsigned int i = 0; i < kum.phi_count; ++i)
		if (kum.phi_pages[i] == KUM_FREE_PAGE)
			return i;
	return -1;
}

static void update_commons(uintptr_t va)
{
	unsigned int i;

	if (kum.phi_count == 0) {
		for (i = sizeof(uintptr_t) * CHAR_BIT - 1; i > 0; i--)
			if (va & ((uintptr_t)1 << i))
				break;

		kum.c_mask = ~((uintptr_t)1 << i);
		kum.c_bits = va & kum.c_mask;
		return;
	}

	uintptr_t m_diff = kum.c_bits ^ (va & kum.c_mask);
	uintptr_t b_diff = kum.c_bits & m_diff;
	for (i = 0; i < kum.phi_count; ++i) {
		kum.phi_pages[i] &= ~m_diff;
		kum.phi_pages[i] |= b_diff;
	}

	kum.c_mask &= ~m_diff;
	kum.c_bits &= ~m_diff;
}

static inline int __put_page(struct page_hook_info *phi)
{
	uintptr_t va = (uintptr_t)phi;
	int place = kum.phi_count;
	if (place >= KUM_MAX_PAGES)
		NT_ASSERT((place = find_free_page()) >= 0);

	kum.phi_pages[place] = (va & ~kum.c_mask) | kum.c_bits;
	kum.phi_count++;
	return place;
}

static inline int put_page(struct page_hook_info *phi)
{
	uintptr_t va = (uintptr_t)phi;
	if ((va & kum.c_mask) != kum.c_bits)
		update_commons(va);

	return __put_page(phi);
}

static inline struct page_hook_info *get_page(int i)
{
	uintptr_t va = kum.phi_pages[i];
	if (va == KUM_FREE_PAGE)
		return NULL;

	return (struct page_hook_info *)((va & ~kum.c_mask) | kum.c_bits);
}

#include <pshpack1.h>
struct trampoline {
	u8 push;
	u32 lo;
	u32 mov;
	u32 hi;
	u32 ret;
};
#include <poppack.h>

static void init_trampoline(struct trampoline *trampo, u64 to)
{
	// push lo
	// mov dword ptr [rsp + 0x4], hi
	// ret
	trampo->push = 0x68;
	trampo->lo = (u32)to;
	trampo->mov = 0x042444C7;
	trampo->hi = to >> 32;
	trampo->ret = 0xC3;
}

static inline bool is_int3_ret(u8 opc, u32 len)
{
	return len == 1 && (opc == 0xCC || opc == 0xC3);
}

static inline bool is_retn(u8 opc, u32 len)
{
	return len == 3 && opc == 0xC2;
}

static bool copy_code(void *func, u8 *out, u32 *outlen)
{
	u8 *src = func;
	u8 *tmp = out;
	u32 size = 0;
	ldasm_data ld;

	do {
		u32 len = ldasm(src, &ld, 1);
		if (ld.flags & F_INVALID || len + size > 128 ||
		    is_int3_ret(src[ld.opcd_offset], len) || is_retn(src[ld.opcd_offset], len))
			break;

		memcpy(tmp, src, len);
		if (ld.flags & F_RELATIVE) {
			const uintptr_t disp_offy = ld.disp_offset != 0 ? ld.disp_offset : ld.imm_offset;
			const uintptr_t disp_size = ld.disp_size != 0 ? ld.disp_size : ld.imm_size;

			long delta = 0;
			memcpy(&delta, src + disp_offy, disp_size);
			delta += (long)(src - tmp);
			memcpy(tmp + disp_offy, &delta, disp_size);
		}

		src += len;
		tmp += len;
		size += len;
	} while (size < sizeof(struct trampoline));
	if (size < sizeof(struct trampoline))
		return false;

	init_trampoline((struct trampoline *)tmp, (u64)src);
	*outlen = size;
	return true;
}

STATIC_DEFINE_DPC(__do_hook_page, __vmx_vmcall, HYPERCALL_HOOK, ctx);
STATIC_DEFINE_DPC(__do_unhook_page, __vmx_vmcall, HYPERCALL_UNHOOK, ctx);

int kum_hook_page(void *original, void *redirect)
{
	struct page_hook_info *phi = ExAllocatePool(NonPagedPoolExecute, sizeof(*phi));
	if (!phi)
		return -STATUS_NO_MEMORY;

	if (!copy_code(original, &phi->data[0], &phi->size)) {
		ExFreePool(phi);
		return -STATUS_BUFFER_TOO_SMALL;
	}

	u8 *code_page = MmAllocateContiguousMemory(PAGE_SIZE, (PHYSICAL_ADDRESS) { .QuadPart = -1 });
	if (!code_page) {
		ExFreePool(phi);
		return -STATUS_INSUFFICIENT_RESOURCES;
	}

	void *aligned = PAGE_ALIGN(original);
	uintptr_t offset = (uintptr_t)original - (uintptr_t)aligned;

	struct trampoline trampo;
	init_trampoline(&trampo, (uintptr_t)redirect);
	memcpy(code_page, aligned, PAGE_SIZE);
	memcpy(code_page + offset, &trampo, sizeof(trampo));

	phi->c_va = (uintptr_t)code_page;
	phi->c_pfn = __pfn(__pa(code_page));
	phi->d_pfn = __pfn(__pa(original));
	KeInvalidateAllCaches();

	STATIC_CALL_DPC(__do_hook_page, phi);
	if (NT_SUCCESS(STATIC_DPC_RET()))
		return put_page(phi);

	ExFreePool(phi);
	MmFreeContiguousMemory(code_page);
	return -STATUS_HV_ACCESS_DENIED;
}

NTSTATUS kum_unhook_page(int i)
{
	struct page_hook_info *phi = get_page(i);
	if (!phi)
		return STATUS_NOT_FOUND;

	STATIC_CALL_DPC(__do_unhook_page, (void *)phi->d_pfn);
	kum_free_phi(phi);
	kum.phi_pages[i] = 0;
	kum.phi_count--;
	return STATIC_DPC_RET();
}

void kum_init_phi_list(void)
{
	for (unsigned int i = 0; i < KUM_MAX_PAGES; ++i)
		kum.phi_pages[i] = KUM_FREE_PAGE;
	kum.phi_count = 0;
	kum.c_mask = 0;
	kum.c_bits = 0;
}

void kum_free_phi(struct page_hook_info *phi)
{
	MmFreeContiguousMemory((void *)phi->c_va);
	ExFreePool(phi);
}

void kum_free_phi_list(void)
{
	for (unsigned int i = 0; i < kum.phi_count; ++i)
		if (kum.phi_pages[i] != KUM_FREE_PAGE)
			kum_free_phi(get_page(i));
	kum.phi_count = 0;
}

struct page_hook_info *kum_find_hook(int i)
{
	return get_page(i);
}

struct page_hook_info *kum_find_hook_pfn(uintptr_t pfn)
{
	for (unsigned int i = 0; i < kum.phi_count; ++i)
		if (get_page(i)->d_pfn == pfn)
			return get_page(i);
	return NULL;
}
