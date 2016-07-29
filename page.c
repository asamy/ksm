#include "vcpu.h"
#include "dpc.h"
#include "ldasm.h"

static inline void epage_init_eptp(struct page_hook_info *phi, struct ept *ept)
{
	uintptr_t dpa = phi->d_pfn << PAGE_SHIFT;
	uintptr_t *epte = ept_pte(ept, EPT4(ept, EPTP_EXHOOK), dpa);
	__set_epte_ar_pfn(epte, EPT_ACCESS_EXEC, phi->c_pfn);

	epte = ept_pte(ept, EPT4(ept, EPTP_RWHOOK), dpa);
	__set_epte_ar_pfn(epte, EPT_ACCESS_RW, phi->c_pfn);

	epte = ept_pte(ept, EPT4(ept, EPTP_NORMAL), dpa);
	__set_epte_ar(epte, EPT_ACCESS_RW);

	/* FIXME:  Maybe should switch to EPTP_EXHOOK incase we are not already,
	 * should probably save a few cycles i.e. a violation?
	 * This is not the case right now...  May also help find several bugs?  */
	__invept_all();
}

static inline u16 epage_select_eptp(struct page_hook_info *phi, u16 cur, u8 ar, u8 ac)
{
	if (ac & EPT_ACCESS_READ)
		return EPTP_NORMAL;

	if (ac & EPT_ACCESS_WRITE)
		return EPTP_RWHOOK;

	return EPTP_EXHOOK;
}

static struct phi_ops epage_ops = {
	.init_eptp = epage_init_eptp,
	.select_eptp = epage_select_eptp,
};

static inline bool ht_cmp(const void *candidate, const void *cmp)
{
	const struct page_hook_info *phi = candidate;
	return phi->origin == (uintptr_t)cmp;
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

NTSTATUS ksm_hook_epage(void *original, void *redirect)
{
	struct page_hook_info *phi = ExAllocatePool(NonPagedPoolExecute, sizeof(*phi));
	if (!phi)
		return STATUS_NO_MEMORY;

	if (!copy_code(original, &phi->data[0], &phi->size)) {
		ExFreePool(phi);
		return STATUS_BUFFER_TOO_SMALL;
	}

	u8 *code_page = MmAllocateContiguousMemory(PAGE_SIZE, (PHYSICAL_ADDRESS) { .QuadPart = -1 });
	if (!code_page) {
		ExFreePool(phi);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	void *aligned = PAGE_ALIGN(original);
	uintptr_t offset = (uintptr_t)original - (uintptr_t)aligned;

	struct trampoline trampo;
	init_trampoline(&trampo, (uintptr_t)redirect);
	memcpy(code_page, aligned, PAGE_SIZE);
	memcpy(code_page + offset, &trampo, sizeof(trampo));

	phi->c_va = code_page;
	phi->c_pfn = __pfn(__pa(code_page));
	phi->d_pfn = __pfn(__pa(original));
	phi->origin = (u64)aligned;
	phi->ops = &epage_ops;

	STATIC_CALL_DPC(__do_hook_page, phi);
	if (NT_SUCCESS(STATIC_DPC_RET())) {
		htable_add(&ksm.ht, page_hash(phi->origin), phi);
		return STATUS_SUCCESS;
	}

	ExFreePool(phi);
	MmFreeContiguousMemory(code_page);
	return STATUS_HV_ACCESS_DENIED;
}

NTSTATUS ksm_unhook_page(void *va)
{
	struct page_hook_info *phi = htable_get(&ksm.ht, page_hash((u64)va), ht_cmp, va);
	if (!phi)
		return STATUS_NOT_FOUND;

	return __ksm_unhook_page(phi);
}

NTSTATUS __ksm_unhook_page(struct page_hook_info *phi)
{
	STATIC_CALL_DPC(__do_unhook_page, (void *)phi->d_pfn);
	htable_del(&ksm.ht, page_hash(phi->origin), phi);
	return STATIC_DPC_RET();
}

struct page_hook_info *ksm_find_page(void *va)
{
	void *align = PAGE_ALIGN(va);
	return htable_get(&ksm.ht, page_hash((u64)align), ht_cmp, align);
}

struct page_hook_info *ksm_find_page_pfn(uintptr_t pfn)
{
	struct htable_iter i;
	for (struct page_hook_info *phi = htable_first(&ksm.ht, &i); phi; phi = htable_next(&ksm.ht, &i))
		if (phi->d_pfn == pfn)
			return phi;
	return NULL;
}
