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
#ifdef EPAGE_HOOK
#include <ntddk.h>

#include "ksm.h"
#include "dpc.h"

static inline void epage_init_eptp(struct page_hook_info *phi, struct ept *ept)
{
	uintptr_t dpa = phi->d_pfn << PAGE_SHIFT;
	uintptr_t *epte = ept_alloc_page(ept, EPT4(ept, EPTP_EXHOOK), EPT_ACCESS_EXEC, dpa);
	__set_epte_ar_pfn(epte, EPT_ACCESS_EXEC, phi->c_pfn);

	ept_alloc_page(ept, EPT4(ept, EPTP_RWHOOK), EPT_ACCESS_RW, dpa);
	ept_alloc_page(ept, EPT4(ept, EPTP_NORMAL), EPT_ACCESS_EXEC, dpa);

	__invept_all();
}

static inline u16 epage_select_eptp(struct page_hook_info *phi, u16 cur, u8 ar, u8 ac)
{
	if (ac & EPT_ACCESS_RW)
		return EPTP_RWHOOK;

	return EPTP_EXHOOK;
}

static struct phi_ops epage_ops = {
	.init_eptp = epage_init_eptp,
	.select_eptp = epage_select_eptp,
};

static inline bool ht_cmp(const void *candidate, void *cmp)
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

STATIC_DEFINE_DPC(__do_hook_page, __vmx_vmcall, HYPERCALL_HOOK, ctx);
STATIC_DEFINE_DPC(__do_unhook_page, __vmx_vmcall, HYPERCALL_UNHOOK, ctx);

NTSTATUS ksm_hook_epage(void *original, void *redirect)
{
	struct page_hook_info *phi = mm_alloc_pool(NonPagedPool, sizeof(*phi));
	if (!phi)
		return STATUS_NO_MEMORY;

	u8 *code_page = MmAllocateContiguousMemory(PAGE_SIZE, (PHYSICAL_ADDRESS) { .QuadPart = -1 });
	if (!code_page) {
		mm_free_pool(phi, sizeof(*phi));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* Offset where code starts in this page  */
	void *aligned = PAGE_ALIGN(original);
	uintptr_t offset = (uintptr_t)original - (uintptr_t)aligned;

	struct trampoline trampo;
	init_trampoline(&trampo, (uintptr_t)redirect);
	memcpy(code_page, aligned, PAGE_SIZE);
	memcpy(code_page + offset, &trampo, sizeof(trampo));

	phi->c_va = code_page;
	phi->c_pfn = __pa(code_page) >> PAGE_SHIFT;
	phi->d_pfn = __pa(original) >> PAGE_SHIFT;
	phi->origin = (u64)aligned;
	phi->ops = &epage_ops;

	STATIC_CALL_DPC(__do_hook_page, phi);
	htable_add(&ksm.ht, page_hash(phi->origin), phi);
	return STATUS_SUCCESS;
}

NTSTATUS ksm_unhook_page(void *va)
{
	struct page_hook_info *phi = ksm_find_page(va);
	if (!phi)
		return STATUS_NOT_FOUND;

	return __ksm_unhook_page(phi);
}

NTSTATUS __ksm_unhook_page(struct page_hook_info *phi)
{
	STATIC_CALL_DPC(__do_unhook_page, (void *)(phi->d_pfn << PAGE_SHIFT));
	MmFreeContiguousMemory(phi->c_va);
	htable_del(&ksm.ht, page_hash(phi->origin), phi);
	mm_free_pool(phi, sizeof(*phi));
	return STATIC_DPC_RET();
}

struct page_hook_info *ksm_find_page(void *va)
{
	const void *align = PAGE_ALIGN(va);
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
#endif
