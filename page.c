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
#ifdef __linux__
#include <linux/vmalloc.h>
#else
#include <ntddk.h>
#endif

#include "ksm.h"
#include "percpu.h"

static inline void epage_init_eptp(struct page_hook_info *phi, struct ept *ept)
{
	u64 dpa = phi->d_pfn << PAGE_SHIFT;
	u64 cpa = phi->c_pfn << PAGE_SHIFT;
	ept_alloc_page(EPT4(ept, EPTP_EXHOOK), EPT_ACCESS_EXEC, dpa, cpa);
	ept_alloc_page(EPT4(ept, EPTP_RWHOOK), EPT_ACCESS_RW, dpa, dpa);
	ept_alloc_page(EPT4(ept, EPTP_NORMAL), EPT_ACCESS_EXEC, dpa, dpa);
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

#ifndef __linux__
#include <pshpack1.h>
#endif
struct trampoline {
	u8 push;
	u32 lo;
	u32 mov;
	u32 hi;
	u32 ret;
} __packed;
#ifndef __linux__
#include <poppack.h>
#endif

static void epage_init_trampoline(struct trampoline *trampo, u64 to)
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

int ksm_hook_epage(void *original, void *redirect)
{
	struct page_hook_info *phi = mm_alloc_pool(sizeof(*phi));
	if (!phi)
		return ERR_NOMEM;

#ifdef __linux__
	void *tmp = mm_alloc_page();
	phi->backing_page = tmp;

	u8 *code_page = map_exec(tmp, PAGE_SIZE);
#else
	u8 *code_page = MmAllocateContiguousMemory(PAGE_SIZE,
						  (PHYSICAL_ADDRESS) { .QuadPart = -1 });
#endif
	if (!code_page) {
		mm_free_pool(phi, sizeof(*phi));
		return ERR_NOMEM;
	}

	/* Offset where code starts in this page  */
	void *aligned = (void *)page_align(original);
	uintptr_t offset = (uintptr_t)original - (uintptr_t)aligned;

	struct trampoline trampo;
	epage_init_trampoline(&trampo, (uintptr_t)redirect);
	memcpy(code_page, aligned, PAGE_SIZE);
	memcpy(code_page + offset, &trampo, sizeof(trampo));

	phi->c_va = code_page;
	phi->c_pfn = __pa(code_page) >> PAGE_SHIFT;
	phi->d_pfn = __pa(original) >> PAGE_SHIFT;
	phi->origin = (u64)aligned;
	phi->ops = &epage_ops;

	STATIC_CALL_DPC(__do_hook_page, phi);
	htable_add(&ksm.ht, page_hash(phi->origin), phi);
	return 0;
}

int ksm_unhook_page(void *va)
{
	struct page_hook_info *phi = ksm_find_page(va);
	if (!phi)
		return ERR_NOTH;

	return __ksm_unhook_page(phi);
}

int __ksm_unhook_page(struct page_hook_info *phi)
{
	STATIC_CALL_DPC(__do_unhook_page, (void *)(phi->d_pfn << PAGE_SHIFT));
#ifdef __linux__
	vunmap(phi->c_va);
	mm_free_page(phi->backing_page);
#else
	MmFreeContiguousMemory(phi->c_va);
#endif
	htable_del(&ksm.ht, page_hash(phi->origin), phi);
	mm_free_pool(phi, sizeof(*phi));
	return STATIC_DPC_RET();
}

struct page_hook_info *ksm_find_page(void *va)
{
	const void *align = (const void *)page_align(va);
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
