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
#include "ksm.h"

static uintptr_t *ept_alloc_entry(struct ept *ept)
{
	if (ept) {
		if (ept->pre_alloc_used >= EPT_MAX_PREALLOC)
			return NULL;

		return ept->pre_alloc[ept->pre_alloc_used++];
	}

	return mm_alloc_pool(NonPagedPool, PAGE_SIZE);
}

static inline void ept_init_entry(uintptr_t *entry, uint8_t access, uintptr_t phys)
{
	*entry ^= *entry;
	*entry |= access & EPT_ACCESS_MAX_BITS;
	*entry |= (phys >> PAGE_SHIFT) << PAGE_SHIFT;
#ifdef EPT_SUPPRESS_VE
	*entry |= EPT_SUPPRESS_VE_BIT;
#endif
}

/*
 * Sets up page tables for the required guest physical address, aka AMD64 page
 * tables, which are ugly and can be confusing, so here's an explanation of what
 * this does:
 *
 *	PML4 (aka Page Map Level 4) ->
 *		PML4E (aka PDPT or Page Directory Pointer Table) ->
 *			PDPTE (aka PDT or Page Directory Table) ->
 *				PDTE (aka PT or Page Table) ->
 *					PTE (aka Page)
 *
 * Assuming:
 *	1) Each PML4 entry is 1 GB, so that makes the whole PML4 table 512 GB
 *	2) Each PDPT entry is 2 MB, so that makes the whole PDPT table 1 GB
 *	3) Each PDT entry is 4 KG, so that makes the whole PDT table 2 MB
 *
 * So, with that being said, while we only have the initial table (PML4) virtual address
 * to work with, we need first need to get an offset into it (for the PDPT), and so on, so
 * we use the following macros:
 *	- __pxe_idx(pa)		- Gives an offset into PML4 to get the PDPT
 *	- __ppe_idx(pa)		- Gives an offset into PDPT to get the PDT
 *	- __pde_idx(pa)		- Gives an offset into PDT to get the PT 
 *	- __pte_idx(pa)		- Gives an offset into PT to get the final page!
 *
 * And since each of those entries contain a physical address, we need to use
 * page_addr() to obtain the virtual address for that specific table, what page_addr()
 * does is quite simple, it checks if the entry is not NULL and is present, then does
 * __va(PAGE_PA(entry)).
 */
uintptr_t *ept_alloc_page(struct ept *ept, uintptr_t *pml4, uint8_t access, uintptr_t phys)
{
	/* PML4 (512 GB) */
	uintptr_t *pml4e = &pml4[__pxe_idx(phys)];
	uintptr_t *pdpt = page_addr(pml4e);

	if (!pdpt) {
		pdpt = ept_alloc_entry(ept);
		if (!pdpt)
			return NULL;

		ept_init_entry(pml4e, EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	uintptr_t *pdpte = &pdpt[__ppe_idx(phys)];
	uintptr_t *pdt = page_addr(pdpte);
	if (!pdt) {
		pdt = ept_alloc_entry(ept);
		if (!pdt)
			return NULL;

		ept_init_entry(pdpte, EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	uintptr_t *pdte = &pdt[__pde_idx(phys)];
	uintptr_t *pt = page_addr(pdte);
	if (!pt) {
		pt = ept_alloc_entry(ept);
		if (!pt)
			return NULL;

		ept_init_entry(pdte, EPT_ACCESS_ALL, __pa(pt));
	}

	/* PT (4 KB)  */
	uintptr_t *page = &pt[__pte_idx(phys)];
	ept_init_entry(page, access, phys);

	*page |= EPT_MT_WRITEBACK << VMX_EPT_MT_EPTE_SHIFT;
#ifdef EPT_SUPPRESS_VE
	*page |= EPT_SUPPRESS_VE_BIT;
#endif
	return page;
}

/*
 * Free pre-allocated EPT entries, discarding used entries because they were
 * used by ept_alloc_page(), so no need to confuse each other.
 */
static void ept_free_prealloc(struct ept *ept)
{
	for (u32 i = ept->pre_alloc_used; i < EPT_MAX_PREALLOC; ++i)
		if (ept->pre_alloc[i])
			mm_free_pool(ept->pre_alloc[i], PAGE_SIZE);
}

/*
 * Recursively free each table entries, see ept_alloc_page()
 * for an explanation.
 */
static void ept_free_entries(uintptr_t *table, uint32_t lvl)
{
	for (int i = 0; i < 512; ++i) {
		uintptr_t entry = table[i];
		if (entry) {
			uintptr_t *sub_table = __va(PAGE_PA(entry));
			if (lvl > 2)
				ept_free_entries(sub_table, lvl - 1);
			else
				mm_free_pool(sub_table, PAGE_SIZE);
		}
	}

	mm_free_pool(table, PAGE_SIZE);
}

static void ept_free_pml4_list(struct ept *ept)
{
	for (int i = 0; i < EPTP_USED; ++i)
		if (EPT4(ept, i))
			ept_free_entries(EPT4(ept, i), 4);
}

static bool setup_pml4(struct ept *ept)
{
	PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges)
		return false;

	bool ret = false;
	for (int run = 0;; ++run) {
		uintptr_t base_addr = pm_ranges[run].BaseAddress.QuadPart;
		uintptr_t bytes = pm_ranges[run].NumberOfBytes.QuadPart;
		if (!base_addr || !bytes)
			break;

		uintptr_t nr_pages = BYTES_TO_PAGES(bytes);
		for (uintptr_t page = 0; page < nr_pages; ++page) {
			uintptr_t page_addr = base_addr + page * PAGE_SIZE;
			for_each_eptp(i)
				if (!ept_alloc_page(NULL, EPT4(ept, i), EPT_ACCESS_ALL, page_addr))
					goto out;
		}
	}

	/* Allocate APIC page  */
	for_each_eptp(i)
		if (!(ret = ept_alloc_page(NULL, EPT4(ept, i), EPT_ACCESS_ALL, __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE)))
			break;

out:
	mm_free_pool(pm_ranges, sizeof(PHYSICAL_MEMORY_RANGE));
	return ret;
}

static inline void setup_eptp(uintptr_t *ptr, uintptr_t pml4_pfn)
{
	*ptr ^= *ptr;
	*ptr |= VMX_EPT_DEFAULT_MT;
	*ptr |= VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
#ifdef ENABLE_PML
	*ptr |= VMX_EPT_AD_ENABLE_BIT;
#endif
	*ptr |= pml4_pfn << PAGE_SHIFT;
}

bool ept_init(struct ept *ept)
{
	for_each_eptp(i) {
		uintptr_t **pml4 = &EPT4(ept, i);
		if (!(*pml4 = mm_alloc_pool(NonPagedPool, PAGE_SIZE)))
			goto err_pml4_list;

		setup_eptp(&EPTP(ept, i), __pa(*pml4) >> PAGE_SHIFT);
	}

	if (!setup_pml4(ept))
		goto err_pml4_list;

	for (int i = 0; i < EPT_MAX_PREALLOC; ++i) {
		uintptr_t *entry = mm_alloc_pool(NonPagedPool, PAGE_SIZE);
		if (!entry)
			goto err_pre;

		ept->pre_alloc[i] = entry;
	}

	ept->pre_alloc_used = 0;
	return true;

err_pre:
	ept_free_prealloc(ept);
err_pml4_list:
	ept_free_pml4_list(ept);
	return false;
}

void ept_exit(struct ept *ept)
{
	ept_free_prealloc(ept);
	ept_free_pml4_list(ept);
}

/*
 * Get a PTE for the specified guest physical address, this can be used
 * to get the host physical address it redirects to or redirect to it.
 */
uintptr_t *ept_pte(struct ept *ept, uintptr_t *pml, uintptr_t phys)
{
	uintptr_t *pxe = page_addr(&pml[__pxe_idx(phys)]);
	if (!pxe)
		return 0;

	uintptr_t *ppe = page_addr(&pxe[__ppe_idx(phys)]);
	if (!ppe)
		return 0;

	uintptr_t *pde = page_addr(&ppe[__pde_idx(phys)]);
	if (!pde)
		return 0;

	return &pde[__pte_idx(phys)];
}

/*
 * Handle a VM-Exit EPT violation (we're inside VMX root here).
 */
bool ept_handle_violation(struct vcpu *vcpu)
{
	u64 exit = vmcs_read(EXIT_QUALIFICATION);
	u64 gpa = vmcs_read(GUEST_PHYSICAL_ADDRESS);
	u64 gva = vmcs_read(GUEST_LINEAR_ADDRESS);
	u16 eptp = vcpu_eptp_idx(vcpu);
	u8 ar = (exit >> EPT_AR_SHIFT) & EPT_AR_MASK;
	u8 ac = exit & EPT_AR_MASK;

	VCPU_DEBUG("%d: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   eptp, gpa, gva, ar, ar_get_bits(ar), ac, ar_get_bits(ac));

	struct ept *ept = &vcpu->ept;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			if (!ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, gpa))
				return false;
	} else {
#ifdef EPAGE_HOOK
		struct page_hook_info *phi = ksm_find_page((void *)gva);
		if (phi) {
			u16 eptp_switch = phi->ops->select_eptp(phi, eptp, ar, ac);
			if (eptp_switch != eptp) {
				VCPU_DEBUG("Found hooked page, switching from %d to %d\n", eptp, eptp_switch);
				vcpu_switch_root_eptp(vcpu, eptp_switch);
			} else {
				/* Crtical error  */
				VCPU_DEBUG_RAW("Found hooked page but NO switching was required!\n");
			}
		} else {
#endif
			VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
			ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, gpa);
#ifdef EPAGE_HOOK
		}
#endif
	}

	__invept_all();
	return true;
}

/*
 * This is called from the IDT handler (__ept_violation) see x64.asm
 * We're inside Guest here
 */
void __ept_handle_violation(uintptr_t cs, uintptr_t rip)
{
	struct vcpu *vcpu = ksm_current_cpu();
	struct ve_except_info *info = &vcpu->ve;
	struct ept *ept = &vcpu->ept;

	u64 gpa = info->gpa;
	u64 gva = info->gla;
	u64 exit = info->exit;
	u16 eptp = info->eptp;
	u8 ar = (exit >> EPT_AR_SHIFT) & EPT_AR_MASK;
	u8 ac = exit & EPT_AR_MASK;

	VCPU_DEBUG("0x%X:%p [%d]: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   cs, rip, eptp, gpa, gva, ar, ar_get_bits(ar), ac, ar_get_bits(ac));

	info->except_mask = 0;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, gpa);
	} else {
#ifdef EPAGE_HOOK
		struct page_hook_info *phi = ksm_find_page((void *)gva);
		if (phi) {
			u16 eptp_switch = phi->ops->select_eptp(phi, eptp, ar, ac);
			if (eptp_switch != eptp) {
				VCPU_DEBUG("Found hooked page, switching from %d to %d\n", eptp, eptp_switch);
				vcpu_vmfunc(eptp_switch, 0);	/* One does not imply the other  */
			} else {
				/* Typically a critical error...  */
				VCPU_DEBUG_RAW("Found hooked page but NO switching was required!\n");
			}
		} else {
#endif
			VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
			ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, gpa);
#ifdef EPAGE_HOOK
		}
#endif
	}
}

bool ept_check_capabilitiy(void)
{
	u64 vpid = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	return (vpid & EPT_VPID_CAP_REQUIRED) == EPT_VPID_CAP_REQUIRED;
}
