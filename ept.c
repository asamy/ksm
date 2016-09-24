#include "ksm.h"

static uintptr_t *__ept_alloc_entry(void)
{
	uintptr_t *entry = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!entry)
		return NULL;

	RtlZeroMemory(entry, PAGE_SIZE);
	return entry;
}

static uintptr_t *ept_alloc_entry(struct ept *ept)
{
	if (ept) {
		if (ept->pre_alloc_used + 1 > EPT_MAX_PREALLOC)
			VCPU_BUGCHECK(EPT_BUGCHECK_CODE, EPT_BUGCHECK_TOOMANY, 0, 0);

		return ept->pre_alloc[ept->pre_alloc_used++];
	}

	return __ept_alloc_entry();
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

uintptr_t *ept_alloc_page(struct ept *ept, uintptr_t *pml4, uint8_t access, uintptr_t phys)
{
	/* PML4 (512 GB) */
	uintptr_t *pml4e = &pml4[__pxe_idx(phys)];
	uintptr_t *pdpt = page_addr(pml4e);

	if (!*pml4e) {
		pdpt = ept_alloc_entry(ept);
		if (!pdpt)
			return NULL;

		ept_init_entry(pml4e, EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	uintptr_t *pdpte = &pdpt[__ppe_idx(phys)];
	uintptr_t *pdt = page_addr(pdpte);
	if (!*pdpte) {
		pdt = ept_alloc_entry(ept);
		if (!pdt)
			return NULL;

		ept_init_entry(pdpte, EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	uintptr_t *pdte = &pdt[__pde_idx(phys)];
	uintptr_t *pt = page_addr(pdte);
	if (!*pdte) {
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

static void ept_free_prealloc(struct ept *ept)
{
	for (int i = ept->pre_alloc_used; i < EPT_MAX_PREALLOC; ++i) {
		if (!ept->pre_alloc[i])
			break;

		ExFreePool(ept->pre_alloc[i]);
	}
}

static void ept_free_entries(uintptr_t *table, uint32_t lvl)
{
	for (int i = 0; i < 512; ++i) {
		uintptr_t pa = PAGE_PA(table[i]);
		if (pa) {
			uintptr_t *sub_table = __va(pa);
			if (lvl > 2)
				ept_free_entries(sub_table, lvl - 1);
			else
				ExFreePool(sub_table);
		}
	}

	ExFreePool(table);
}

static void ept_free_pml4_list(struct ept *ept)
{
	for (int i = 0; i < EPTP_USED; ++i)
		if (ept->pml4_list[i])
			ept_free_entries(ept->pml4_list[i], 4);
}

static bool setup_pml4(uintptr_t *pml4)
{
	PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	bool ret = false;

	for (int run = 0;; ++run) {
		uintptr_t base_addr = pm_ranges[run].BaseAddress.QuadPart;
		uintptr_t bytes = pm_ranges[run].NumberOfBytes.QuadPart;
		if (!base_addr || !bytes)
			break;

		uintptr_t nr_pages = BYTES_TO_PAGES(bytes);
		for (uintptr_t page = 0; page < nr_pages; ++page) {
			uintptr_t page_addr = base_addr + page * PAGE_SIZE;
			uintptr_t *entry = ept_alloc_page(NULL, pml4, EPT_ACCESS_ALL, page_addr);
			if (!entry)
				goto out;
		}
	}

	/* Allocate APIC page  */
	ret = !!ept_alloc_page(NULL, pml4, EPT_ACCESS_ALL, __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE);

out:
	ExFreePool(pm_ranges);
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

bool ept_setup_p(struct ept *ept, uintptr_t **pml4, uintptr_t *ptr)
{
	uintptr_t *pt_pml = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!pt_pml)
		return false;

	RtlZeroMemory(pt_pml, PAGE_SIZE);
	if (!setup_pml4(pt_pml)) {
		ExFreePool(pt_pml);
		return false;
	}

	*pml4 = pt_pml;
	setup_eptp(ptr, __pa(pt_pml) >> PAGE_SHIFT);
	return true;
}

bool ept_init(struct ept *ept)
{
	/* This can take some time (~5s) and is not very nice...
	 * FIXME: implement some caching.  */
	for (int i = 0; i < EPTP_USED; ++i)
		if (!ept_setup_p(ept, &ept->pml4_list[i], &ept->ptr_list[i]))
			goto err_pml4_list;

	for (int i = 0; i < EPT_MAX_PREALLOC; ++i) {
		uintptr_t *entry = __ept_alloc_entry();
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

uintptr_t *ept_pte(struct ept *ept, uintptr_t *pml, uintptr_t phys)
{
	uintptr_t *pxe = page_addr(&pml[__pxe_idx(phys)]);
	uintptr_t *ppe = page_addr(&pxe[__ppe_idx(phys)]);
	uintptr_t *pde = page_addr(&ppe[__pde_idx(phys)]);
	return &pde[__pte_idx(phys)];
}

void ept_switch_root_p(struct ept *ept, u16 index)
{
	__vmx_vmwrite(EPTP_INDEX, index);
	__vmx_vmwrite(EPT_POINTER, EPTP(ept, index));
}

bool ept_handle_violation(struct vcpu *vcpu)
{
	u64 exit;
	__vmx_vmread(EXIT_QUALIFICATION, &exit);

	u64 fault_pa;
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &fault_pa);

	u64 fault_va;
	__vmx_vmread(GUEST_LINEAR_ADDRESS, &fault_va);

	u64 eptp;
	__vmx_vmread(EPTP_INDEX, &eptp);

	struct ept *ept = &vcpu->ept;
	u8 ar = (exit >> EPT_VE_SHIFT) & EPT_VE_MASK;
	u8 ac = exit & 7;
	VCPU_DEBUG("PA %p VA %p (%d AR %s - %d AC %s)\n",
		   fault_pa, fault_va,
		   ar, ar_get_bits(ar),
		   ac, ar_get_bits(ac));
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			if (!ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, fault_pa))
				return false;
		__invept_all();
		return true;
	}

	struct page_hook_info *h = ksm_find_page((void *)fault_va);
	if (h) {
		u16 eptp_switch = h->ops->select_eptp(h, eptp, ar, ac);
		if (eptp_switch != eptp) {
			VCPU_DEBUG("Found hooked page, switching from %d to %d\n", eptp, eptp_switch);
			ept_switch_root_p(ept, eptp_switch);
			__invept_all();		/* Do we need to invalidate here?  */
		}

		VCPU_DEBUG_RAW("Found hooked page but NO switching was required!\n");
		return true;
	}

	VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
	ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, fault_pa);
	__invept_all();
	return true;
}

void __ept_handle_violation(uintptr_t cs, uintptr_t rip)
{
	struct vcpu *vcpu = ksm_current_cpu();
	struct ve_except_info *info = &vcpu->ve;
	struct ept *ept = &vcpu->ept;

	u16 eptp = info->eptp;
	u64 fault_pa = info->gpa;
	u64 fault_va = info->gla;
	u64 exit = info->exit;
	u8 ar = (exit >> EPT_VE_SHIFT) & EPT_VE_MASK;
	u8 ac = exit & 7;

	VCPU_DEBUG("0x%X:%p [%d]: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   cs, rip, eptp, fault_pa, fault_va,
		   ar, ar_get_bits(ar), ac, ar_get_bits(ac));

	info->except_mask = 0;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, fault_pa);
		return;
	}

	struct page_hook_info *h = ksm_find_page((void *)fault_va);
	if (h) {
		u16 eptp_switch = h->ops->select_eptp(h, eptp, ar, ac);
		if (eptp_switch != eptp) {
			VCPU_DEBUG("Found hooked page, switching from %d to %d\n", eptp, eptp_switch);
			__vmx_vmfunc(0, eptp_switch);
			return;
		}

		VCPU_DEBUG_RAW("Found hooked page but NO switching was required!\n");
	} else {
		VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
		ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, fault_pa);
	}
}

bool ept_check_capabilitiy(void)
{
	u64 vpid = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	return (vpid & EPT_VPID_CAP_REQUIRED) == EPT_VPID_CAP_REQUIRED;
}
