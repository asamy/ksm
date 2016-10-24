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
	for (u32 i = ept->pre_alloc_used; i < EPT_MAX_PREALLOC; ++i) {
		if (!ept->pre_alloc[i])
			break;

		mm_free_pool(ept->pre_alloc[i], PAGE_SIZE);
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

bool ept_handle_violation(struct vcpu *vcpu)
{
	u64 exit = vmcs_read(EXIT_QUALIFICATION);
	u64 gpa = vmcs_read(GUEST_PHYSICAL_ADDRESS);
	u64 gva = vmcs_read(GUEST_LINEAR_ADDRESS);
	u16 eptp = vcpu_eptp_idx(vcpu);
	u8 ar = (exit >> EPT_AR_SHIFT) & EPT_AR_MASK;
	u8 ac = exit & EPT_AR_MASK;

	if (!(exit & EPT_VE_VALID_GLA))
		gva = 0;

	VCPU_DEBUG("%d: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   eptp, gpa, gva, ar, ar_get_bits(ar), ac, ar_get_bits(ac));

	struct ept *ept = &vcpu->ept;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			if (!ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, gpa))
				return false;

		VCPU_DEBUG("Used %d/%d\n", ept->pre_alloc_used, EPT_MAX_PREALLOC);
	} else {
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
			VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
			ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, gpa);
		}
	}

	__invept_all();
	return true;
}

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

	if (!(exit & EPT_VE_VALID_GLA))
		gva = 0;

	VCPU_DEBUG("0x%X:%p [%d]: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   cs, rip, eptp, gpa, gva, ar, ar_get_bits(ar), ac, ar_get_bits(ac));

	info->except_mask = 0;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, gpa);

		VCPU_DEBUG("Used %d/%d\n", ept->pre_alloc_used, EPT_MAX_PREALLOC);
	} else {
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
			VCPU_DEBUG_RAW("Something smells totally off; fixing manually.\n");
			ept_alloc_page(ept, EPT4(ept, eptp), ac | ar, gpa);
		}
	}
}

bool ept_check_capabilitiy(void)
{
	u64 vpid = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	return (vpid & EPT_VPID_CAP_REQUIRED) == EPT_VPID_CAP_REQUIRED;
}
