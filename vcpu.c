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
#ifdef __linux__
#include <linux/kernel.h>
#else
#include <ntddk.h>
#endif

#include "ksm.h"

static inline void init_epte(u64 *entry, int access, u64 hpa)
{
	*entry ^= *entry;
	*entry |= access & EPT_ACCESS_MAX_BITS;
	*entry |= (hpa >> PAGE_SHIFT) << PAGE_SHIFT;
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
 *	3) Each PDT entry is 4 KB, so that makes the whole PDT table 2 MB
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
u64 *ept_alloc_page(u64 *pml4, int access, u64 gpa, u64 hpa)
{
	/* PML4 (512 GB) */
	u64 *pml4e = &pml4[__pxe_idx(gpa)];
	u64 *pdpt = page_addr(pml4e);

	if (!pdpt) {
		pdpt = mm_alloc_page();
		if (!pdpt)
			return NULL;

		init_epte(pml4e, EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	u64 *pdpte = &pdpt[__ppe_idx(gpa)];
	u64 *pdt = page_addr(pdpte);
	if (!pdt) {
		pdt = mm_alloc_page();
		if (!pdt)
			return NULL;

		init_epte(pdpte, EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	u64 *pdte = &pdt[__pde_idx(gpa)];
	u64 *pt = page_addr(pdte);
	if (!pt) {
		pt = mm_alloc_page();
		if (!pt)
			return NULL;

		init_epte(pdte, EPT_ACCESS_ALL, __pa(pt));
	}

	/* PT (4 KB)  */
	u64 *page = &pt[__pte_idx(gpa)];
	init_epte(page, access, hpa);

	*page |= EPT_MT_WRITEBACK << VMX_EPT_MT_EPTE_SHIFT;
#ifdef EPT_SUPPRESS_VE
	*page |= EPT_SUPPRESS_VE_BIT;
#endif
	return page;
}

/*
 * Recursively free each table entries, see ept_alloc_page()
 * for an explanation.
 */
static void free_entries(u64 *table, int lvl)
{
	for (int i = 0; i < 512; ++i) {
		u64 entry = table[i];
		if (entry) {
			u64 *sub_table = __va(PAGE_PA(entry));
			if (lvl > 2)
				free_entries(sub_table, lvl - 1);
			else
				mm_free_page(sub_table);
		}
	}

	mm_free_page(table);
}

static void free_pml4_list(struct ept *ept)
{
	for (int i = 0; i < EPTP_USED; ++i)
		if (EPT4(ept, i))
			free_entries(EPT4(ept, i), 4);
}

static bool setup_pml4(struct ept *ept)
{
	bool ret = false;

#ifndef __linux__
	PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges)
		return false;

	for (int run = 0;; ++run) {
		uintptr_t base_addr = pm_ranges[run].BaseAddress.QuadPart;
		uintptr_t bytes = pm_ranges[run].NumberOfBytes.QuadPart;
		if (!base_addr || !bytes)
			break;

		uintptr_t nr_pages = BYTES_TO_PAGES(bytes);
		for (uintptr_t page = 0; page < nr_pages; ++page) {
			uintptr_t page_addr = base_addr + page * PAGE_SIZE;
			for_each_eptp(i)
				if (!ept_alloc_page(EPT4(ept, i), EPT_ACCESS_ALL, page_addr, page_addr))
					goto out;
		}
	}
#endif

	/* Allocate APIC page  */
	u64 apic = __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE;
	for_each_eptp(i)
		if (!(ret = ept_alloc_page(EPT4(ept, i), EPT_ACCESS_ALL, apic, apic)))
			break;

#ifndef __linux__
out:
	ExFreePool(pm_ranges);
#endif
	return ret;
}

static inline void setup_eptp(u64 *ptr, u64 pml4)
{
	*ptr ^= *ptr;
	*ptr |= VMX_EPT_DEFAULT_MT;
	*ptr |= VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
#ifdef ENABLE_PML
	*ptr |= VMX_EPT_AD_ENABLE_BIT;
#endif
	*ptr |= (pml4 >> PAGE_SHIFT) << PAGE_SHIFT;
}

static inline bool init_ept(struct ept *ept)
{
	for_each_eptp(i) {
		u64 **pml4 = &EPT4(ept, i);
		if (!(*pml4 = mm_alloc_page()))
			goto err_pml4_list;

		setup_eptp(&EPTP(ept, i), __pa(*pml4));
	}

	if (setup_pml4(ept))
		return true;

err_pml4_list:
	free_pml4_list(ept);
	return false;
}

static inline void free_ept(struct ept *ept)
{
	free_pml4_list(ept);
}

/*
 * Get a PTE for the specified guest physical address, this can be used
 * to get the host physical address it redirects to or redirect to it.
 */
u64 *ept_pte(u64 *pml4, u64 gpa)
{
	u64 *pdpt, *pdt, *pd;
	u64 *pdpte, *pdte;

	pdpt = page_addr(&pml4[__pxe_idx(gpa)]);
	if (!pdpt)
		return 0;

	pdpte = &pdpt[__ppe_idx(gpa)];
	pdt = page_addr(pdpte);
	if (!pdt)
		return 0;

	if (*pdpte & PAGE_LARGE)
		return pdpte;	/* 1 GB  */

	pdte = &pdt[__pde_idx(gpa)];
	pd = page_addr(pdte);
	if (!pd)
		return 0;

	if (*pdte & PAGE_LARGE)
		return pdte;	/* 2 MB  */

	return &pd[__pte_idx(gpa)];	/* 4 KB  */
}

static u16 do_ept_violation(struct vcpu *vcpu, u64 rip, u64 gpa, u64 gva, u16 eptp, u8 ar, u8 ac)
{
	struct ept *ept = &vcpu->ept;
	if (ar == EPT_ACCESS_NONE) {
		for_each_eptp(i)
			if (!ept_alloc_page(EPT4(ept, i), EPT_ACCESS_ALL, gpa, gpa))
				return EPT_MAX_EPTP_LIST;
	} else {
#ifdef EPAGE_HOOK
		struct page_hook_info *phi = ksm_find_page((void *)gva);
		if (phi) {
			u16 eptp_switch = phi->ops->select_eptp(phi, eptp, ar, ac);
			VCPU_DEBUG("Found hooked page, switching from %d to %d\n", eptp, eptp_switch);
			return eptp_switch;
		} else {
			return kprotect_select_eptp(ept, rip, ac);
		}
#else
		return EPT_MAX_EPTP_LIST;
#endif
	}

	return eptp;
}

/*
 * Handle a VM-Exit EPT violation (we're inside VMX root here).
 */
bool ept_handle_violation(struct vcpu *vcpu)
{
	u64 exit = vmcs_read(EXIT_QUALIFICATION);
	u64 gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	u64 gva = vmcs_read(GUEST_LINEAR_ADDRESS);
	u16 eptp = vcpu_eptp_idx(vcpu);
	u8 ar = (exit >> EPT_AR_SHIFT) & EPT_AR_MASK;
	u8 ac = exit & EPT_AR_MASK;
	char sar[3], sac[3];
	ar_get_bits(ar, sar);
	ar_get_bits(ac, sac);

	VCPU_DEBUG("%d: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   eptp, gpa, gva, ar, sar, ac, sac);
	u16 eptp_switch = do_ept_violation(vcpu, vcpu->ip, gpa, gva, eptp, ar, ac);
	if (eptp_switch == EPT_MAX_EPTP_LIST)
		return false;

	if (eptp_switch != eptp)
		vcpu_switch_root_eptp(vcpu, eptp_switch);

	return true;
}

/*
 * This is called from the IDT handler (__ept_violation) see x64.{S,asm}
 * We're inside Guest here
 */
void __ept_handle_violation(uintptr_t cs, uintptr_t rip)
{
	struct vcpu *vcpu = ksm_current_cpu();
	struct ve_except_info *info = &vcpu->ve;

	u64 gpa = info->gpa;
	u64 gva = info->gla;
	u64 exit = info->exit;
	u16 eptp = info->eptp;
	u8 ar = (exit >> EPT_AR_SHIFT) & EPT_AR_MASK;
	u8 ac = exit & EPT_AR_MASK;
	char sar[3], sac[3];
	ar_get_bits(ar, sar);
	ar_get_bits(ac, sac);

	VCPU_DEBUG("0x%X:%p [%d]: PA %p VA %p (%d AR %s - %d AC %s)\n",
		   cs, rip, eptp, gpa, gva, ar, sar, ac, sac);
	info->except_mask = 0;

	u16 eptp_switch = do_ept_violation(vcpu, rip, gpa, gva, eptp, ar, ac);
	if (eptp_switch == EPT_MAX_EPTP_LIST)
		VCPU_BUGCHECK(EPT_BUGCHECK_CODE, EPT_UNHANDLED_VIOLATION, rip, gpa);

	if (eptp_switch != eptp)
		vcpu_vmfunc(eptp, 0);
}

#ifndef _MSC_VER
unsigned long __segmentlimit(unsigned long selector)
{
	unsigned long limit;
	__asm __volatile("lsl %1, %0" : "=r" (limit) : "r" (selector));
	return limit;
}
#endif

static inline u32 __accessright(u16 selector)
{
	if (selector)
		return (__lar(selector) >> 8) & 0xF0FF;

	/* unusable  */
	return 0x10000;
}

static inline void adjust_ctl_val(u32 msr, u32 *val)
{
	u64 v = __readmsr(msr);
	*val &= (u32)(v >> 32);			/* bit == 0 in high word ==> must be zero  */
	*val |= (u32)v;				/* bit == 1 in low word  ==> must be one  */
}

static u8 setup_vmcs(struct vcpu *vcpu, uintptr_t gsp, uintptr_t gip)
{
	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	u16 es = __reades();
	u16 cs = __readcs();
	u16 ss = __readss();
	u16 ds = __readds();
	u16 fs = __readfs();
	u16 gs = __readgs();
	u16 ldt = __sldt();
	u16 tr = __str();
	u8 err = 0;

	struct gdtr gdtr;
	__sgdt(&gdtr);

	struct gdtr idtr;
	__sidt(&idtr);

	struct ept *ept = &vcpu->ept;
	vcpu->g_idt.base = idtr.base;
	vcpu->g_idt.limit = idtr.limit;

	struct kidt_entry64 *current_idt = (struct kidt_entry64 *)idtr.base;
	struct kidt_entry64 *shadow = (struct kidt_entry64 *)vcpu->idt.base;
	unsigned count = idtr.limit / sizeof(*shadow);
	for (unsigned n = 0; n < count; ++n)
		memcpy(&shadow[n], &current_idt[n], sizeof(*shadow));

	struct vmcs *vmxon = &vcpu->vmxon;
	vmxon->revision_id = (u32)vmx;

	/*
	 * Actually enter VMX root mode.
	 *
	 * If we're running nested on a hypervisor that does not
	 * support VT-x, this will cause #GP.
	 */
	uintptr_t cr0 = __readcr0();
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0);

	uintptr_t cr4 = __readcr4();
	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4);

	/* Enter VMX root operation  */
	u64 pa = __pa(vmxon);
	if (__vmx_on(&pa))
		return 3;

	/*
	 * Initialize VMCS (VM control structure) that we're going to use
	 * to store stuff in it, see setup_vmcs().
	 */
	struct vmcs *vmcs = &vcpu->vmcs;
	vmcs->revision_id = (u32)vmx;

	pa = __pa(vmcs);
	err = __vmx_vmclear(&pa);
	if (err)
		return err;

	err = __vmx_vmptrld(&pa);
	if (err)
		return err;

	u32 apicv = 0;
#if 0
	if (lapic_in_kernel()) {
		apicv |= SECONDARY_EXEC_APIC_REGISTER_VIRT | SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		if (cpu_has_x2apic() && x2apic_enabled()) {
			apicv |= SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
			apicv &= ~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		}
	}
#endif

	u32 msr_off = 0;
	if (__readmsr(MSR_IA32_VMX_BASIC) & VMX_BASIC_TRUE_CTLS)
		msr_off = 0xC;

	u32 vm_entry = VM_ENTRY_IA32E_MODE
#ifndef DBG
		| VM_ENTRY_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_ENTRY_CTLS + msr_off, &vm_entry);
	vcpu->entry_ctl = vm_entry;

	u32 vm_exit = VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE
#ifndef DBG
		| VM_EXIT_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_EXIT_CTLS + msr_off, &vm_exit);
	vcpu->exit_ctl = vm_exit;

	u32 vm_pinctl = 0;// PIN_BASED_POSTED_INTR;
	adjust_ctl_val(MSR_IA32_VMX_PINBASED_CTLS + msr_off, &vm_pinctl);
	vcpu->pin_ctl = vm_pinctl;

	u32 vm_2ndctl = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID |
		SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_UNRESTRICTED_GUEST
#ifndef EMULATE_VMFUNC
		| SECONDARY_EXEC_ENABLE_VMFUNC
#endif
		| SECONDARY_EXEC_ENABLE_VE
		| /* apic virtualization  */ apicv
#if !defined(__linux__) && _WIN32_WINNT == 0x0A00	/* w10 required features  */
		| SECONDARY_EXEC_RDTSCP
#endif
#ifdef ENABLE_PML
		| SECONDARY_EXEC_ENABLE_PML
#endif
#ifndef DBG
		| SECONDARY_EXEC_CONCEAL_VMX_IPT
#endif
		;
	/* NB: Desc table exiting makes windbg go maniac mode.  */
#ifndef __linux__
	if (!KD_DEBUGGER_ENABLED || KD_DEBUGGER_NOT_PRESENT)
#endif
		vm_2ndctl |= SECONDARY_EXEC_DESC_TABLE_EXITING;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS2, &vm_2ndctl);

	u32 vm_cpuctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_USE_IO_BITMAPS;
	if (vm_2ndctl & apicv)
		vm_cpuctl |= CPU_BASED_TPR_SHADOW;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS + msr_off, &vm_cpuctl);
	vcpu->cpu_ctl = vm_cpuctl;

	/* Processor control fields  */
	err |= vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl);
	err |= vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
	err |= vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vm_2ndctl);
	err |= vmcs_write32(VM_ENTRY_CONTROLS, vm_entry);
	err |= vmcs_write32(VM_EXIT_CONTROLS, vm_exit);
	err |= vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	err |= vmcs_write64(VM_EXIT_MSR_STORE_ADDR, 0);
	err |= vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	err |= vmcs_write32(VM_EXIT_MSR_LOAD_ADDR, 0);
	err |= vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	err |= vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);

	/* Control Fields */
	err |= vmcs_write16(VIRTUAL_PROCESSOR_ID, vpid_nr());
	err |= vmcs_write32(EXCEPTION_BITMAP, __EXCEPTION_BITMAP);
	err |= vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	err |= vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	err |= vmcs_write32(CR3_TARGET_COUNT, 0);
	err |= vmcs_write64(IO_BITMAP_A, __pa(ksm.io_bitmap_a));
	err |= vmcs_write64(IO_BITMAP_B, __pa(ksm.io_bitmap_b));
	err |= vmcs_write64(MSR_BITMAP, __pa(ksm.msr_bitmap));
	err |= vmcs_write64(EPT_POINTER, EPTP(ept, EPTP_DEFAULT));
	err |= vmcs_write64(VMCS_LINK_POINTER, -1ULL);

	/* Posted interrupts if available.  */
	if (vm_pinctl & PIN_BASED_POSTED_INTR) {
		err |= vmcs_write16(POSTED_INTR_NV, 0);
		err |= vmcs_write64(POSTED_INTR_DESC_ADDR, __pa(&vcpu->pi_desc));
	}

	/* Full APIC virtualization if any available.  */
	if (vm_2ndctl & apicv) {
		if (vm_2ndctl & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
			err |= vmcs_write64(EOI_EXIT_BITMAP0, 0);
			err |= vmcs_write64(EOI_EXIT_BITMAP1, 0);
			err |= vmcs_write64(EOI_EXIT_BITMAP2, 0);
			err |= vmcs_write64(EOI_EXIT_BITMAP3, 0);
			err |= vmcs_write16(GUEST_INTR_STATUS, 0);
		}

		if (vm_cpuctl & CPU_BASED_TPR_SHADOW) {
			err |= vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, __pa(vcpu->vapic_page));
			err |= vmcs_write16(TPR_THRESHOLD, 0);

			if (vm_2ndctl & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
				err |= vmcs_write64(APIC_ACCESS_ADDR,
						    __readmsr(MSR_IA32_APICBASE_BASE) & MSR_IA32_APICBASE_BASE);
		}
	}

	/* CR0/CR4 controls  */
	err |= vmcs_write(CR0_GUEST_HOST_MASK, vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_GUEST_HOST_MASK, vcpu->cr4_guest_host_mask);
	err |= vmcs_write(CR0_READ_SHADOW, cr0 & ~vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_READ_SHADOW, cr4 & ~vcpu->cr4_guest_host_mask);

	/* Cache secondary ctl for emulation purposes  */
	vcpu->secondary_ctl = vm_2ndctl;
	vcpu->vm_func_ctl = 0;

	/* See if we need to emulate VMFUNC via a VMCALL  */
	if (vm_2ndctl & SECONDARY_EXEC_ENABLE_VMFUNC) {
		err |= vmcs_write(VM_FUNCTION_CTRL, VM_FUNCTION_CTL_EPTP_SWITCHING);
		err |= vmcs_write64(EPTP_LIST_ADDRESS, __pa(&ept->ptr_list));
	} else {
		/* Enable emulation for VMFUNC  */
		vcpu->vm_func_ctl |= VM_FUNCTION_CTL_EPTP_SWITCHING;
	}

	/*
	 * We shouldn't emulate VE unless we're nesting someone,
	 * it'll add pointless overhead.
	 */
	if (vm_2ndctl & SECONDARY_EXEC_ENABLE_VE) {
		err |= vmcs_write16(EPTP_INDEX, EPTP_DEFAULT);
		err |= vmcs_write64(VE_INFO_ADDRESS, __pa(&vcpu->ve));
		vcpu_put_idt(vcpu, cs, X86_TRAP_VE, __ept_violation);
	} else {
		/* Emulate EPTP Index  */
		struct ve_except_info *ve = &vcpu->ve;
		ve->eptp = EPTP_DEFAULT;
	}

	if (vm_2ndctl & SECONDARY_EXEC_XSAVES)
		err |= vmcs_write64(XSS_EXIT_BITMAP, 0);

#ifdef ENABLE_PML
	/* PML if supported  */
	if (vm_2ndctl & SECONDARY_EXEC_ENABLE_PML) {
		err |= vmcs_write64(PML_ADDRESS, __pa(&vcpu->pml));
		err |= vmcs_write16(GUEST_PML_INDEX, PML_MAX_ENTRIES - 1);
	}
#endif

	/* Guest  */
	err |= vmcs_write16(GUEST_ES_SELECTOR, es);
	err |= vmcs_write16(GUEST_CS_SELECTOR, cs);
	err |= vmcs_write16(GUEST_SS_SELECTOR, ss);
	err |= vmcs_write16(GUEST_DS_SELECTOR, ds);
	err |= vmcs_write16(GUEST_FS_SELECTOR, fs);
	err |= vmcs_write16(GUEST_GS_SELECTOR, gs);
	err |= vmcs_write16(GUEST_LDTR_SELECTOR, ldt);
	err |= vmcs_write16(GUEST_TR_SELECTOR, tr);
	err |= vmcs_write32(GUEST_ES_LIMIT, __segmentlimit(es));
	err |= vmcs_write32(GUEST_CS_LIMIT, __segmentlimit(cs));
	err |= vmcs_write32(GUEST_SS_LIMIT, __segmentlimit(ss));
	err |= vmcs_write32(GUEST_DS_LIMIT, __segmentlimit(ds));
	err |= vmcs_write32(GUEST_FS_LIMIT, __segmentlimit(fs));
	err |= vmcs_write32(GUEST_GS_LIMIT, __segmentlimit(gs));
	err |= vmcs_write32(GUEST_LDTR_LIMIT, __segmentlimit(ldt));
	err |= vmcs_write32(GUEST_TR_LIMIT, __segmentlimit(tr));
	err |= vmcs_write32(GUEST_GDTR_LIMIT, gdtr.limit);
	err |= vmcs_write32(GUEST_IDTR_LIMIT, idtr.limit);
	err |= vmcs_write32(GUEST_ES_AR_BYTES, __accessright(es));
	err |= vmcs_write32(GUEST_CS_AR_BYTES, __accessright(cs));
	err |= vmcs_write32(GUEST_SS_AR_BYTES, __accessright(ss));
	err |= vmcs_write32(GUEST_DS_AR_BYTES, __accessright(ds));
	err |= vmcs_write32(GUEST_FS_AR_BYTES, __accessright(fs));
	err |= vmcs_write32(GUEST_GS_AR_BYTES, __accessright(gs));
	err |= vmcs_write32(GUEST_LDTR_AR_BYTES, __accessright(ldt));
	err |= vmcs_write32(GUEST_TR_AR_BYTES, __accessright(tr));
	err |= vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	err |= vmcs_write32(GUEST_ACTIVITY_STATE, 0);
	err |= vmcs_write64(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTLMSR));
	err |= vmcs_write32(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= vmcs_write(GUEST_CR0, cr0);
	err |= vmcs_write(GUEST_CR3, ksm.origin_cr3);
	err |= vmcs_write(GUEST_CR4, cr4);
	err |= vmcs_write(GUEST_ES_BASE, 0);
	err |= vmcs_write(GUEST_CS_BASE, 0);
	err |= vmcs_write(GUEST_SS_BASE, 0);
	err |= vmcs_write(GUEST_DS_BASE, 0);
	err |= vmcs_write(GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= vmcs_write(GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= vmcs_write(GUEST_LDTR_BASE, __segmentbase(gdtr.base, ldt));
	err |= vmcs_write(GUEST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= vmcs_write(GUEST_GDTR_BASE, gdtr.base);
	err |= vmcs_write(GUEST_IDTR_BASE, vcpu->idt.base);
	err |= vmcs_write(GUEST_DR7, __readdr(7));
	err |= vmcs_write(GUEST_RSP, gsp);
	err |= vmcs_write(GUEST_RIP, gip);
	err |= vmcs_write(GUEST_RFLAGS, __readeflags());
	err |= vmcs_write(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= vmcs_write(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	/* Host  */
	err |= vmcs_write16(HOST_ES_SELECTOR, es & 0xf8);
	err |= vmcs_write16(HOST_CS_SELECTOR, cs & 0xf8);
	err |= vmcs_write16(HOST_SS_SELECTOR, ss & 0xf8);
	err |= vmcs_write16(HOST_DS_SELECTOR, ds & 0xf8);
	err |= vmcs_write16(HOST_FS_SELECTOR, fs & 0xf8);
	err |= vmcs_write16(HOST_GS_SELECTOR, gs & 0xf8);
	err |= vmcs_write16(HOST_TR_SELECTOR, tr & 0xf8);
	err |= vmcs_write(HOST_CR0, cr0);
	err |= vmcs_write(HOST_CR3, ksm.kernel_cr3);
	err |= vmcs_write(HOST_CR4, cr4);
	err |= vmcs_write(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= vmcs_write(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= vmcs_write(HOST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= vmcs_write(HOST_GDTR_BASE, gdtr.base);
	err |= vmcs_write(HOST_IDTR_BASE, idtr.base);
	err |= vmcs_write(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= vmcs_write(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= vmcs_write(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	err |= vmcs_write(HOST_RSP, (uintptr_t)vcpu->stack + KERNEL_STACK_SIZE);
	err |= vmcs_write(HOST_RIP, (uintptr_t)__vmx_entrypoint);

	if (err == 0) {
		/*
		 * This is necessary here or just before we exit the VM,
		 * we do it here as it's easier.
		 */
		__invept_all();
		__invvpid_all();
	}

	return err;
}

void vcpu_init(struct vcpu *vcpu, uintptr_t sp, uintptr_t ip)
{
	/*
	 * Note: that we return to __ksm_init_cpu anyway regardless of failure or
	 * success, but the difference is, if we fail, __vmx_vmlaunch() will give
	 * us back control instead of directly returning to __ksm_init_cpu.
	 *
	 * What we do here (in order):
	 *	- Setup EPT
	 *	- Allocate the shadow IDT (later initialized)
	 *	- Setup VMCS (shadow IDT initialized here)
	 *	- Launch VM
	 */
	u32 vm_err;
	u8 err;
	if (!init_ept(&vcpu->ept))
		return;

	vcpu->idt.limit = PAGE_SIZE - 1;
	vcpu->idt.base = (uintptr_t)mm_alloc_page();
	if (!vcpu->idt.base)
		return free_ept(&vcpu->ept);

#ifdef NESTED_VMX
	vcpu->nested_vcpu.feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL) & ~FEATURE_CONTROL_LOCKED;
#endif

	/*
	 * Leave cr0 guest host mask empty, we support all.
	 * Set VMXE bit in cr4 guest host mask so they VM-exit to us when
	 * they try to set that bit.
	 */
	vcpu->cr0_guest_host_mask = 0;
	vcpu->cr4_guest_host_mask = X86_CR4_VMXE;

	err = setup_vmcs(vcpu, sp, ip);
	if (err) {
		if (err != 3) {
			vm_err = vmcs_read32(VM_INSTRUCTION_ERROR);
			__vmx_off();
			VCPU_DEBUG("setup_vmcs(): failed %d\n", vm_err);
		}

		VCPU_DEBUG("setup_vmcs(): failed with error %d\n", err);
	} else {
		err = __vmx_vmlaunch();
		if (err) {
			vm_err = vmcs_read32(VM_INSTRUCTION_ERROR);
			__vmx_off();
			VCPU_DEBUG("__vmx_vmlaunch(): failed %d\n", vm_err);
		}
	}

	/*
	 * setup_vmcs()/__vmx_vmlaunch() failed if we got here, we had already overwritten the
	 * IDT entry for #VE (X86_TRAP_VE), restore it now otherwise PatchGuard is gonna
	 * notice and BSOD us.
	 */
	__lidt(&vcpu->g_idt);
	vcpu_free(vcpu);
}

void vcpu_free(struct vcpu *vcpu)
{
	if (vcpu->idt.base)
		mm_free_page((void *)vcpu->idt.base);

	free_ept(&vcpu->ept);
	__stosq((unsigned long long *)vcpu, 0x00, sizeof(*vcpu) >> 3);
}

void vcpu_set_mtf(bool enable)
{
	/* BAD BAD BAD!  Do not use.  */
	u64 vm_cpuctl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	if (enable)
		vm_cpuctl |= CPU_BASED_MONITOR_TRAP_FLAG;
	else
		vm_cpuctl &= ~CPU_BASED_MONITOR_TRAP_FLAG;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
}

void vcpu_switch_root_eptp(struct vcpu *vcpu, u16 index)
{
	if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE) {
		/* Native  */
		vmcs_write16(EPTP_INDEX, index);
	} else {
		/* Emulated  */
		struct ve_except_info *ve = &vcpu->ve;
		ve->eptp = index;
	}

	/* Update EPT pointer  */
	vmcs_write64(EPT_POINTER, EPTP(&vcpu->ept, index));
	/* We have to invalidate, we just switched to a new paging hierarchy  */
	__invept_all();
}

bool ept_check_capabilitiy(void)
{
	u64 vpid = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	return (vpid & EPT_VPID_CAP_REQUIRED) == EPT_VPID_CAP_REQUIRED;
}
