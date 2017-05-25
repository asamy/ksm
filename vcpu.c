/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
*/
#ifdef __linux__
#include <linux/kernel.h>
#else
#include <ntddk.h>
#include <intrin.h>
#endif

#include "ksm.h"

static inline u64 mkepte(int access, u64 hpa)
{
	return (access & EPT_AR_MASK) | (hpa & PAGE_PA_MASK);
}

static inline u64 *ept_page_addr(u64 *pte)
{
	if (!pte || !(*pte & EPT_ACCESS_RWX))
		return 0;

	return __va(PAGE_PA(*pte));
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
 * Note: Each table contains 512 entries, which makes each table occupy 4096
 * bytes (8 * 512 or PAGE_SIZE), which is a page.
 *
 * Assuming:
 *	1) Each PML4 entry is 1 GB, so that makes the whole PML4 table 512 GB
 *	2) Each PDPT entry is 2 MB, so that makes the whole PDPT table 1 GB
 *	3) Each PDT entry is 4 KB, so that makes the whole PDT table 2 MB
 *
 * So, with that being said, while we only have the initial table (PML4) virtual address
 * to work with, we need first need to get an offset into it (for the PDPT), and so on, so
 * we use the following macros (defined in mm.h):
 *	- PGD_INDEX_P(pa)		- Gives an offset into PML4 to get the PDPT
 *	- PUD_INDEX_P(pa)		- Gives an offset into PDPT to get the PDT
 *	- PMD_INDEX_P(pa)		- Gives an offset into PDT to get the PT 
 *	- PTE_INDEX_P(pa)		- Gives an offset into PT to get the final page!
 *
 * And since each of those entries contain a physical address, we need to use
 * ept_page_addr() to obtain the virtual address for that specific table.
 *
 * We currently just do a 1:1 mapping by default, but some APIs redirect to
 * "a shadow" physical page, and those are in the following files:
 *	- introspect.c
 *	- epage.c
 *	- sandbox.c
 */
u64 *ept_alloc_page(u64 *pml4, int access, u64 gpa, u64 hpa)
{
	/* PML4 (512 GB) */
	u64 *pml4e = &pml4[PGD_INDEX_P(gpa)];
	u64 *pdpt = ept_page_addr(pml4e);

	if (!pdpt) {
		pdpt = mm_alloc_page();
		if (!pdpt)
			return NULL;

		*pml4e = mkepte(EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	u64 *pdpte = &pdpt[PUD_INDEX_P(gpa)];
	u64 *pdt = ept_page_addr(pdpte);
	if (!pdt) {
		pdt = mm_alloc_page();
		if (!pdt)
			return NULL;

		*pdpte = mkepte(EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	u64 *pdte = &pdt[PMD_INDEX_P(gpa)];
	u64 *pt = ept_page_addr(pdte);
	if (!pt) {
		pt = mm_alloc_page();
		if (!pt)
			return NULL;

		*pdte = mkepte(EPT_ACCESS_ALL, __pa(pt));
	}

	/* PT (4 KB)  */
	u64 *page = &pt[PTE_INDEX_P(gpa)];
	*page = mkepte(access, hpa);
	*page |= EPT_MT_WRITEBACK << VMX_EPT_MT_EPTE_SHIFT;
	return page;
}

/*
 * Get a PTE for the specified guest physical address, this can be used
 * to get the host physical address it redirects to or redirect to it.
 *
 * To redirect to an HPA (Host physical address):
 * \code
 *	struct ept *ept = &vcpu->ept;
 *	u64 *epte = ept_pte(EPT4(ept, EPTP_EXHOOK), gpa);
 *	__set_epte_pfn(epte, hpa >> PAGE_SHIFT);
 *	__invept_all();
 * \endcode
 *
 * Similarly, to get the HPA:
 * \code
 *	struct ept *ept = &vcpu->ept;
 *	u64 *epte = ept_pte(EPT4(ept, EPTP_EXHOOK), gpa);
 *	u64 hpa = *epte & PAGE_PA_MASK;
 *	u64 hfn = hpa >> PAGE_SHIFT;
 * \endcode
 */
u64 *ept_pte(u64 *pml4, u64 gpa)
{
	u64 *pdpt, *pdt, *pt;
	u64 *pdpte, *pdte;

	pdpt = ept_page_addr(&pml4[PGD_INDEX_P(gpa)]);
	if (!pdpt)
		return 0;

	pdpte = &pdpt[PUD_INDEX_P(gpa)];
	pdt = ept_page_addr(pdpte);
	if (!pdt)
		return 0;

	if (*pdpte & PAGE_LARGE)
		return pdpte;	/* 1 GB  */

	pdte = &pdt[PMD_INDEX_P(gpa)];
	pt = ept_page_addr(pdte);
	if (!pt)
		return 0;

	if (*pdte & PAGE_LARGE)
		return pdte;	/* 2 MB  */

	return &pt[PTE_INDEX_P(gpa)];	/* 4 KB  */
}

static bool setup_pml4(struct ept *ept, int access, u16 eptp)
{
	/*
	 * On Linux, this doesn't have to be done, and we can get each
	 * one as a violation, on Windows, the kernel screams and hangs.
	 *
	 * See mm_cache_ram_ranges() in mm.c for how this is optained.
	 */
	int i;
	u64 addr;
	u64 apic;
	struct pmem_range *range;

	for (i = 0; i < ksm->range_count; ++i) {
		range = &ksm->ranges[i];
		for (addr = range->start; addr < range->end; addr += PAGE_SIZE) {
			int r = access;
			if (access != EPT_ACCESS_ALL && mm_is_kernel_addr(__va(addr)))
				r = EPT_ACCESS_ALL;

			if (!ept_alloc_page(EPT4(ept, eptp), r, addr, addr))
				return false;
		}
	}

	/* Allocate APIC page  */
	apic = __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE;
	if (!ept_alloc_page(EPT4(ept, eptp), EPT_ACCESS_ALL, apic, apic))
		return false;

	return true;
}

static inline u64 mkeptp(u64 pml4)
{
	/*
	 * You can think of the EPT pointer like CR3, but it does not have to
	 * be changed during a task switch, however, EPT manages physical-addr
	 * to physical-addr translation, unlike CR3, which manages virtual-addr
	 * to physical-addr translation.
	 *
	 * The pml4 parameter is the physical address of the PML4 table which
	 * we allocate down below in ept_create_ptr().
	 */
	return VMX_EPT_DEFAULT_MT | VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT |
		(pml4 & PAGE_PA_MASK)
#ifdef ENABLE_PML
		| VMX_EPT_AD_ENABLE_BIT
#endif
		;
}

bool ept_create_ptr(struct ept *ept, int access, u16 *out)
{
	u64 **pml4;
	u16 eptp;

	eptp = (u16)find_first_zero_bit(ept->ptr_bitmap, sizeof(ept->ptr_bitmap));
	if (eptp == sizeof(ept->ptr_bitmap))
		return false;

	pml4 = &EPT4(ept, eptp);
	if (!(*pml4 = mm_alloc_page()))
		return false;

	if (!setup_pml4(ept, access, eptp)) {
		__mm_free_page(*pml4);
		return false;
	}

	EPTP(ept, eptp) = mkeptp(__pa(*pml4));
	set_bit(eptp, ept->ptr_bitmap);
	*out = eptp;
	return true;
}

/*
 * Recursively free each table entries, see comments above
 * ept_alloc_page() for an explanation.
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

void ept_free_ptr(struct ept *ept, u16 eptp)
{
	free_entries(EPT4(ept, eptp), 4);
	clear_bit(eptp, ept->ptr_bitmap);
}

static void free_pml4_list(struct ept *ept)
{
	for_each_eptp(ept, i)
		ept_free_ptr(ept, i);
}

static inline bool init_ept(struct ept *ept)
{
	int i;
	u16 dontcare;

	for (i = 0; i < EPTP_INIT_USED; ++i) {
		if (!ept_create_ptr(ept, EPT_ACCESS_ALL, &dontcare)) {
			free_pml4_list(ept);
			return false;
		}
	}

	return true;
}

static inline void free_ept(struct ept *ept)
{
	free_pml4_list(ept);
}

/*
 * Called from:
 *	- ept_handle_violation() aka VMX root mode (host mode)
 *	- __ept_handle_violation() aka IDT #VE (guest mode)
 *
 * @eptp_switch is modified if switching is needed.
 * If invalidation is required, @invd will be set,
 * do note that invalidation can only occur inside VMX root
 * mode, and it's not required in non-root (#VE).
 *
 * Note that we don't need to invalidate non existent entries, aka entries that
 * mostly have EPT_ACCESS_NONE which is usually not even allocated...
 */
static bool do_ept_violation(struct ept_ve_around *ve)
{
	struct vcpu *vcpu = ve->vcpu;
	struct ept *ept = &vcpu->ept;
	struct ksm *k = vcpu_to_ksm(vcpu);
	struct ve_except_info *info = ve->info;

	if ((info->exit & EPT_VE_RWX) == 0) {	/* no access  */
		if (!ept_alloc_page(EPT4(ept, info->eptp),
				    EPT_ACCESS_ALL, info->gpa, info->gpa))
			return false;

		return true;
	}

#ifdef EPAGE_HOOK
	struct epage_info *epage = ksm_find_epage(k, info->gpa);
	if (epage) {
		ksm_handle_epage_ve(epage, ve);
		return true;
	}
#endif

#ifdef PMEM_SANDBOX
	if (ksm_sandbox_handle_ept(ve))
		return true;
#endif

#ifdef INTROSPECT_ENGINE
	if (ksm_introspect_handle_ept(ve))
		return true;
#endif

	return false;
}

/*
 * Handle a VM-Exit EPT violation
 * Root mode.
 */
bool ept_handle_violation(struct vcpu *vcpu)
{
	struct ksm *k = vcpu_to_ksm(vcpu);
	struct ve_except_info info = {
		.exit = vmcs_read(EXIT_QUALIFICATION),
		.gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS),
		.gla = vmcs_read(GUEST_LINEAR_ADDRESS),
		.eptp = vcpu_eptp_idx(vcpu),
	};
	struct ept_ve_around ve = {
		.vcpu = vcpu,
		.info = &info,
		.rip = vcpu->ip,
		.dpl = VMX_AR_DPL(vmcs_read(GUEST_SS_AR_BYTES)),
		.pgd = vmcs_read(GUEST_CR3) & PAGE_PA_MASK,
		.eptp_next = info.eptp,
		.invalidate = false,
	};

	if (!do_ept_violation(&ve))
		return false;

	if (ve.eptp_next != info.eptp)
		vcpu_switch_root_eptp(vcpu, ve.eptp_next);
	else if (ve.invalidate)
		cpu_invept(k, info.gpa, EPTP(&vcpu->ept, info.eptp));

	return true;
}

/*
 * This is called from the IDT handler (__ept_violation) see vmx.{S,asm}
 * Non-root mode.
 */
void __ept_handle_violation(uintptr_t cs, uintptr_t rip)
{
	struct vcpu *vcpu = ksm_current_cpu();
	struct ve_except_info *info = &vcpu->ve;
	struct ept_ve_around ve = {
		.vcpu = vcpu,
		.info = info,
		.rip = rip,
		.pgd = __readcr3() & PAGE_PA_MASK,
		.dpl = cs & 3,
		.eptp_next = info->eptp,
		.invalidate = false,
	};

	info->except_mask = 0;
	if (!do_ept_violation(&ve))
		KSM_PANIC(EPT_BUGCHECK_CODE, EPT_UNHANDLED_VIOLATION, rip, info->gpa);

	if (ve.eptp_next != info->eptp)
		vcpu_vmfunc(ve.eptp_next, 0);
}

#ifndef _MSC_VER
/*
 * Under MinGW a function with the same name is exported, but
 * I haven't been able to find which library exports it.
 * Others are part of libmingwex, this one should've also been
 * there, perhaps it's part of the Microsoft related libraries?
 */
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
	*val &= (u32)(v >> 32); 	/* bit == 0 in high word ==> must be zero  */
	*val |= (u32)v; 		/* bit == 1 in low word  ==> must be one  */
}

void vcpu_run(struct vcpu *vcpu, uintptr_t gsp, uintptr_t gip)
{
	/*
	 * This function is called from __vmx_vminit, which is in assembly.
	 *
	 * Note: that we end up in __ksm_init_cpu anyway regardless of failure or
	 * success, but the difference is, if we fail, __vmx_vmlaunch() will give
	 * us back control instead of directly ending up in __ksm_init_cpu.
	 *
	 * The guest start is do_resume in assembly, which returns to __ksm_init_cpu.
	 *	The following are restored on entry:
	 *		- GUEST_RFLAGS
	 *		- Guest registers
	 */
	struct vmcs *vmcs, *vmxon;
	struct gdtr gdtr;
	struct gdtr *idtr = &vcpu->g_idt;
	struct ept *ept = &vcpu->ept;
	struct ksm *k = vcpu_to_ksm(vcpu);

	u64 vmx;
	u16 es = __reades();
	u16 cs = __readcs();
	u16 ss = __readss();
	u16 ds = __readds();
	u16 fs = __readfs();
	u16 gs = __readgs();
	u16 ldt = __sldt();
	u16 tr = __str();
	u32 verr;
	u8 err = 0;

	uintptr_t cr0 = __readcr0();
	uintptr_t cr3 = __readcr3();
	uintptr_t cr4 = __readcr4();

	/*
	 * Keep an original copy of their IDT base and limit so we can
	 * restore on exit, and give it to them when `sidt' is executed.
	 *
	 * The shadow IDT ->idt is also a copy of their original, but here
	 * we overwrite the #VE (X86_TRAP_VE) in that one later if we find out
	 * that #VE is supported.
	 *
	 * For more information, see:
	 *	vcpu_sync_idt() in exit.c
	 *  and vcpu_handle_gdt_idt_access() in exit.c
	 */
	__sgdt(&gdtr);
	__sidt(idtr);
	memcpy((void *)vcpu->idt.base, (void *)idtr->base, idtr->limit);

	/* Required bits in CR0  */
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0);

	/* ... and CR4 (Most importantly VMXE bit) */
	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4);

	/*
	 * This MSR has some useful stuff, most notably the VMX revision ID
	 * which must be on top of VMXON region and VMCS region.
	 */
	vmx = __readmsr(MSR_IA32_VMX_BASIC);

	vmxon = &vcpu->vmxon;
	vmxon->revision_id = (u32)vmx;

	/* Enter VMX root operation  */
	u64 pa = __pa(vmxon);
	err = __vmx_on(&pa);
	if (err) {
		KSM_DEBUG("vmxon failed: %d\n", err);
		return;
	}

	vmcs = &vcpu->vmcs;
	vmcs->revision_id = (u32)vmx;

	pa = __pa(vmcs);
	err = __vmx_vmclear(&pa);
	if (err)
		goto off;

	err = __vmx_vmptrld(&pa);
	if (err)
		goto off;

#if 0
	/* This needs serious fixing  */
	u32 apicv = 0;
	if (lapic_in_kernel()) {
		apicv |= SECONDARY_EXEC_APIC_REGISTER_VIRT;
		if (x2apic_enabled())
			apicv |= SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
		else
			apicv |= SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
	}
#endif

	/*
	 * VMX MSRs are split into 2 things (normal and true controls), the VMX
	 * basic MSR determines which one we should be using, in short, the MSR
	 * has bits to control which bits are allowed in the control fields,
	 * and which must be set.  See adjust_ctl_val().
	 */
	u32 msr_off = 0;
	if (vmx & VMX_BASIC_TRUE_CTLS)
		msr_off = 0xC;

	/* VM Entry (aka guest entry)  */
	u32 vm_entry = VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE	/* We want long mode  */
#ifndef DBG
		| VM_ENTRY_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_ENTRY_CTLS + msr_off, &vm_entry);
	vcpu->entry_ctl = vm_entry;

	/* VM Exit (aka host entry)  */
	u32 vm_exit = VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_ACK_INTR_ON_EXIT
		| VM_EXIT_HOST_ADDR_SPACE_SIZE
#ifndef DBG
		| VM_EXIT_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_EXIT_CTLS + msr_off, &vm_exit);
	vcpu->exit_ctl = vm_exit;

	/* Pin controls (external interrupts, etc.)  */
	u32 vm_pinctl = PIN_BASED_POSTED_INTR;
	adjust_ctl_val(MSR_IA32_VMX_PINBASED_CTLS + msr_off, &vm_pinctl);
	vcpu->pin_ctl = vm_pinctl;

	/* Primary processor controls  */
	const u32 req_cpuctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_USE_IO_BITMAPS
#ifdef PMEM_SANDBOX
		| CPU_BASED_CR3_LOAD_EXITING
#endif
		;
	u32 vm_cpuctl = req_cpuctl
#if 0
		| CPU_BASED_TPR_SHADOW
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS + msr_off, &vm_cpuctl);
	vcpu->cpu_ctl = vm_cpuctl;

	/* Make sure required are set  */
	if ((vm_cpuctl & req_cpuctl) != req_cpuctl) {
		KSM_DEBUG("Primary controls required are not supported: 0x%X 0x%X\n",
			   req_cpuctl, vm_cpuctl & req_cpuctl);
		return;
	}

	/* Secondary processor controls  */
	const u32 req_2ndctl = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID;
	u32 vm_2ndctl = req_2ndctl
		| SECONDARY_EXEC_XSAVES //| SECONDARY_EXEC_UNRESTRICTED_GUEST
		| SECONDARY_EXEC_ENABLE_VMFUNC | SECONDARY_EXEC_ENABLE_VE
#if 0
		| /* apic virtualization  */ apicv
#endif
#if defined(_WIN32_WINNT) && _WIN32_WINNT == 0x0A00	/* w10 required features  */
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
	vcpu->secondary_ctl = vm_2ndctl;

	/* Make sure required bits are set  */
	if ((vm_2ndctl & req_2ndctl) != req_2ndctl) {
		KSM_DEBUG("Secondary controls required are not supported: 0x%X 0x%X\n",
			   req_2ndctl, vm_2ndctl & req_2ndctl);
		return;
	}

	/* Processor control fields  */
	err |= vmcs_write32(VM_ENTRY_CONTROLS, vm_entry);
	err |= vmcs_write32(VM_EXIT_CONTROLS, vm_exit);
	err |= vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl);
	err |= vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
	err |= vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vm_2ndctl);

	/*
	 * We don't really have any MSRs that we want to auto-load, so zero
	 * everything.
	 */
	err |= vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	err |= vmcs_write64(VM_EXIT_MSR_STORE_ADDR, 0);
	err |= vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	err |= vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, 0);
	err |= vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	/* This controls injectible-interrupts (see exit.c)  */
	err |= vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	err |= vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	err |= vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 0);

	/* Control Fields */
	err |= vmcs_write16(VIRTUAL_PROCESSOR_ID, vpid_nr());
	err |= vmcs_write32(EXCEPTION_BITMAP, __EXCEPTION_BITMAP);
	err |= vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	err |= vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	err |= vmcs_write32(CR3_TARGET_COUNT, 0);
	err |= vmcs_write64(IO_BITMAP_A, __pa(k->io_bitmap_a));
	err |= vmcs_write64(IO_BITMAP_B, __pa(k->io_bitmap_b));
	err |= vmcs_write64(MSR_BITMAP, __pa(k->msr_bitmap));
	err |= vmcs_write64(EPT_POINTER, EPTP(ept, EPTP_DEFAULT));

	/* This must be ~0ULL  */
	err |= vmcs_write64(VMCS_LINK_POINTER, ~0ULL);

	/* Posted interrupts if available, otherwise entry to guest will fail.  */
	if (vm_pinctl & PIN_BASED_POSTED_INTR) {
		err |= vmcs_write16(POSTED_INTR_NV, 0);
		err |= vmcs_write64(POSTED_INTR_DESC_ADDR, __pa(&vcpu->pi_desc));
	}

#if 0
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
						    __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE);
		}
	}
#endif

	/*
	 * CR0/CR4 controls:
	 *	1. Shadow fields: For each bit that is set, that bit will not
	 *	   appear when guest reads the control field.
	 *	2. Guest host mask fields: For each bit that is set, a VM exit
	 *	   will occur when the guest attempts to set that bit.
	 */
	err |= vmcs_write(CR0_GUEST_HOST_MASK, vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_GUEST_HOST_MASK, vcpu->cr4_guest_host_mask);
	err |= vmcs_write(CR0_READ_SHADOW, cr0 & ~vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_READ_SHADOW, cr4 & ~vcpu->cr4_guest_host_mask);

	/* See if we need to emulate VMFUNC via a VMCALL  */
	vcpu->vm_func_ctl = 0;
	if (vm_2ndctl & SECONDARY_EXEC_ENABLE_VMFUNC) {
		err |= vmcs_write64(VM_FUNCTION_CTRL, VM_FUNCTION_CTL_EPTP_SWITCHING);
		err |= vmcs_write64(EPTP_LIST_ADDRESS, __pa(ept->ptr_list));
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
		err |= vmcs_write64(PML_ADDRESS, __pa(vcpu->pml));
		err |= vmcs_write16(GUEST_PML_INDEX, PML_MAX_ENTRIES - 1);
	}
#endif

	/*
	 * Guest fields:
	 *	This simply just copies over selectors, their access rights and
	 *	their bases, their cr0, cr3, cr4 and some more, note that their
	 *	eflags are always restored to the one before this call, so it
	 *	doesn't really matter what we set them to.
	 */
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
	err |= vmcs_write32(GUEST_IDTR_LIMIT, idtr->limit);
	err |= vmcs_write32(GUEST_ES_AR_BYTES, __accessright(es));
	err |= vmcs_write32(GUEST_CS_AR_BYTES, __accessright(cs));
	err |= vmcs_write32(GUEST_SS_AR_BYTES, __accessright(ss));
	err |= vmcs_write32(GUEST_DS_AR_BYTES, __accessright(ds));
	err |= vmcs_write32(GUEST_FS_AR_BYTES, __accessright(fs));
	err |= vmcs_write32(GUEST_GS_AR_BYTES, __accessright(gs));
	err |= vmcs_write32(GUEST_LDTR_AR_BYTES, __accessright(ldt));
	err |= vmcs_write32(GUEST_TR_AR_BYTES, __accessright(tr));
	err |= vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	err |= vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	err |= vmcs_write64(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTLMSR));
	err |= vmcs_write(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	err |= vmcs_write(GUEST_CR0, cr0);
	err |= vmcs_write(GUEST_CR3, cr3);
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
	err |= vmcs_write32(GUEST_SYSENTER_CS, (u32)__readmsr(MSR_IA32_SYSENTER_CS));
	err |= vmcs_write(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= vmcs_write(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	/*
	 * Host fields:
	 *	Note for the selector part, the processor requires that the TI
	 *	(Table indicator) and RPL (Requestor privilege level) are 0, so
	 *	we AND it with 0xF8 to make sure they are clear.
	 */
	err |= vmcs_write16(HOST_ES_SELECTOR, es & 0xf8);
	err |= vmcs_write16(HOST_CS_SELECTOR, cs & 0xf8);
	err |= vmcs_write16(HOST_SS_SELECTOR, ss & 0xf8);
	err |= vmcs_write16(HOST_DS_SELECTOR, ds & 0xf8);
	err |= vmcs_write16(HOST_FS_SELECTOR, fs & 0xf8);
	err |= vmcs_write16(HOST_GS_SELECTOR, gs & 0xf8);
	err |= vmcs_write16(HOST_TR_SELECTOR, tr & 0xf8);
	err |= vmcs_write(HOST_CR0, cr0);
	err |= vmcs_write(HOST_CR3, k->host_pgd);
	err |= vmcs_write(HOST_CR4, cr4);
	err |= vmcs_write(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= vmcs_write(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= vmcs_write(HOST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= vmcs_write(HOST_GDTR_BASE, gdtr.base);
	err |= vmcs_write(HOST_IDTR_BASE, idtr->base);
	err |= vmcs_write32(HOST_IA32_SYSENTER_CS, (u32)__readmsr(MSR_IA32_SYSENTER_CS));
	err |= vmcs_write(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= vmcs_write(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	err |= vmcs_write(HOST_RSP, (uintptr_t)vcpu->stack + KERNEL_STACK_SIZE - 8);
	err |= vmcs_write(HOST_RIP, (uintptr_t)__vmx_entrypoint);

	if (err == 0) {
		/*
		 * This is necessary here or just before we exit the VM,
		 * we do it both just incase.
		 */
		__invept_all();
		__invvpid_all();

		/* If all good, this goes to do_resume (initial guest entry) label in assembly.  */
		err = __vmx_vmlaunch();
	}

	/*
	 * vmwrite/vmlaunch failed if we got here,  In the vmlaunch fail case,
	 * we had already overwritten the IDT entry for #VE (X86_TRAP_VE),
	 * restore it now otherwise on Windows, PatchGuard is gonna
	 * notice and crash the system.
	 */
	__lidt(&vcpu->g_idt);

off:
	verr = vmcs_read32(VM_INSTRUCTION_ERROR);
	__vmx_off();
	KSM_DEBUG("%d: something went wrong: %d\n", err, verr);
}

int vcpu_init(struct vcpu *vcpu)
{
	/*
	 * This is gonna hold the shadow IDT, which they won't see, but it's
	 * the one that'll they be using.
	 */
	vcpu->idt.limit = PAGE_SIZE - 1;
	vcpu->idt.base = (uintptr_t)mm_alloc_page();
	if (!vcpu->idt.base)
		return ERR_NOMEM;

	if (!init_ept(&vcpu->ept)) {
		mm_free_page((void *)vcpu->idt.base);
		return ERR_NOMEM;
	}

#ifdef NESTED_VMX
	vcpu->nested_vcpu.feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL) & ~FEATURE_CONTROL_LOCKED;
#endif

	/*
	 * Leave cr0 guest host mask empty, we support all.
	 * Set VMXE bit in cr4 guest host mask so they VM-exit to us when
	 * they try to set that bit.
	 *
	 * Note: These bits are also removed from CRx_READ_SHADOW fields, if
	 * you want to opt-in a VM exit without having to remove that bit
	 * completely from their CR0, then you'd probably want to make
	 * a different variable, e.g. `cr0_read_shadow = X86_CR0_PE` and OR it
	 * in CR0_GUEST_HOST_MASK, without masking it in CR0_READ_SHADOW...
	 */
	vcpu->cr0_guest_host_mask = 0;
	vcpu->cr4_guest_host_mask = X86_CR4_VMXE;

	*(struct vcpu **)((uintptr_t)vcpu->stack + KERNEL_STACK_SIZE - 8) = vcpu;
	return 0;
}

void vcpu_free(struct vcpu *vcpu)
{
	mm_free_page((void *)vcpu->idt.base);
	free_ept(&vcpu->ept);
}

void vcpu_switch_root_eptp(struct vcpu *vcpu, u16 index)
{
	u16 curr;
	BUG_ON(!test_bit(index, (const volatile unsigned long *)vcpu->ept.ptr_bitmap));

	if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE) {
		/* Native  */
		curr = vmcs_read16(EPTP_INDEX);
		if (curr == index)
			return;

		vmcs_write16(EPTP_INDEX, index);
	} else {
		/* Emulated  */
		struct ve_except_info *ve = &vcpu->ve;
		if (ve->eptp == index)
			return;

		ve->eptp = index;
	}

	/* Update EPT pointer  */
	vmcs_write64(EPT_POINTER, EPTP(&vcpu->ept, index));
	/* We have to invalidate, we just switched to a new paging hierarchy  */
	__invept_all();
}
