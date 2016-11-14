/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * This file handles a VM-exit from guest, if any error occurs,
 * it either:
 *	1) crashes the system
 *	2) injects an exception into guest
 * Otherwise it returns execution to guest.
 *
 * TODO:
 *	1) APIC virtualization
 *	2) Interrupt Queueing (currently, if it fails, it just ignores error)
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
#ifdef MINGW
/* Annoying warning from ntddk */
struct _DISK_GEOMETRY_EX;
#endif

#include <ntddk.h>
#include <intrin.h>

#include "ksm.h"

#if defined(NESTED_VMX) || defined(DBG)
static u16 curr_handler = 0;
#ifdef DBG
static u16 prev_handler = 0;
#endif
#endif

#ifdef NESTED_VMX
static const u32 nested_unsupported_secondary = SECONDARY_EXEC_ENABLE_VE | SECONDARY_EXEC_ENABLE_EPT |
						SECONDARY_EXEC_DESC_TABLE_EXITING | SECONDARY_EXEC_APIC_REGISTER_VIRT |
						SECONDARY_EXEC_ENABLE_ENCLS_EXITING | SECONDARY_EXEC_ENABLE_PML |
						SECONDARY_EXEC_ENABLE_VPID | SECONDARY_EXEC_ENABLE_VMFUNC;

static inline u32 field_offset(u32 field)
{
	/* Stolen from XEN  */
	u32 index = (field >> 1) & 0x1F;
	u32 type = (field >> 10) & 2;
	u32 width = (field >> 12) & 2;

	u32 offset = index | type << 5 | width << 7;
	if (offset == 0)
		return 0x3F;	/* VPID  */

	return offset;
}

typedef enum {
	FIELD_U16 = 0,
	FIELD_U64 = 1,
	FIELD_U32 = 2,
	FIELD_NATURAL = 3,
} ftype_t;

static inline ftype_t field_type(u32 field)
{
	if (field & 1)
		return FIELD_U32;

	return (field >> 13) & 3;
}

static inline bool field_ro(u32 field)
{
	return ((field >> 10) & 3) == 1;
}

static inline bool nested_vmcs_write(uintptr_t vmcs, u32 field, u64 value)
{
	uintptr_t f = vmcs + field_offset(field);
	switch (field_type(field)) {
	case FIELD_U16:
		*(u16 *)f = value;
		return true;
	case FIELD_U32:
		*(u32 *)f = value;
		return true;
	case FIELD_U64:
	case FIELD_NATURAL:
		*(u64 *)f = value;
		return true;
	}

	return false;
}

static inline u64 nested_vmcs_read(uintptr_t vmcs, u32 field)
{
	uintptr_t f = vmcs + field_offset(field);
	switch (field_type(field)) {
	case FIELD_U16:		return *(u16 *)f;
	case FIELD_U32:		return *(u32 *)f;
	case FIELD_U64:
	case FIELD_NATURAL:
		return *(u64 *)f;
	}

	return 0;
}
#endif

static inline int vcpu_read_cpl(void)
{
	u32 ar = vmcs_read32(GUEST_SS_AR_BYTES);
	return VMX_AR_DPL(ar);
}

static inline bool vcpu_check_cpl(int required)
{
	return vcpu_read_cpl() <= required;
}

static inline bool vcpu_inject_irq(size_t instr_len, u16 intr_type, u8 vector, bool has_err, u32 ec)
{
	u32 irq = vector | intr_type | INTR_INFO_VALID_MASK;
	if (has_err) {
		irq |= INTR_INFO_DELIVER_CODE_MASK;
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ec);
	}

	bool ret = __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, irq & ~INTR_INFO_RESVD_BITS_MASK) == 0;
	if (instr_len)
		ret &= __vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, instr_len) == 0;
	return ret;
}

static inline bool vcpu_inject_hardirq_noerr(u8 vector)
{
	return vcpu_inject_irq(vmcs_read(VM_EXIT_INSTRUCTION_LEN), INTR_TYPE_HARD_EXCEPTION,
			       vector, false, 0);
}

static inline void vcpu_advance_rip(struct vcpu *vcpu)
{
	if (vcpu->eflags & X86_EFLAGS_TF) {
		vcpu_inject_hardirq_noerr(X86_TRAP_DB);
		if (vcpu_check_cpl(0)) {
			__writedr(6, __readdr(6) | DR6_BS | DR6_RTM);
			__writedr(7, __readdr(7) & ~DR7_GD);

			u64 dbg;
			__vmx_vmread(GUEST_IA32_DEBUGCTL, &dbg);
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL, dbg & ~DEBUGCTLMSR_LBR);
		}
	}

	size_t instr_len;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instr_len);
	__vmx_vmwrite(GUEST_RIP, vcpu->ip + instr_len);

	size_t interruptibility;
	__vmx_vmread(GUEST_INTERRUPTIBILITY_INFO, &interruptibility);
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO,
		      interruptibility & ~(GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI));
}

static inline bool vcpu_inject_ve(struct vcpu *vcpu)
{
	/*
	 * Shouldn't really call this function at all unless
	 * "fake" injection is really required, otherwise this is going
	 * to cause a unneeded overhead.
	 *
	 * See if we support #VE handling.
	 */
	if (!(vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE))
		return false;

	/* Make sure there is an IDT entry for #VE  */
	if (!idte_present(idt_entry(vcpu->idt.base, X86_TRAP_VE))) {
		VCPU_DEBUG("Trying to inject #VE into a non-existent IDT entry.\n");
		return false;
	}

	struct ve_except_info *info = &vcpu->ve;
	if (info->except_mask != 0)	/* Just warn  */
		VCPU_DEBUG("Trying to inject #VE but guest opted-out.\n");

	/* Set appropriate data in VE structure  */
	info->eptp = vcpu_eptp_idx(vcpu);
	info->except_mask = ~0UL;
	info->reason = EXIT_REASON_EPT_VIOLATION;
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &info->gpa);
	__vmx_vmread(GUEST_LINEAR_ADDRESS, &info->gla);
	__vmx_vmread(EXIT_QUALIFICATION, &info->exit);

	return vcpu_inject_hardirq_noerr(X86_TRAP_VE);
}

static inline bool vcpu_inject_pf(struct vcpu *vcpu, u64 gla, u32 ec)
{
	__writecr2(gla);	/* XXX  */
	return vcpu_inject_irq(vmcs_read(VM_EXIT_INSTRUCTION_LEN),
			       INTR_TYPE_HARD_EXCEPTION,
			       X86_TRAP_PF,
			       true,
			       ec);
}

static bool vcpu_nop(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	VCPU_DEBUG_RAW("you need to handle the corresponding VM-exit for the handler you set.\n");
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_BUG_UNHANDLED, curr_handler, prev_handler);
	return false;
}

static bool vcpu_handle_except_nmi(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	u32 intr_type = intr_info & INTR_INFO_INTR_TYPE_MASK;
	u8 vector = intr_info & INTR_INFO_VECTOR_MASK;

	size_t instr_len = 0;
	if (intr_type & INTR_TYPE_HARD_EXCEPTION && vector == X86_TRAP_PF)
		__writecr2(vmcs_read(EXIT_QUALIFICATION));
	else if (intr_type & INTR_TYPE_SOFT_EXCEPTION && vector == X86_TRAP_BP)
		instr_len = 1;
	else
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instr_len);

	bool has_err = intr_info & INTR_INFO_DELIVER_CODE_MASK;
	u32 err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
	if (!vcpu_inject_irq(instr_len, intr_type, vector, has_err, err))
		VCPU_BUGCHECK(VCPU_IRQ_NOT_HANDLED, vcpu->ip, intr_type, vector);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_triplefault(struct vcpu *vcpu)
{
	/* A triple fault occured during handling of a double fault in guest, bug check.  */
	VCPU_TRACER_START();
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_TRIPLEFAULT, curr_handler, prev_handler);
	VCPU_TRACER_END();
	return false;
}

static bool vcpu_handle_taskswitch(struct vcpu *vcpu)
{
	/* Not really called  */
	VCPU_TRACER_START();

	u64 exit;
	__vmx_vmread(EXIT_QUALIFICATION, &exit);

	u16 selector = (u16)exit;
	u8 src = (exit >> 30) & 3;
	const char *name;
	switch (src) {
	case 0:
		name = "call";
		break;
	case 1:
		name = "iret";
		break;
	case 2:
		name = "jmp";
		break;
	case 3:
	default:
		name = "task gate";
		break;
	}

	const char *table = "gdt";
	if (selector & 4)
		table = "ldt";

	VCPU_DEBUG("switching through %s (selector: %d => table: %s index: %d)\n",
		   name, selector, table, selector >> 3);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_cpuid(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	int cpuid[4];
	int func = ksm_read_reg32(vcpu, REG_AX);
	int subf = ksm_read_reg32(vcpu, REG_CX);
	__cpuidex(cpuid, func, subf);

#ifndef NESTED_VMX
	if (func == 1)
		cpuid[2] &= ~(1 << (X86_FEATURE_VMX & 31));
#endif

	ksm_write_reg32(vcpu, REG_AX, cpuid[0]);
	ksm_write_reg32(vcpu, REG_BX, cpuid[1]);
	ksm_write_reg32(vcpu, REG_CX, cpuid[2]);
	ksm_write_reg32(vcpu, REG_DX, cpuid[3]);
	vcpu_advance_rip(vcpu);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_hlt(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	__halt();
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invd(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	__invd();
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invlpg(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	uintptr_t addr;
	__vmx_vmread(EXIT_QUALIFICATION, &addr);
	__invlpg((void *)addr);
	__invvpid_addr(vpid_nr(), addr);
	vcpu_advance_rip(vcpu);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_rdtsc(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u64 tsc = __rdtsc();
	ksm_write_reg32(vcpu, REG_AX, tsc);
	ksm_write_reg32(vcpu, REG_DX, tsc >> 32);
	vcpu_advance_rip(vcpu);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_vmfunc(struct vcpu *vcpu)
{
	/* VM functions do not cause VM exit unless:
	 *	1) funciton is not supported
	 *	2) EPTP index is too high.
	 */
	VCPU_TRACER_START();
	VCPU_DEBUG("vmfunc caused VM-exit!  func is %d eptp index is %d\n",
		   ksm_read_reg32(vcpu, REG_AX), ksm_read_reg32(vcpu, REG_CX));
	vcpu_inject_hardirq_noerr(X86_TRAP_UD);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END()
		return true;
}

#ifdef ENABLE_PML
static bool vcpu_dump_pml(struct vcpu *vcpu)
{
	u64 pml_index;
	__vmx_vmread(GUEST_PML_INDEX, &pml_index);

	/* CPU _decrements_ PML index (i.e. from 511 to 0 then overflows to FFFF),
	 * make sure we don't have an empty table...  */
	if (pml_index == PML_MAX_ENTRIES - 1)
		return false;

	/* PML index always points to next available PML entry.  */
	if (pml_index >= PML_MAX_ENTRIES)
		pml_index = 0;
	else
		pml_index++;

	/* Dump it...  */
	struct ept *ept = &vcpu->ept;

	u16 eptp = vcpu_eptp_idx(vcpu);
	for (; pml_index < PML_MAX_ENTRIES; ++pml_index) {
		/* CPU guarantees that the lower 12 bits (the offset) are always 0.  */
		u64 gpa = vcpu->pml[pml_index];
		u64 gva = (u64)__va(gpa);
		VCPU_DEBUG("On PML %d: GPA %p GVA %p\n", pml_index, gpa, gva);

		/* Reset AD bits now otherwise we probably won't get this page again  */
		uintptr_t *epte = ept_pte(ept, EPT4(ept, eptp), gpa);
		*epte &= ~(EPT_ACCESSED | EPT_DIRTY);
	}

	/* Reset the PML index now...  */
	__vmx_vmwrite(GUEST_PML_INDEX, pml_index);
	/* We're done here  */
	VCPU_DEBUG_RAW("PML dump done\n");
	/* We definitely modified AD bits  */
	__invept_all();
	return true;
}
#endif

static bool vcpu_handle_pml_full(struct vcpu *vcpu)
{
#ifdef ENABLE_PML
	/* Page Modification Log is now full, dump it.  */
	VCPU_DEBUG_RAW("PML full\n");
	return vcpu_dump_pml(vcpu);
#else
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_BUG_UNHANDLED, 0xDEAFDEAF, 0xBAADF00D);
	return false;
#endif
}

static inline void vcpu_vm_succeed(struct vcpu *vcpu)
{
	vcpu->eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			  X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
}

static inline void vcpu_vm_fail_invalid(struct vcpu *vcpu)
{
	vcpu->eflags |= X86_EFLAGS_CF;
	vcpu->eflags &= ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
}

static inline void vcpu_vm_fail_valid(struct vcpu *vcpu, size_t err)
{
	vcpu->eflags |= X86_EFLAGS_ZF;
	vcpu->eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_SF | X86_EFLAGS_OF);
	__vmx_vmwrite(VM_INSTRUCTION_ERROR, err);
}

static inline void vcpu_adjust_rflags(struct vcpu *vcpu, bool success)
{
	if (success)
		return vcpu_vm_succeed(vcpu);

	return vcpu_vm_fail_invalid(vcpu);
}

static inline void vcpu_do_exit(struct vcpu *vcpu)
{
	/* Fix GDT  */
	struct gdtr gdt;
	gdt.limit = vmcs_read16(GUEST_GDTR_LIMIT);
	gdt.base = vmcs_read(GUEST_GDTR_BASE);
	__lgdt(&gdt);

	/* Fix IDT (restore whatever guest last loaded...)  */
	__lidt(&vcpu->g_idt);

	size_t ret = vcpu->ip + vmcs_read(VM_EXIT_INSTRUCTION_LEN);
	vcpu_vm_succeed(vcpu);

	u64 cr3;
	__vmx_vmread(GUEST_CR3, &cr3);
	__writecr3(cr3);

	/* See __vmx_entrypoint in assembly on how this is used.  */
	ksm_write_reg(vcpu, REG_CX, ret);
	ksm_write_reg(vcpu, REG_DX, ksm_read_reg(vcpu, REG_SP));
	ksm_write_reg(vcpu, REG_AX, vcpu->eflags);
}

static bool vcpu_handle_hook(struct vcpu *vcpu, struct page_hook_info *h)
{
	VCPU_DEBUG("page hook request for %p => %p (%p)\n", h->d_pfn, h->c_pfn, h->c_va);
	h->ops->init_eptp(h, &vcpu->ept);
	return true;
}

static inline bool vcpu_handle_unhook(struct vcpu *vcpu, uintptr_t dpa)
{
	struct ept *ept = &vcpu->ept;
	VCPU_DEBUG("unhook page %p\n", dpa);
	for_each_eptp(i)
		ept_alloc_page(ept, EPT4(ept, i), EPT_ACCESS_ALL, dpa);
	__invept_all();
	return true;
}

static inline void vcpu_flush_idt(struct vcpu *vcpu)
{
	__vmx_vmwrite(GUEST_IDTR_LIMIT, vcpu->idt.limit);
	__vmx_vmwrite(GUEST_IDTR_BASE, vcpu->idt.base);
}

static inline bool vcpu_hook_idte(struct vcpu *vcpu, struct shadow_idt_entry *h)
{
	u16 cs = vmcs_read16(GUEST_CS_SELECTOR);
	vcpu_put_idt(vcpu, cs, h->n, h->h);
	vcpu_flush_idt(vcpu);
	return true;
}

static inline bool vcpu_unhook_idte(struct vcpu *vcpu, struct shadow_idt_entry *h)
{
	struct kidt_entry64 *entry = &vcpu->shadow_idt[h->n];
	if (!idte_present(entry))
		return false;

	put_entry(vcpu->idt.base, h->n, entry);
	vcpu_flush_idt(vcpu);
	entry->e32.p = 0;
	return true;
}

static inline bool vcpu_emulate_vmfunc(struct vcpu *vcpu, struct h_vmfunc *vmfunc)
{
	/* Emulate a VMFUNC due it to not being supported natively.  */
	if (vmfunc->func >= 64 || !(vcpu->vm_func_ctl & (1 << vmfunc->func)) ||
		(vmfunc->func == 0 && vmfunc->eptp >= EPTP_USED)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		return false;
	}

	vcpu_switch_root_eptp(vcpu, vmfunc->eptp);
	return true;
}

static bool vcpu_handle_vmcall(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	if (!vcpu_check_cpl(0)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		goto out;
	}

	uint8_t nr = ksm_read_reg32(vcpu, REG_CX);
	uintptr_t arg = ksm_read_reg(vcpu, REG_DX);
	switch (nr) {
	case HYPERCALL_STOP:
		vcpu_do_exit(vcpu);
		VCPU_TRACER_END();
		return false;
	case HYPERCALL_IDT:
		vcpu_adjust_rflags(vcpu, vcpu_hook_idte(vcpu, (struct shadow_idt_entry *)arg));
		break;
	case HYPERCALL_UIDT:
		vcpu_adjust_rflags(vcpu, vcpu_unhook_idte(vcpu, (struct shadow_idt_entry *)arg));
		break;
	case HYPERCALL_HOOK:
		vcpu_adjust_rflags(vcpu, vcpu_handle_hook(vcpu, (struct page_hook_info *)arg));
		break;
	case HYPERCALL_UNHOOK:
		vcpu_adjust_rflags(vcpu, vcpu_handle_unhook(vcpu, arg));
		break;
	case HYPERCALL_VMFUNC:
		vcpu_adjust_rflags(vcpu, vcpu_emulate_vmfunc(vcpu, (struct h_vmfunc *)arg));
		break;
	default:
		VCPU_DEBUG("unsupported hypercall: %d\n", nr);
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		break;
	}

out:
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

#ifdef NESTED_VMX
static inline u64 nested_translate_gva(struct vcpu *vcpu, u64 gva, u64 mask)
{
	u32 ec = PGF_PRESENT;
	if (mask & PAGE_WRITE)
		ec |= PGF_WRITE;

	uintptr_t *pte = va_to_pxe(gva);
	if (!pte || !pte_present(pte))
		goto fault;

	pte = va_to_ppe(gva);
	if (!pte || !pte_present(pte))
		goto fault;

	pte = va_to_pde(gva);
	if (!pte_present(pte))
		goto fault;

	if (!pte_large(pte) && !(pte = va_to_pte(gva)))
		goto fault;

	if ((*pte & mask) == mask)
		return PAGE_PA(*pte);	/* Check EPT?  */

fault:
	vcpu_inject_pf(vcpu, gva, ec);
	return ~0ULL;
}

static inline uintptr_t vcpu_read_vmx_addr(struct vcpu *vcpu, u64 exit, u64 inst, u64 *gpa, u32 mask)
{
	if (inst & (1 << 10)) {
		/* register not allowed  */
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		return 0;
	}

	uintptr_t base = 0;
	if (!((inst >> 27) & 1))
		base = ksm_read_reg(vcpu, (inst >> 23) & 15);

	uintptr_t index = 0;
	if (!((inst >> 22) & 1))
		index = ksm_read_reg(vcpu, (inst >> 18) & 15);

	/* exit is displacement.  */
	uintptr_t gva = base + index + exit;

	/* Add segment base  */
	u32 seg_offset = (inst >> 15) & 7;
	if (seg_offset < 5)
		gva += vmcs_read(GUEST_ES_BASE + (seg_offset << 1));

	if (((inst >> 7) & 7) == 1)
		gva &= 0xFFFFFFFF;

	if ((gva & (PAGE_SIZE - 1)) != 0 || (gva >> 48) != 0) {
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		return 0;
	}

	*gpa = nested_translate_gva(vcpu, gva, mask);
	return gva;
}

static inline bool vcpu_nested_root_checks(struct vcpu *vcpu)
{
	/* Typical VMX checks, make sure we're inside the nested hypervisor's "root".  */
	if (!vcpu->nested_vcpu.current_vmxon) {
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		return false;
	}

	return true;
}

static inline void nested_copy(uintptr_t vmcs, u32 field)
{
	__vmx_vmwrite(field, nested_vmcs_read(vmcs, field));
}

static void prepare_nested_vmcs(struct vcpu *vcpu, uintptr_t vmcs)
{
	/*
	 * Here, we are called from the nested hypervisor which called us via either:
	 *	1) vmresume
	 *	2) vmlaunch
	 *
	 * In that case, the nested hypervisor is our guest, and we called it to run in
	 * emulated root mode (or it's about to start it's execution), so it processed
	 * whatever event has happened and wants us to resume control back to it's guest.
	 *
	 * Do so by setting the appropriate guest field's for that hypervisor's guest and
	 * retaining the host fields so that it can exit to us instead of the nested one.
	 */
	nested_copy(vmcs, CR0_GUEST_HOST_MASK);
	nested_copy(vmcs, CR4_GUEST_HOST_MASK);
	nested_copy(vmcs, CR0_READ_SHADOW);
	nested_copy(vmcs, CR4_READ_SHADOW);
	nested_copy(vmcs, GUEST_CR0);
	nested_copy(vmcs, GUEST_CR3);
	nested_copy(vmcs, GUEST_CR4);

	nested_copy(vmcs, GUEST_ES_BASE);
	nested_copy(vmcs, GUEST_FS_BASE);
	nested_copy(vmcs, GUEST_GS_BASE);
	nested_copy(vmcs, GUEST_SS_BASE);
	nested_copy(vmcs, GUEST_CS_BASE);
	nested_copy(vmcs, GUEST_DS_BASE);
	nested_copy(vmcs, GUEST_LDTR_BASE);
	nested_copy(vmcs, GUEST_TR_BASE);
	nested_copy(vmcs, GUEST_IDTR_BASE);
	nested_copy(vmcs, GUEST_GDTR_BASE);

	nested_copy(vmcs, GUEST_ES_LIMIT);
	nested_copy(vmcs, GUEST_FS_LIMIT);
	nested_copy(vmcs, GUEST_GS_LIMIT);
	nested_copy(vmcs, GUEST_SS_LIMIT);
	nested_copy(vmcs, GUEST_CS_LIMIT);
	nested_copy(vmcs, GUEST_DS_LIMIT);
	nested_copy(vmcs, GUEST_LDTR_LIMIT);
	nested_copy(vmcs, GUEST_IDTR_LIMIT);
	nested_copy(vmcs, GUEST_GDTR_LIMIT);

	nested_copy(vmcs, GUEST_ES_AR_BYTES);
	nested_copy(vmcs, GUEST_FS_AR_BYTES);
	nested_copy(vmcs, GUEST_GS_AR_BYTES);
	nested_copy(vmcs, GUEST_SS_AR_BYTES);
	nested_copy(vmcs, GUEST_CS_AR_BYTES);
	nested_copy(vmcs, GUEST_DS_AR_BYTES);
	nested_copy(vmcs, GUEST_LDTR_AR_BYTES);
	nested_copy(vmcs, GUEST_TR_AR_BYTES);

	if (nested_vmcs_read(vmcs, VM_ENTRY_CONTROLS) & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
		__writedr(7, nested_vmcs_read(vmcs, GUEST_DR7));
		nested_copy(vmcs, GUEST_DR7);
		nested_copy(vmcs, GUEST_IA32_DEBUGCTL);
	}

	if (nested_vmcs_read(vmcs, CPU_BASED_VM_EXEC_CONTROL) & CPU_BASED_USE_MSR_BITMAPS)
		nested_copy(vmcs, MSR_BITMAP);

	if (nested_vmcs_read(vmcs, CPU_BASED_VM_EXEC_CONTROL) & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS &&
	    nested_vmcs_read(vmcs, SECONDARY_VM_EXEC_CONTROL) & SECONDARY_EXEC_ENABLE_EPT)
		nested_copy(vmcs, EPT_POINTER);

	nested_copy(vmcs, GUEST_LINEAR_ADDRESS);
	nested_copy(vmcs, GUEST_PHYSICAL_ADDRESS);
	nested_copy(vmcs, VMCS_LINK_POINTER);
	nested_copy(vmcs, EXIT_QUALIFICATION);

	nested_copy(vmcs, GUEST_RIP);
	nested_copy(vmcs, GUEST_RFLAGS);
	nested_copy(vmcs, GUEST_SYSENTER_CS);
	nested_copy(vmcs, GUEST_SYSENTER_ESP);
	nested_copy(vmcs, GUEST_SYSENTER_EIP);

	nested_copy(vmcs, VM_ENTRY_CONTROLS);
	nested_copy(vmcs, VM_EXIT_CONTROLS);
	nested_copy(vmcs, PIN_BASED_VM_EXEC_CONTROL);
	nested_copy(vmcs, CPU_BASED_VM_EXEC_CONTROL);
	nested_copy(vmcs, SECONDARY_VM_EXEC_CONTROL);
}

static inline bool vcpu_enter_nested_guest(struct vcpu *vcpu)
{
	/*
	 * We're called from the nested hypervisor to run it's nested guest here.
	 * Do the appropriate checks then prepare the VMCS fields with the appropriate
	 * nested guest fields.
	 */
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;

	if (nested_vmcs_read(vmcs, VMCS_LINK_POINTER) != -1ULL) {
		/* TODO: VM entry fail  */
		return false;
	}

	/* FIXME  */
	prepare_nested_vmcs(vcpu, vmcs);
	return true;
}
#endif

static bool vcpu_handle_vmx(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	if (!vcpu_check_cpl(0)) {
		/* all of these instructions require CPL 0  */
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		goto out;
	}

#ifdef NESTED_VMX
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;
	u64 gpa = 0;	/* shit compiler  */
	u64 gva = 0;	/* shit compiler (x2)  */
	switch (curr_handler) {
	case EXIT_REASON_VMCLEAR:
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		gva = vcpu_read_vmx_addr(vcpu,
					 vmcs_read(EXIT_QUALIFICATION),
					 vmcs_read(VMX_INSTRUCTION_INFO),
					 &gpa,
					 PAGE_PRESENT | PAGE_WRITE);
		if (!gva)
			goto out;

		if (gpa == nested->vmxon_region) {
			vcpu_vm_fail_valid(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);
			goto out;
		}

		/* clear VMCS launch state  */
		nested->launch_state = VMCS_LAUNCH_STATE_CLEAR;
		break;
	case EXIT_REASON_VMLAUNCH:
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		if (nested->launch_state != VMCS_LAUNCH_STATE_CLEAR) {
			/* must be clear prior to call to vmlaunch  */
			vcpu_vm_fail_valid(vcpu, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
			goto out;
		}

		vcpu_enter_nested_guest(vcpu);
		break;
	case EXIT_REASON_VMPTRLD:
	{
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		gva = vcpu_read_vmx_addr(vcpu,
					 vmcs_read(EXIT_QUALIFICATION),
					 vmcs_read(VMX_INSTRUCTION_INFO),
					 &gpa,
					 PAGE_PRESENT | PAGE_WRITE);
		if (!gva)
			goto out;

		if (gpa == nested->vmxon_region) {
			vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);
			goto out;
		}

		struct vmcs *tmp = (struct vmcs *)gva;
		if (tmp->revision_id != vcpu->vmcs.revision_id) {
			vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
			goto out;
		}

		/* Clear out "Shadow" VMCS  */
		memset((void *)vmcs, 0, PAGE_SIZE);

		nested->vmcs = gva;
		nested->vmcs_region = gpa;
		break;
	}
	case EXIT_REASON_VMREAD:
	{
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		u64 exit = vmcs_read(EXIT_QUALIFICATION);
		u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);

		u64 field = ksm_read_reg(vcpu, (inst >> 28) & 15);
		u64 value = nested_vmcs_read(vmcs, field);;
		if (value == 0) {
			vcpu_vm_fail_valid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
			goto out;
		}

		if ((inst >> 10) & 1) {
			ksm_write_reg(vcpu, (inst >> 3) & 15, value);
			goto out;
		}

		gva = vcpu_read_vmx_addr(vcpu, exit, inst, &gpa, PAGE_WRITE | PAGE_PRESENT);
		if (gva == 0)
			goto out;

		VCPU_ENTER_GUEST();
		*(u64 *)gva = value;
		VCPU_EXIT_GUEST();
		break;
	}
	case EXIT_REASON_VMRESUME:
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		/* Must be launched prior to vmresume...  */
		if (nested->launch_state != VMCS_LAUNCH_STATE_LAUNCHED) {
			vcpu_vm_fail_valid(vcpu, VMXERR_VMRESUME_NONLAUNCHED_VMCS);
			goto out;
		}

		vcpu_enter_nested_guest(vcpu);
		break;
	case EXIT_REASON_VMWRITE:
	{
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		u64 exit = vmcs_read(EXIT_QUALIFICATION);
		u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);

		u64 field = ksm_read_reg(vcpu, (inst >> 28) & 15);
		if (field_ro(field)) {
			vcpu_vm_fail_valid(vcpu, VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT);
			goto out;
		}

		u64 value;
		if ((inst >> 10) & 1) {
			/* register  */
			value = ksm_read_reg(vcpu, (inst >> 3) & 15);
		} else {
			/* memory address  */
			gva = vcpu_read_vmx_addr(vcpu, exit, inst, &gpa, PAGE_PRESENT);
			if (gva == 0)
				goto out;

			VCPU_ENTER_GUEST();
			value = *(u64 *)gva;
			VCPU_EXIT_GUEST();
		}

		if (!nested_vmcs_write(vmcs, field, value)) {
			vcpu_vm_fail_valid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
			goto out;
		}

		break;
	}
	case EXIT_REASON_VMOFF:
		/* can only be executed from root  */
		if (!vcpu_nested_root_checks(vcpu))
			goto out;

		break;
	case EXIT_REASON_VMON:
	{
		if (!(vmcs_read(GUEST_CR4) & X86_CR4_VMXE)) {
			vcpu_inject_hardirq_noerr(X86_TRAP_UD);
			goto out;
		}

		const u64 required_feat = FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
		if ((nested->feat_ctl & required_feat) != required_feat) {
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			goto out;
		}

		if (nested->current_vmxon) {
			/* In root  */
			vcpu_vm_fail_valid(vcpu, VMXERR_VMXON_IN_VMX_ROOT_OPERATION);
			goto out;
		}

		gva = vcpu_read_vmx_addr(vcpu,
					 vmcs_read(EXIT_QUALIFICATION),
					 vmcs_read(VMX_INSTRUCTION_INFO),
					 &gpa,
					 PAGE_PRESENT);
		if (!gva)
			goto out;

		struct vmcs *vmxon = (struct vmcs *)gva;
		struct vmcs *ours = &vcpu->vmxon;
		if (vmxon->revision_id != ours->revision_id) {
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			goto out;
		}

		/* Mark them as inside root now  */
		nested->vmxon_region = gpa;
		nested->current_vmxon = gpa;
		nested->vmxon = true;
		break;
	}
	default:
		/* FIXME: invept/invvpid  */
		break;
	}

	/* succeeded  */
	VCPU_DEBUG("VMX instruction succeeded\n");
	vcpu_vm_succeed(vcpu);
#else
	vcpu_inject_hardirq_noerr(X86_TRAP_UD);
#endif
out:
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_cr_access(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u64 exit;
	__vmx_vmread(EXIT_QUALIFICATION, &exit);

	int cr = exit & 15;
	int reg = (exit >> 8) & 15;
	u64 *val;
	switch ((exit >> 4) & 3) {
	case 0:		/* mov to cr  */
		val = ksm_reg(vcpu, reg);
		switch (cr) {
		case 0:
			if (*val & __CR0_GUEST_HOST_MASK) {
				/* unsupported  */
				vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			} else {
				__vmx_vmwrite(GUEST_CR0, *val);
				__vmx_vmwrite(CR0_READ_SHADOW, *val);
			}
			break;
		case 3:
			__invvpid_no_global(vpid_nr());
			__vmx_vmwrite(GUEST_CR3, *val);
			break;
		case 4:
			__invvpid_single(vpid_nr());
			if (*val & __CR4_GUEST_HOST_MASK) {
#ifndef NESTED_VMX
				if (*val & X86_CR4_VMXE) {
					vcpu_inject_hardirq_noerr(X86_TRAP_GP);
					break;
		}
#endif
	}

			__vmx_vmwrite(GUEST_CR4, *val);
			__vmx_vmwrite(CR4_READ_SHADOW, *val);
			break;
		case 8:
			vcpu->cr8 = *val;
			break;
}
		break;
	case 1:		/* mov from cr  */
		val = ksm_reg(vcpu, reg);
		switch (cr) {
		case 3:
			__vmx_vmread(GUEST_CR3, val);
			break;
		case 8:
			*val = vcpu->cr8;
			break;
		}
		break;
	case 2:		/* clts  */
	{
		u64 cr0 = vmcs_read(GUEST_CR0) & ~X86_CR0_TS;
		__vmx_vmwrite(GUEST_CR0, cr0);
		__vmx_vmwrite(CR0_READ_SHADOW, cr0);
		break;
	}
	case 3:		/* lmsw  */
	{
		u64 msw = exit >> LMSW_SOURCE_DATA_SHIFT;
		u64 cr0 = vmcs_read(GUEST_CR0);

		cr0 = ((cr0 & ~(X86_CR0_MP | X86_CR0_EM | X86_CR0_TS)) |
			(msw & (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS)))
			& ~__CR0_GUEST_HOST_MASK;

		__vmx_vmwrite(GUEST_CR0, cr0);
		__vmx_vmwrite(CR0_READ_SHADOW, cr0);
		break;
	}
	default:
		break;
	}

	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_dr_access(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u64 exit = vmcs_read(EXIT_QUALIFICATION);
	int dr = exit & DEBUG_REG_ACCESS_NUM;

	/*
	 * See Intel Manual, when CR4.DE is enabled, dr4/5 cannot be used,
	 * when clear, they are aliased to 6/7.
	 * */
	u64 cr4 = vmcs_read(GUEST_CR4);
	if (cr4 & X86_CR4_DE && (dr == 4 || dr == 5)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		goto out;
	}

	if (!vcpu_check_cpl(0)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		goto out;
	}

	u64 *reg = ksm_reg(vcpu, DEBUG_REG_ACCESS_REG(exit));
	if (exit & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0:	*reg = __readdr(0); break;
		case 1: *reg = __readdr(1); break;
		case 2: *reg = __readdr(2); break;
		case 3: *reg = __readdr(3); break;
		case 4: *reg = __readdr(4); break;
		case 5: *reg = __readdr(5); break;
		case 6: *reg = __readdr(6); break;
		case 7: __vmx_vmread(GUEST_DR7, reg); break;
		}
	} else {
		switch (dr) {
		case 0: __writedr(0, *reg); break;
		case 1: __writedr(1, *reg); break;
		case 2: __writedr(2, *reg); break;
		case 3: __writedr(3, *reg); break;
		case 4: __writedr(4, *reg); break;
		case 5: __writedr(5, *reg); break;
		case 6:
			if ((*reg >> 32) != 0)
				vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			else
				__writedr(6, *reg);
			break;
		case 7:
			if ((*reg >> 32) != 0)
				vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			else
				__vmx_vmwrite(GUEST_DR7, *reg);
			break;
		}
	}

out:
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static inline u64 read_tsc_msr(void)
{
	u64 host_tsc = __rdtsc();
	u64 tsc_off;
	__vmx_vmread(TSC_OFFSET, &tsc_off);

	u64 tsc_mul;
	__vmx_vmread(TSC_MULTIPLIER, &tsc_mul);

#ifdef MINGW
	return (u64)(((unsigned __int128)host_tsc * tsc_mul) >> 48);
#else
	return (u64)MultiplyExtract128(host_tsc, tsc_mul, 48);
#endif
}

static bool vcpu_handle_msr_read(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 msr = ksm_read_reg32(vcpu, REG_CX);
	u64 val = 0;

	switch (msr) {
	case MSR_IA32_SYSENTER_CS:
		__vmx_vmread(GUEST_SYSENTER_CS, &val);
		break;
	case MSR_IA32_SYSENTER_ESP:
		__vmx_vmread(GUEST_SYSENTER_ESP, &val);
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmread(GUEST_SYSENTER_EIP, &val);
		break;
	case MSR_IA32_GS_BASE:
		__vmx_vmread(GUEST_GS_BASE, &val);
		break;
	case MSR_IA32_DEBUGCTLMSR:
		__vmx_vmread(GUEST_IA32_DEBUGCTL, &val);
		break;
	case MSR_IA32_FEATURE_CONTROL:
#ifdef NESTED_VMX
		val = vcpu->nested_vcpu.feat_ctl;
#else
		val = __readmsr(msr) & ~(FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX);
#endif
		break;
	case MSR_IA32_TSC:
		val = read_tsc_msr();
		break;
	default:
		if (msr >= MSR_IA32_VMX_BASIC && msr <= MSR_IA32_VMX_VMFUNC) {
#ifndef NESTED_VMX
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
#else
			val = __readmsr(msr);
			if (msr == MSR_IA32_VMX_PROCBASED_CTLS2)
				val &= ~(nested_unsupported_secondary | vcpu->secondary_ctl);
#endif
	}

		val = __readmsr(msr);
		break;
}

	ksm_write_reg32(vcpu, REG_AX, val);
	ksm_write_reg32(vcpu, REG_CX, val >> 32);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_msr_write(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 msr = ksm_read_reg(vcpu, REG_CX);
	u64 val = ksm_combine_reg64(vcpu, REG_AX, REG_DX);

	switch (msr) {
	case MSR_IA32_SYSENTER_CS:
		__vmx_vmwrite(GUEST_SYSENTER_CS, val);
		break;
	case MSR_IA32_SYSENTER_ESP:
		__vmx_vmwrite(GUEST_SYSENTER_ESP, val);
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmwrite(GUEST_SYSENTER_EIP, val);
		break;
	case MSR_IA32_GS_BASE:
		__vmx_vmwrite(GUEST_GS_BASE, val);
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (val & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF))
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		else
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL, val);
		break;
	case MSR_IA32_FEATURE_CONTROL:
#ifdef NESTED_VMX
		if (val & ~(FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_LMCE |
			    FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX))
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		else
			vcpu->nested_vcpu.feat_ctl = val;
#else
		if (val & (FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX))
			vcpu_inject_hardirq_noerr(X86_TRAP_UD);
#endif
		break;
	default:
		if (msr >= MSR_IA32_VMX_BASIC && msr <= MSR_IA32_VMX_VMFUNC)
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		else
			__writemsr(msr, val);
		break;
	}

	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invalid_state(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	VCPU_BUGCHECK(VCPU_BUGCHECK_GUEST_STATE, vcpu->ip, vcpu->eflags, prev_handler);
	VCPU_TRACER_END();
	return false;
}

static bool vcpu_handle_mtf(struct vcpu *vcpu)
{
	/* Monitor Trap Flag, it's not recommended to use this at all.  */
	VCPU_TRACER_START();
	vcpu_set_mtf(false);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static inline void vcpu_sync_idt(struct vcpu *vcpu, struct gdtr *idt)
{
	/*
	 * Synchronize shadow IDT with Guest's IDT, taking into account
	 * entries that we set, by simply just discarding them.
	 */
	unsigned entries = min(idt->limit, PAGE_SIZE - 1) / sizeof(struct kidt_entry64);
	struct kidt_entry64 *current = (struct kidt_entry64 *)idt->base;
	struct kidt_entry64 *shadow = (struct kidt_entry64 *)vcpu->idt.base;

	VCPU_DEBUG("Loading new IDT (new size: %d old size: %d)  Copying %d entries\n",
		   idt->limit, vcpu->idt.limit, entries);

	vcpu->idt.limit = idt->limit;
	for (unsigned n = 0; n < entries; ++n)
		if (n > X86_TRAP_VE || !idte_present(&vcpu->shadow_idt[n]))
			memcpy(&shadow[n], &current[n], sizeof(*shadow));
	vcpu_flush_idt(vcpu);
}

static bool vcpu_handle_gdt_idt_access(struct vcpu *vcpu)
{
	u64 exit;
	__vmx_vmread(VMX_INSTRUCTION_INFO, &exit);

	u64 displacement;
	__vmx_vmread(EXIT_QUALIFICATION, &displacement);

	uintptr_t base = 0;
	if (!((exit >> 27) & 1))
		base = ksm_read_reg(vcpu, (exit >> 23) & 15);

	uintptr_t index = 0;
	if (!((exit >> 22) & 1))
		index = ksm_read_reg(vcpu, (exit >> 18) & 15) << (exit & 3);

	uintptr_t addr = base + index + displacement;
	if (((exit >> 7) & 7) == 1)
		addr &= 0xFFFFFFFF;

	VCPU_DEBUG("GDT/IDT access, addr [%p] (%p, %d, %d)\n", addr, base, index, displacement);

	VCPU_ENTER_GUEST();
	struct gdtr *dt = (struct gdtr *)addr;
	switch ((exit >> 28) & 3) {
	case 0:		/* sgdt  */
		dt->limit = vmcs_read16(GUEST_GDTR_LIMIT);
		dt->base = vmcs_read(GUEST_GDTR_BASE);
		break;
	case 1:		/* sidt */
		dt->limit = vcpu->g_idt.limit;
		dt->base = vcpu->g_idt.base;
		break;
	case 2:		/* lgdt  */
		__vmx_vmwrite(GUEST_GDTR_BASE, dt->base);
		__vmx_vmwrite(GUEST_GDTR_LIMIT, dt->limit);
		break;
	case 3:		/* lidt  */
		vcpu->g_idt.base = dt->base;
		vcpu->g_idt.limit = dt->limit;
		vcpu_sync_idt(vcpu, dt);
		break;
	}
	VCPU_EXIT_GUEST();

	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_ldt_tr_access(struct vcpu *vcpu)
{
	u64 exit;
	__vmx_vmread(VMX_INSTRUCTION_INFO, &exit);

	size_t displacement;
	__vmx_vmread(EXIT_QUALIFICATION, &displacement);

	uintptr_t addr;
	if ((exit >> 10) & 1) {
		// register
		addr = (uintptr_t)ksm_reg(vcpu, (exit >> 3) & 15);
		VCPU_DEBUG("LDT/TR access, addr %p\n", addr);
	} else {
		// base
		uintptr_t base = 0;
		if (!((exit >> 27) & 1))
			base = ksm_read_reg(vcpu, (exit >> 23) & 15);

		uintptr_t index = 0;
		if (!((exit >> 22) & 1))
			index = ksm_read_reg(vcpu, (exit >> 18) & 15) << (exit & 3);

		addr = base + index + displacement;
		if (((exit >> 7) & 7) == 1)
			addr &= 0xFFFFFFFF;
		VCPU_DEBUG("LDT/TR access, addr [%p] (%p, %d, %d)\n", addr, base, index, displacement);
	}

	VCPU_ENTER_GUEST();
	u16 *selector = (u16 *)addr;
	switch ((exit >> 28) & 3) {
	case 0:		/* sldt  */
		*selector = vmcs_read16(GUEST_LDTR_SELECTOR);
		break;
	case 1:		/* str  */
		*selector = vmcs_read16(GUEST_TR_SELECTOR);
		break;
	case 2:		/* lldt  */
		__vmx_vmwrite(GUEST_LDTR_SELECTOR, *selector);
		break;
	case 3:		/* ltr  */
		__vmx_vmwrite(GUEST_TR_SELECTOR, *selector);
		break;
	}
	VCPU_EXIT_GUEST();

	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_ept_violation(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	if (!ept_handle_violation(vcpu)) {
#ifndef DBG
		if (vcpu_inject_ve(vcpu))
			return true;
#endif

		VCPU_BUGCHECK(EPT_BUGCHECK_CODE,
			      EPT_UNHANDLED_VIOLATION,
			      vcpu->ip,
			      vmcs_read(GUEST_PHYSICAL_ADDRESS));
}

	VCPU_TRACER_END();
	return true;
	}

static bool vcpu_handle_ept_misconfig(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	struct ept *ept = &vcpu->ept;
	u64 gpa = vmcs_read(GUEST_PHYSICAL_ADDRESS);
	u16 eptp = vcpu_eptp_idx(vcpu);

	uintptr_t *pte = ept_pte(ept, EPT4(ept, eptp), gpa);
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, EPT_BUGCHECK_MISCONFIG, gpa, *pte);
	return false;
}

static bool vcpu_handle_rdtscp(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 tsc_aux;
	u64 tsc = __rdtscp(&tsc_aux);

	ksm_write_reg32(vcpu, REG_AX, tsc);
	ksm_write_reg32(vcpu, REG_DX, tsc >> 32);
	ksm_write_reg32(vcpu, REG_CX, tsc_aux);
	vcpu_advance_rip(vcpu);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_wbinvd(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	__wbinvd();
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_xsetbv(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 ext = ksm_read_reg32(vcpu, REG_CX);
	u64 val = ksm_combine_reg64(vcpu, REG_AX, REG_DX);
	_xsetbv(ext, val);
	vcpu_advance_rip(vcpu);

	VCPU_TRACER_END();
	return true;
}

/* VM-exit handlers.  */
static bool(*g_handlers[]) (struct vcpu *) = {
	[EXIT_REASON_EXCEPTION_NMI] = vcpu_handle_except_nmi,
	[EXIT_REASON_EXTERNAL_INTERRUPT] = vcpu_nop,
	[EXIT_REASON_TRIPLE_FAULT] = vcpu_handle_triplefault,
	[EXIT_REASON_INIT_SIGNAL] = vcpu_nop,
	[EXIT_REASON_STARTUP_IPI] = vcpu_nop,
	[EXIT_REASON_SMI_INTERRUPT] = vcpu_nop,
	[EXIT_REASON_OTHER_SMI] = vcpu_nop,
	[EXIT_REASON_PENDING_INTERRUPT] = vcpu_nop,
	[EXIT_REASON_NMI_WINDOW] = vcpu_nop,
	[EXIT_REASON_TASK_SWITCH] = vcpu_handle_taskswitch,
	[EXIT_REASON_CPUID] = vcpu_handle_cpuid,
	[EXIT_REASON_GETSEC] = vcpu_nop,
	[EXIT_REASON_HLT] = vcpu_handle_hlt,
	[EXIT_REASON_INVD] = vcpu_handle_invd,
	[EXIT_REASON_INVLPG] = vcpu_handle_invlpg,
	[EXIT_REASON_RDPMC] = vcpu_nop,
	[EXIT_REASON_RDTSC] = vcpu_handle_rdtsc,
	[EXIT_REASON_RSM] = vcpu_nop,
	[EXIT_REASON_VMCALL] = vcpu_handle_vmcall,
	[EXIT_REASON_VMCLEAR] = vcpu_handle_vmx,
	[EXIT_REASON_VMLAUNCH] = vcpu_handle_vmx,
	[EXIT_REASON_VMPTRLD] = vcpu_handle_vmx,
	[EXIT_REASON_VMPTRST] = vcpu_handle_vmx,
	[EXIT_REASON_VMREAD] = vcpu_handle_vmx,
	[EXIT_REASON_VMRESUME] = vcpu_handle_vmx,
	[EXIT_REASON_VMWRITE] = vcpu_handle_vmx,
	[EXIT_REASON_VMOFF] = vcpu_handle_vmx,
	[EXIT_REASON_VMON] = vcpu_handle_vmx,
	[EXIT_REASON_CR_ACCESS] = vcpu_handle_cr_access,
	[EXIT_REASON_DR_ACCESS] = vcpu_handle_dr_access,
	[EXIT_REASON_IO_INSTRUCTION] = vcpu_nop,
	[EXIT_REASON_MSR_READ] = vcpu_handle_msr_read,
	[EXIT_REASON_MSR_WRITE] = vcpu_handle_msr_write,
	[EXIT_REASON_INVALID_STATE] = vcpu_handle_invalid_state,
	[EXIT_REASON_MSR_LOAD_FAIL] = vcpu_nop,
	[EXIT_REASON_UNKNOWN35] = vcpu_nop,
	[EXIT_REASON_MWAIT_INSTRUCTION] = vcpu_nop,
	[EXIT_REASON_MONITOR_TRAP_FLAG] = vcpu_handle_mtf,
	[EXIT_REASON_UNKNOWN38] = vcpu_nop,
	[EXIT_REASON_MONITOR_INSTRUCTION] = vcpu_nop,
	[EXIT_REASON_PAUSE_INSTRUCTION] = vcpu_nop,
	[EXIT_REASON_MCE_DURING_VMENTRY] = vcpu_nop,
	[EXIT_REASON_UNKNOWN42] = vcpu_nop,
	[EXIT_REASON_TPR_BELOW_THRESHOLD] = vcpu_nop,
	[EXIT_REASON_APIC_ACCESS] = vcpu_nop,
	[EXIT_REASON_EOI_INDUCED] = vcpu_nop,
	[EXIT_REASON_GDT_IDT_ACCESS] = vcpu_handle_gdt_idt_access,
	[EXIT_REASON_LDT_TR_ACCESS] = vcpu_handle_ldt_tr_access,
	[EXIT_REASON_EPT_VIOLATION] = vcpu_handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG] = vcpu_handle_ept_misconfig,
	[EXIT_REASON_INVEPT] = vcpu_handle_vmx,
	[EXIT_REASON_RDTSCP] = vcpu_handle_rdtscp,
	[EXIT_REASON_PREEMPTION_TIMER] = vcpu_nop,
	[EXIT_REASON_INVVPID] = vcpu_handle_vmx,
	[EXIT_REASON_WBINVD] = vcpu_handle_wbinvd,
	[EXIT_REASON_XSETBV] = vcpu_handle_xsetbv,
	[EXIT_REASON_APIC_WRITE] = vcpu_nop,
	[EXIT_REASON_RDRAND] = vcpu_nop,
	[EXIT_REASON_INVPCID] = vcpu_nop,
	[EXIT_REASON_VMFUNC] = vcpu_handle_vmfunc,
	[EXIT_REASON_ENCLS] = vcpu_nop,
	[EXIT_REASON_RDSEED] = vcpu_nop,
	[EXIT_REASON_PML_FULL] = vcpu_handle_pml_full,
	[EXIT_REASON_XSAVES] = vcpu_nop,
	[EXIT_REASON_XRSTORS] = vcpu_nop,
	[EXIT_REASON_PCOMMIT] = vcpu_nop
};

bool vcpu_handle_exit(u64 *regs)
{
	struct vcpu *vcpu = ksm_current_cpu();
	u64 cr8 = __readcr8();

	vcpu->gp = regs;
	vcpu->cr8 = cr8;
	__vmx_vmread(GUEST_RFLAGS, &vcpu->eflags);
	__vmx_vmread(GUEST_RIP, &vcpu->ip);
	__vmx_vmread(GUEST_RSP, &vcpu->gp[REG_SP]);

	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);
#ifdef DBG
	prev_handler = curr_handler;
#endif
	curr_handler = (u16)exit_reason;

	bool ret = false;
	u64 eflags = vcpu->eflags;
	if (curr_handler < sizeof(g_handlers) / sizeof(g_handlers[0]) &&
	    (ret = g_handlers[curr_handler](vcpu)) &&
	    (vcpu->eflags ^ eflags) != 0)
		__vmx_vmwrite(GUEST_RFLAGS, vcpu->eflags);

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		/*
		 * Mostly comes via invalid guest state, and is due to a cruical
		 * thing that happened past VM-exit, let the handler see what it does first
		 */
		VCPU_BUGCHECK(VCPU_BUGCHECK_FAILED_VMENTRY, vcpu->ip,
			      vmcs_read(EXIT_QUALIFICATION), curr_handler);
	}

	if (!ret) {
		/*
		 * It can be done here or on initialization, we do it in both...
		 * Just incase someone screws it up somehow.
		 */
		__invept_all();
		__invvpid_all();
	}

	if ((cr8 ^ vcpu->cr8) != 0)
		__writecr8(vcpu->cr8);
	return ret;
}

void vcpu_handle_fail(struct regs *regs)
{
	/*
	 * Handle failure due to either:
	 *	1) VM entry
	 *	2) vmxoff
	 */
	size_t err = 0;
	if (regs->eflags & X86_EFLAGS_ZF)
		__vmx_vmread(VM_INSTRUCTION_ERROR, &err);

	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, err, curr_handler, prev_handler);
}

