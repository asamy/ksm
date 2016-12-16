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
#include <ntddk.h>
#include <intrin.h>

#include "ksm.h"

static u16 curr_handler = 0;
static u16 prev_handler = 0;

#define dbgbreak() do {		\
	if (KD_DEBUGGER_ENABLED && !KD_DEBUGGER_NOT_PRESENT)	\
		__debugbreak();		\
} while (0)

#ifdef NESTED_VMX
/* FIXME:  Support these!  */
static const u32 nested_unsupported_primary = CPU_BASED_MOV_DR_EXITING;
static const u32 nested_unsupported_secondary = SECONDARY_EXEC_ENABLE_VMFUNC | SECONDARY_EXEC_DESC_TABLE_EXITING;

static const u32 supported_fields[] = {
	VIRTUAL_PROCESSOR_ID,
	POSTED_INTR_NV,
	EPTP_INDEX,
	GUEST_ES_SELECTOR,
	GUEST_CS_SELECTOR,
	GUEST_SS_SELECTOR,
	GUEST_DS_SELECTOR,
	GUEST_FS_SELECTOR,
	GUEST_GS_SELECTOR,
	GUEST_LDTR_SELECTOR,
	GUEST_TR_SELECTOR,
	GUEST_INTR_STATUS,
	GUEST_PML_INDEX,
	HOST_ES_SELECTOR,
	HOST_CS_SELECTOR,
	HOST_SS_SELECTOR,
	HOST_DS_SELECTOR,
	HOST_FS_SELECTOR,
	HOST_GS_SELECTOR,
	HOST_TR_SELECTOR,
	IO_BITMAP_A,
	IO_BITMAP_A_HIGH,
	IO_BITMAP_B,
	IO_BITMAP_B_HIGH,
	MSR_BITMAP,
	MSR_BITMAP_HIGH,
	VM_EXIT_MSR_STORE_ADDR,
	VM_EXIT_MSR_STORE_ADDR_HIGH,
	VM_EXIT_MSR_LOAD_ADDR,
	VM_EXIT_MSR_LOAD_ADDR_HIGH,
	VM_ENTRY_MSR_LOAD_ADDR,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH,
	PML_ADDRESS,
	PML_ADDRESS_HIGH,
	TSC_OFFSET,
	TSC_OFFSET_HIGH,
	VIRTUAL_APIC_PAGE_ADDR,
	VIRTUAL_APIC_PAGE_ADDR_HIGH,
	APIC_ACCESS_ADDR,
	APIC_ACCESS_ADDR_HIGH,
	POSTED_INTR_DESC_ADDR,
	POSTED_INTR_DESC_ADDR_HIGH,
	VM_FUNCTION_CTRL,
	VM_FUNCTION_CTRL_HIGH,
	EPT_POINTER,
	EPT_POINTER_HIGH,
	EOI_EXIT_BITMAP0,
	EOI_EXIT_BITMAP0_HIGH,
	EOI_EXIT_BITMAP1,
	EOI_EXIT_BITMAP1_HIGH,
	EOI_EXIT_BITMAP2,
	EOI_EXIT_BITMAP2_HIGH,
	EOI_EXIT_BITMAP3,
	EOI_EXIT_BITMAP3_HIGH,
	EPTP_LIST_ADDRESS,
	EPTP_LIST_ADDRESS_HIGH,
	VMREAD_BITMAP,
	VMREAD_BITMAP_HIGH,
	VMWRITE_BITMAP,
	VMWRITE_BITMAP_HIGH,
	VE_INFO_ADDRESS,
	VE_INFO_ADDRESS_HIGH,
	XSS_EXIT_BITMAP,
	XSS_EXIT_BITMAP_HIGH,
	TSC_MULTIPLIER,
	TSC_MULTIPLIER_HIGH,
	GUEST_PHYSICAL_ADDRESS,
	GUEST_PHYSICAL_ADDRESS_HIGH,
	VMCS_LINK_POINTER,
	VMCS_LINK_POINTER_HIGH,
	GUEST_IA32_DEBUGCTL,
	GUEST_IA32_DEBUGCTL_HIGH,
	GUEST_IA32_PAT,
	GUEST_IA32_PAT_HIGH,
	GUEST_IA32_EFER,
	GUEST_IA32_EFER_HIGH,
	GUEST_IA32_PERF_GLOBAL_CTRL,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH,
	GUEST_PDPTR0,
	GUEST_PDPTR0_HIGH,
	GUEST_PDPTR1,
	GUEST_PDPTR1_HIGH,
	GUEST_PDPTR2,
	GUEST_PDPTR2_HIGH,
	GUEST_PDPTR3,
	GUEST_PDPTR3_HIGH,
	GUEST_BNDCFGS,
	GUEST_BNDCFGS_HIGH,
	HOST_IA32_PAT,
	HOST_IA32_PAT_HIGH,
	HOST_IA32_EFER,
	HOST_IA32_EFER_HIGH,
	HOST_IA32_PERF_GLOBAL_CTRL,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH,
	PIN_BASED_VM_EXEC_CONTROL,
	CPU_BASED_VM_EXEC_CONTROL,
	EXCEPTION_BITMAP,
	PAGE_FAULT_ERROR_CODE_MASK,
	PAGE_FAULT_ERROR_CODE_MATCH,
	CR3_TARGET_COUNT,
	VM_EXIT_CONTROLS,
	VM_EXIT_MSR_STORE_COUNT,
	VM_EXIT_MSR_LOAD_COUNT,
	VM_ENTRY_CONTROLS,
	VM_ENTRY_MSR_LOAD_COUNT,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INSTRUCTION_LEN,
	TPR_THRESHOLD,
	SECONDARY_VM_EXEC_CONTROL,
	PLE_GAP,
	PLE_WINDOW,
	VM_INSTRUCTION_ERROR,
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INTR_ERROR_CODE,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INSTRUCTION_LEN,
	VMX_INSTRUCTION_INFO,
	GUEST_ES_LIMIT,
	GUEST_CS_LIMIT,
	GUEST_SS_LIMIT,
	GUEST_DS_LIMIT,
	GUEST_FS_LIMIT,
	GUEST_GS_LIMIT,
	GUEST_LDTR_LIMIT,
	GUEST_TR_LIMIT,
	GUEST_GDTR_LIMIT,
	GUEST_IDTR_LIMIT,
	GUEST_ES_AR_BYTES,
	GUEST_CS_AR_BYTES,
	GUEST_SS_AR_BYTES,
	GUEST_DS_AR_BYTES,
	GUEST_FS_AR_BYTES,
	GUEST_GS_AR_BYTES,
	GUEST_LDTR_AR_BYTES,
	GUEST_TR_AR_BYTES,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_SYSENTER_CS,
	VMX_PREEMPTION_TIMER_VALUE,
	HOST_IA32_SYSENTER_CS,
	CR0_GUEST_HOST_MASK,
	CR4_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	CR3_TARGET_VALUE0,
	CR3_TARGET_VALUE1,
	CR3_TARGET_VALUE2,
	CR3_TARGET_VALUE3,
	EXIT_QUALIFICATION,
	GUEST_LINEAR_ADDRESS,
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_ES_BASE,
	GUEST_CS_BASE,
	GUEST_SS_BASE,
	GUEST_DS_BASE,
	GUEST_FS_BASE,
	GUEST_GS_BASE,
	GUEST_LDTR_BASE,
	GUEST_TR_BASE,
	GUEST_GDTR_BASE,
	GUEST_IDTR_BASE,
	GUEST_DR7,
	GUEST_RSP,
	GUEST_RIP,
	GUEST_RFLAGS,
	GUEST_PENDING_DBG_EXCEPTIONS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
	HOST_CR0,
	HOST_CR3,
	HOST_CR4,
	HOST_FS_BASE,
	HOST_GS_BASE,
	HOST_TR_BASE,
	HOST_GDTR_BASE,
	HOST_IDTR_BASE,
	HOST_IA32_SYSENTER_ESP,
	HOST_IA32_SYSENTER_EIP,
	HOST_RSP,
	HOST_RIP,
};

/*
 * From XEN:
 *	include/asm-x86/hvm/vmx/vvmx.h
 *	arch/x86/hvm/vmx/vvmx.c
 *
 * Virtual VMCS layout
 *
 * Since physical VMCS layout is unknown, a custom layout is used
 * for virtual VMCS seen by guest. It occupies a 4k page, and the
 * field is offset by an 9-bit offset into u64[], The offset is as
 * follow, which means every <width, type> pair has a max of 32
 * fields available.
 *
 *             9       7      5               0
 *             --------------------------------
 *     offset: | width | type |     index     |
 *             --------------------------------
 *
 * Also, since the lower range <width=0, type={0,1}> has only one
 * field: VPID, it is moved to a higher offset (63), and leaves the
 * lower range to non-indexed field like VMCS revision.
 * -- End Xen
 *
 * Note: The VMCS encoding above is not actually the same as in
 * the sturcture, the first bit is the "access type", otherwise
 * they are all shifted 1 bit to the left.
 */
static inline u16 field_offset(u32 field)
{
	u16 index = (field >> 1) & 0x1F;
	u16 type = (field >> 10) & 3;
	u16 width = (field >> 13) & 3;

	u16 offset = index | type << 5 | width << 7;
	if (offset == 0)	/* VPID  */
		return 0x3F;

	return offset;
}

typedef enum {
	FIELD_U16 = 0,
	FIELD_U64 = 1,
	FIELD_U32 = 2,
	FIELD_NATURAL = 3,
} fwidth_t;

static inline fwidth_t field_width(u32 field)
{
	return (field >> 13) & 3;
}

static inline bool field_ro(u32 field)
{
	return ((field >> 10) & 3) == 1;
}

static inline bool field_supported(u32 field)
{
	if (field > HOST_RIP)
		return false;	/* quickie  */

	for (size_t i = 0; i < sizeof(supported_fields) / sizeof(supported_fields[0]); ++i)
		if (supported_fields[i] == field)
			return true;

	return false;
}

static inline bool __nested_vmcs_write(uintptr_t vmcs, u32 field, u64 value)
{
	u64 *s = (u64 *)vmcs;
	u16 off = field_offset(field);
	u64 v = s[off];
	switch (field_width(field)) {
	case FIELD_U16:
		v = value & 0xFFFF;
		break;
	case FIELD_U32:
		v = value & 0xFFFFFFFF;
		break;
	case FIELD_U64:
		if (field & 1) {	/* _HIGH  */
			v &= 0xFFFFFFFF;
			v |= value << 32;
			break;
		}

		/* fallthrough  */
	default:
		v = value;
		break;
	}

	s[off] = v;
	return true;
}

static inline bool __nested_vmcs_write64(uintptr_t vmcs, u32 field, u64 value)
{
	return __nested_vmcs_write(vmcs, field, (u32)value) &&
		__nested_vmcs_write(vmcs, field + 1, (u32)(value >> 32));
}

static inline bool nested_vmcs_write(uintptr_t vmcs, u32 field, u64 value)
{
	if (!field_supported(field))
		return false;

	switch (field) {
	case HOST_ES_SELECTOR:
	case HOST_CS_SELECTOR:
	case HOST_SS_SELECTOR:
	case HOST_DS_SELECTOR:
	case HOST_FS_SELECTOR:
	case HOST_GS_SELECTOR:
	case HOST_TR_SELECTOR:
		if ((value & 0xF8) == 0)
			return false;

		break;
	case CPU_BASED_VM_EXEC_CONTROL:
		if (value & nested_unsupported_primary)
			return false;

		break;
	case SECONDARY_VM_EXEC_CONTROL:
		if (value & nested_unsupported_secondary)
			return false;

		break;
	}

	return __nested_vmcs_write(vmcs, field, value);
}

static inline u64 __nested_vmcs_read(uintptr_t vmcs, u32 field)
{
	u64 *s = (u64 *)vmcs;
	u64 v = s[field_offset(field)];
	switch (field_width(field)) {
	case FIELD_U16:
		v &= 0xFFFF;
		break;
	case FIELD_U32:
		v &= 0xFFFFFFFF;
		break;
	case FIELD_U64:
		if (field & 1)	/* _HIGH  */
			v >>= 32;
		break;
	}

	return v;
}

static inline u64 __nested_vmcs_read64(uintptr_t vmcs, u32 field)
{
	return __nested_vmcs_read(vmcs, field) |
		__nested_vmcs_read(vmcs, field + 1) << 32;
}

static inline u32 __nested_vmcs_read32(uintptr_t vmcs, u32 field)
{
	return (u32)__nested_vmcs_read(vmcs, field);
}

static inline u16 __nested_vmcs_read16(uintptr_t vmcs, u32 field)
{
	return (u16)__nested_vmcs_read(vmcs, field);
}

static inline bool nested_vmcs_read(uintptr_t vmcs, u32 field, u64 *val)
{
	if (!field_supported(field))
		return false;

	*val = __nested_vmcs_read(vmcs, field);
	return true;
}
#endif

static inline int vcpu_read_cpl(void)
{
	u32 ar = vmcs_read32(GUEST_SS_AR_BYTES);
	return VMX_AR_DPL(ar);
}

static inline bool vcpu_probe_cpl(int required)
{
	return vcpu_read_cpl() <= required;
}

typedef enum {
	EXCEPTION_BENIGN,
	EXCEPTION_CONTRIBUTORY,
	EXCEPTION_PAGE_FAULT,
} except_class_t;

static inline except_class_t exception_class(u8 vec)
{
	switch (vec) {
	case X86_TRAP_PF:
		return EXCEPTION_PAGE_FAULT;
	case X86_TRAP_DE:
	case X86_TRAP_TS:
	case X86_TRAP_NP:
	case X86_TRAP_SS:
	case X86_TRAP_GP:
		return EXCEPTION_CONTRIBUTORY;
	}

	return EXCEPTION_BENIGN;
}

static inline void vcpu_pack_irq(struct pending_irq *pirq, size_t instr_len, u16 intr_type,
				 u8 vector, bool has_err, u32 ec)
{
	u32 irq = vector | intr_type | INTR_INFO_VALID_MASK;
	if (has_err)
		irq |= INTR_INFO_DELIVER_CODE_MASK;

	pirq->pending = true;
	pirq->err = ec;
	pirq->instr_len = instr_len;
	pirq->bits = irq & ~INTR_INFO_RESVD_BITS_MASK;
}

static inline void vcpu_inject_irq(struct vcpu *vcpu, size_t instr_len, u16 intr_type,
				   u8 vector, bool has_err, u32 ec)
{
	/*
	 * Queue the IRQ, no injection happens here.
	 * In case we have contributory exceptions that follow, then
	 * we overwrite the previous with the appropriate IRQ.
	 */
	struct pending_irq *pirq = &vcpu->irq;
	if (pirq->pending) {
		u8 prev_vec = pirq->bits;
		if (prev_vec == X86_TRAP_DF) {
			/* FIXME:  Triple fault  */
			dbgbreak();
			return;
		}

		except_class_t lhs = exception_class(prev_vec);
		except_class_t rhs = exception_class(vector);
		if ((lhs == EXCEPTION_CONTRIBUTORY && rhs == EXCEPTION_CONTRIBUTORY) ||
		    (lhs == EXCEPTION_PAGE_FAULT && rhs != EXCEPTION_BENIGN))
			return vcpu_pack_irq(pirq, instr_len, INTR_TYPE_HARD_EXCEPTION,
					     X86_TRAP_DF, true, 0);
	}

	return vcpu_pack_irq(pirq, instr_len, intr_type, vector, has_err, ec);
}

static inline void vcpu_inject_hardirq_noerr(struct vcpu *vcpu, u8 vector)
{
	return vcpu_inject_irq(vcpu, vmcs_read(VM_EXIT_INSTRUCTION_LEN),
			       INTR_TYPE_HARD_EXCEPTION, vector, false, 0);
}

static inline void vcpu_inject_hardirq(struct vcpu *vcpu, u8 vector, u32 err)
{
	return vcpu_inject_irq(vcpu, vmcs_read(VM_EXIT_INSTRUCTION_LEN),
			       INTR_TYPE_HARD_EXCEPTION, vector, true, err);
}

static inline void vcpu_inject_pf(struct vcpu *vcpu, u64 gla, u32 ec)
{
	__writecr2(gla);	/* XXX  */
	return vcpu_inject_irq(vcpu, 0,
			       INTR_TYPE_HARD_EXCEPTION,
			       X86_TRAP_PF,
			       true,
			       ec);
}

static inline void vcpu_advance_rip(struct vcpu *vcpu)
{
	if (vcpu->eflags & X86_EFLAGS_TF) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_DB);
		if (vcpu_probe_cpl(0)) {
			__writedr(6, __readdr(6) | DR6_BS | DR6_RTM);
			__writedr(7, __readdr(7) & ~DR7_GD);

			u64 dbg = vmcs_read64(GUEST_IA32_DEBUGCTL);
			vmcs_write64(GUEST_IA32_DEBUGCTL, dbg & ~DEBUGCTLMSR_LBR);
		}
	}

	size_t instr_len = vmcs_read(VM_EXIT_INSTRUCTION_LEN);
	vmcs_write(GUEST_RIP, vcpu->ip + instr_len);

	size_t interruptibility = vmcs_read(GUEST_INTERRUPTIBILITY_INFO);
	vmcs_write(GUEST_INTERRUPTIBILITY_INFO,
		   interruptibility & ~(GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI));
}

#ifdef NESTED_VMX
static inline u64 gva_to_gpa(struct vcpu *vcpu, uintptr_t cr3, uintptr_t gva, u32 ac)
{
	u64 *pte = __cr3_resolve_va(cr3, gva);
	u32 pgf = PGF_PRESENT;
	if (ac & PAGE_WRITE)
		pgf |= PGF_WRITE;

	if (!pte || (*pte & pgf) != pgf) {
		vcpu_inject_pf(vcpu, gva, pgf);
		return 0;
	}

	return PAGE_PA(*pte);
}

static inline bool gpa_to_hpa(struct vcpu *vcpu, u64 gpa, u64 *hpa)
{
	struct ept *ept = &vcpu->ept;
	uintptr_t *epte = ept_pte(ept, EPT4(ept, vcpu_eptp_idx(vcpu)), gpa);
	if (!(*epte & EPT_ACCESS_RW))
		return false;

	*hpa = PAGE_PA(*epte);
	return true;
}

static inline bool nested_inject_ve(struct vcpu *vcpu)
{
	/*
	 * Shouldn't really call this function at all unless
	 * "fake" injection is really required, otherwise this is going
	 * to cause a unneeded overhead.
	 */
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;

	/*
	 * First see if nested opt'd in for #VE handling, then
	 * write the required fields to whatever ve info address poitns
	 * to then inject #VE as a normal IDT injection.
	 */
	u32 secondary_ctl = __nested_vmcs_read32(vmcs, SECONDARY_VM_EXEC_CONTROL);
	if (!(secondary_ctl & SECONDARY_EXEC_ENABLE_VE))
		return false;

	u64 ve_info_addr = __nested_vmcs_read64(vmcs, VE_INFO_ADDRESS);
	if (!page_aligned(ve_info_addr))
		return false;

	u64 hpa;
	if (!gpa_to_hpa(vcpu, ve_info_addr, &hpa))
		return false;

	struct ve_except_info *info = kmap(hpa, PAGE_SIZE);
	if (!info)
		return false;

	if (info->except_mask == 0) {
		VCPU_DEBUG("Trying to inject #VE but guest opted-out.\n");
		kunmap(info, PAGE_SIZE);
		return false;
	}

	/* Set appropriate data in VE structure  */
	info->eptp = __nested_vmcs_read16(vmcs, EPTP_INDEX);
	info->except_mask = ~0UL;
	info->reason = EXIT_REASON_EPT_VIOLATION;
	info->gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	info->gla = vmcs_read(GUEST_LINEAR_ADDRESS);
	info->exit = vmcs_read(EXIT_QUALIFICATION);
	kunmap(info, PAGE_SIZE);
	vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_VE);
	return true;
}
#endif

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
	else
		instr_len = vmcs_read(VM_EXIT_INSTRUCTION_LEN);

	bool has_err = intr_info & INTR_INFO_DELIVER_CODE_MASK;
	u32 err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
	vcpu_inject_irq(vcpu, instr_len, intr_type, vector, has_err, err);

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

	uintptr_t exit = vmcs_read(EXIT_QUALIFICATION);
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

	uintptr_t addr = vmcs_read(EXIT_QUALIFICATION);
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
	/*
	 * VM functions do not cause VM exit unless:
	 *	1) funciton is not supported
	 *	2) EPTP index is too high.
	 */
	VCPU_TRACER_START();
	VCPU_DEBUG("vmfunc caused VM-exit!  func is %d eptp index is %d\n",
		   ksm_read_reg32(vcpu, REG_AX), ksm_read_reg32(vcpu, REG_CX));
	vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END()
	return true;
}

#ifdef ENABLE_PML
static bool vcpu_dump_pml(struct vcpu *vcpu)
{
	/* CPU _decrements_ PML index (i.e. from 511 to 0 then overflows to FFFF),
	 * make sure we don't have an empty table...  */
	u16 pml_index = vmcs_read16(GUEST_PML_INDEX);
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
		u64_t *epte = ept_pte(ept, EPT4(ept, eptp), gpa);
		*epte &= ~(EPT_ACCESSED | EPT_DIRTY);
	}

	/* Reset the PML index now...  */
	vmcs_write16(GUEST_PML_INDEX, pml_index);
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

#ifdef NESTED_VMX
static inline void vcpu_vm_fail_valid(struct vcpu *vcpu, size_t err)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	if (nested_has_vmcs(nested))
		__nested_vmcs_write(nested->vmcs, VM_INSTRUCTION_ERROR, err);

	vcpu->eflags |= X86_EFLAGS_ZF;
	vcpu->eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_SF | X86_EFLAGS_OF);
}
#endif

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

	uintptr_t cr3 = vmcs_read(GUEST_CR3);
	__writecr3(cr3);

	/* See __vmx_entrypoint in assembly on how this is used.  */
	ksm_write_reg(vcpu, REG_CX, ret);
	ksm_write_reg(vcpu, REG_DX, ksm_read_reg(vcpu, REG_SP));
	ksm_write_reg(vcpu, REG_AX, vcpu->eflags);
}

#ifdef EPAGE_HOOK
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
#endif

static inline void vcpu_flush_idt(struct vcpu *vcpu)
{
	vmcs_write16(GUEST_IDTR_LIMIT, vcpu->idt.limit);
	vmcs_write(GUEST_IDTR_BASE, vcpu->idt.base);
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
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		return false;
	}

	vcpu_switch_root_eptp(vcpu, vmfunc->eptp);
	return true;
}

#ifdef NESTED_VMX
static inline bool nested_has_pin(const struct nested_vcpu *nested, u32 bits)
{
	return (__nested_vmcs_read32(nested->vmcs, PIN_BASED_VM_EXEC_CONTROL) & bits) == bits;
}

static inline bool nested_has_primary(const struct nested_vcpu *nested, u32 bits)
{
	return (__nested_vmcs_read32(nested->vmcs, CPU_BASED_VM_EXEC_CONTROL) & bits) == bits;
}

static inline bool nested_has_secondary(const struct nested_vcpu *nested, u32 bits)
{
	return (__nested_vmcs_read32(nested->vmcs, SECONDARY_VM_EXEC_CONTROL) & bits) == bits;
}

static inline u32 nested_build_ar_bytes(u32 type, u32 s, u32 dpl, u32 present,
					u32 avl, u32 l, u32 db, u32 g)
{
	return type | (s << 4) | (dpl << 5) | (present << 7) |
		(avl << 12) | (l << 13) | (db << 14) | (g << 15);
}

static inline void nested_save(uintptr_t vmcs, u32 field)
{
	__nested_vmcs_write(vmcs, field, vmcs_read(field));
}

static inline void nested_save16(uintptr_t vmcs, u32 field)
{
	__nested_vmcs_write(vmcs, field, vmcs_read16(field));
}

static inline void nested_save32(uintptr_t vmcs, u32 field)
{
	__nested_vmcs_write(vmcs, field, vmcs_read32(field));
}

static inline void nested_save64(uintptr_t vmcs, u32 field)
{
	__nested_vmcs_write(vmcs, field, vmcs_read32(field));
	__nested_vmcs_write(vmcs, field + 1, vmcs_read32(field + 1));
}

static inline void nested_save_guest_state(struct nested_vcpu *nested)
{
	uintptr_t vmcs = nested->vmcs;
	nested_save(vmcs, GUEST_CR0);
	nested_save(vmcs, GUEST_CR3);
	nested_save(vmcs, GUEST_CR4);
	nested_save(vmcs, GUEST_RSP);
	nested_save(vmcs, GUEST_RIP);
	nested_save(vmcs, GUEST_RFLAGS);

	nested_save64(vmcs, GUEST_PDPTR0);
	nested_save64(vmcs, GUEST_PDPTR1);
	nested_save64(vmcs, GUEST_PDPTR2);
	nested_save64(vmcs, GUEST_PDPTR3);

	nested_save16(vmcs, GUEST_ES_SELECTOR);
	nested_save16(vmcs, GUEST_FS_SELECTOR);
	nested_save16(vmcs, GUEST_CS_SELECTOR);
	nested_save16(vmcs, GUEST_SS_SELECTOR);
	nested_save16(vmcs, GUEST_GS_SELECTOR);
	nested_save16(vmcs, GUEST_DS_SELECTOR);
	nested_save16(vmcs, GUEST_LDTR_SELECTOR);
	nested_save16(vmcs, GUEST_TR_SELECTOR);

	nested_save32(vmcs, GUEST_ES_LIMIT);
	nested_save32(vmcs, GUEST_FS_LIMIT);
	nested_save32(vmcs, GUEST_CS_LIMIT);
	nested_save32(vmcs, GUEST_SS_LIMIT);
	nested_save32(vmcs, GUEST_GS_LIMIT);
	nested_save32(vmcs, GUEST_DS_LIMIT);
	nested_save32(vmcs, GUEST_LDTR_LIMIT);
	nested_save32(vmcs, GUEST_TR_LIMIT);

	nested_save32(vmcs, GUEST_ES_AR_BYTES);
	nested_save32(vmcs, GUEST_FS_AR_BYTES);
	nested_save32(vmcs, GUEST_CS_AR_BYTES);
	nested_save32(vmcs, GUEST_GS_AR_BYTES);
	nested_save32(vmcs, GUEST_SS_AR_BYTES);
	nested_save32(vmcs, GUEST_LDTR_AR_BYTES);
	nested_save32(vmcs, GUEST_TR_AR_BYTES);

	nested_save(vmcs, GUEST_ES_BASE);
	nested_save(vmcs, GUEST_FS_BASE);
	nested_save(vmcs, GUEST_CS_BASE);
	nested_save(vmcs, GUEST_SS_BASE);
	nested_save(vmcs, GUEST_GS_BASE);
	nested_save(vmcs, GUEST_LDTR_BASE);
	nested_save(vmcs, GUEST_TR_BASE);

	nested_save16(vmcs, GUEST_IDTR_LIMIT);
	nested_save(vmcs, GUEST_IDTR_BASE);

	nested_save16(vmcs, GUEST_GDTR_LIMIT);
	nested_save(vmcs, GUEST_GDTR_BASE);

	nested_save32(vmcs, GUEST_INTERRUPTIBILITY_INFO);
	nested_save(vmcs, GUEST_PENDING_DBG_EXCEPTIONS);

	nested_save(vmcs, GUEST_SYSENTER_CS);
	nested_save(vmcs, GUEST_SYSENTER_EIP);
	nested_save(vmcs, GUEST_SYSENTER_ESP);
	nested_save64(vmcs, GUEST_BNDCFGS);

	u32 exit = __nested_vmcs_read32(vmcs, VM_EXIT_CONTROLS);
	if (exit & VM_EXIT_SAVE_DEBUG_CONTROLS) {
		nested_save(vmcs, GUEST_DR7);
		nested_save64(vmcs, GUEST_IA32_DEBUGCTL);
	}

	if (exit & VM_EXIT_LOAD_IA32_PAT)
		nested_save64(vmcs, GUEST_IA32_PAT);

	if (exit & VM_ENTRY_LOAD_IA32_EFER)
		nested_save64(vmcs, GUEST_IA32_EFER);

	if (nested_has_primary(nested, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
	    nested_has_secondary(nested, SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY))
		nested_save16(vmcs, GUEST_INTR_STATUS);
}

static inline bool nested_prepare_hypervisor(struct vcpu *vcpu, uintptr_t vmcs)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	bool secondary = nested_has_primary(nested, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
	u8 err = 0;

	err |= vmcs_write(GUEST_RIP, __nested_vmcs_read(vmcs, HOST_RIP));
	err |= vmcs_write(GUEST_RSP, __nested_vmcs_read(vmcs, HOST_RSP));
	err |= vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);

	err |= vmcs_write(CR0_GUEST_HOST_MASK, vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_GUEST_HOST_MASK, vcpu->cr4_guest_host_mask);
	err |= vmcs_write(CR0_READ_SHADOW, __nested_vmcs_read(vmcs, HOST_CR0) & ~vcpu->cr0_guest_host_mask);
	err |= vmcs_write(CR4_READ_SHADOW, __nested_vmcs_read(vmcs, HOST_CR4) & ~vcpu->cr4_guest_host_mask);

	err |= vmcs_write(GUEST_CR0, __nested_vmcs_read(vmcs, HOST_CR0));
	err |= vmcs_write(GUEST_CR4, __nested_vmcs_read(vmcs, HOST_CR4));
	err |= vmcs_write(GUEST_CR3, __nested_vmcs_read(vmcs, HOST_CR3));

	err |= vmcs_write(GUEST_SYSENTER_CS, __nested_vmcs_read(vmcs, HOST_IA32_SYSENTER_CS));
	err |= vmcs_write(GUEST_SYSENTER_EIP, __nested_vmcs_read(vmcs, HOST_IA32_SYSENTER_EIP));
	err |= vmcs_write(GUEST_SYSENTER_ESP, __nested_vmcs_read(vmcs, HOST_IA32_SYSENTER_ESP));

	err |= vmcs_write16(GUEST_ES_SELECTOR, __nested_vmcs_read16(vmcs, HOST_ES_SELECTOR));
	err |= vmcs_write16(GUEST_CS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_CS_SELECTOR));
	err |= vmcs_write16(GUEST_SS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_SS_SELECTOR));
	err |= vmcs_write16(GUEST_DS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_DS_SELECTOR));
	err |= vmcs_write16(GUEST_FS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_FS_SELECTOR));
	err |= vmcs_write16(GUEST_GS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_GS_SELECTOR));
	err |= vmcs_write16(GUEST_DS_SELECTOR, __nested_vmcs_read16(vmcs, HOST_DS_SELECTOR));
	err |= vmcs_write16(GUEST_TR_SELECTOR, __nested_vmcs_read16(vmcs, HOST_TR_SELECTOR));

	err |= vmcs_write(GUEST_IDTR_BASE, __nested_vmcs_read(vmcs, HOST_IDTR_BASE));
	err |= vmcs_write(GUEST_GDTR_BASE, __nested_vmcs_read(vmcs, HOST_GDTR_BASE));

	err |= vmcs_write(GUEST_CS_BASE, 0);
	err |= vmcs_write32(GUEST_CS_LIMIT, 0xFFFFFFFF);
	if (__nested_vmcs_read(vmcs, VM_EXIT_CONTROLS) & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		err |= vmcs_write32(GUEST_CS_AR_BYTES, nested_build_ar_bytes(11, 1, 0, 1, 0, 1, 0, 1));
	else
		err |= vmcs_write32(GUEST_CS_AR_BYTES, nested_build_ar_bytes(11, 1, 0, 1, 0, 0, 1, 0));

	const u32 ar = nested_build_ar_bytes(3, 1, 0, 1, 0, 0, 1, 1);
	err |= vmcs_write32(GUEST_ES_LIMIT, 0xFFFFFFFF);
	err |= vmcs_write(GUEST_ES_BASE, 0);
	err |= vmcs_write32(GUEST_ES_AR_BYTES, ar);

	err |= vmcs_write32(GUEST_DS_LIMIT, 0xFFFFFFFF);
	err |= vmcs_write(GUEST_DS_BASE, 0);
	err |= vmcs_write32(GUEST_DS_AR_BYTES, ar);

	err |= vmcs_write32(GUEST_SS_LIMIT, 0xFFFFFFFF);
	err |= vmcs_write(GUEST_SS_BASE, 0);
	err |= vmcs_write32(GUEST_SS_AR_BYTES, ar);

	err |= vmcs_write32(GUEST_FS_LIMIT, 0xFFFFFFFF);
	err |= vmcs_write(GUEST_FS_BASE, __nested_vmcs_read(vmcs, HOST_FS_BASE));
	err |= vmcs_write32(GUEST_FS_AR_BYTES, ar);

	err |= vmcs_write32(GUEST_GS_LIMIT, 0xFFFFFFFF);
	err |= vmcs_write(GUEST_GS_BASE, __nested_vmcs_read(vmcs, HOST_GS_BASE));
	err |= vmcs_write32(GUEST_GS_AR_BYTES, ar);

	const u32 tar = nested_build_ar_bytes(11, 0, 0, 1, 0, 0, 0, 0);
	err |= vmcs_write32(GUEST_TR_AR_BYTES, tar);
	err |= vmcs_write(GUEST_TR_BASE, __nested_vmcs_read(vmcs, HOST_TR_BASE));
	err |= vmcs_write32(GUEST_TR_LIMIT, 0x67);

	err |= vmcs_write(GUEST_DR7, DR7_FIXED_1);
	err |= vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	err |= vmcs_write64(VMCS_LINK_POINTER, -1ULL);
	err |= vmcs_write32(VM_ENTRY_CONTROLS, vcpu->entry_ctl);
	err |= vmcs_write32(VM_EXIT_CONTROLS, vcpu->exit_ctl);
	err |= vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vcpu->pin_ctl);
	err |= vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vcpu->cpu_ctl);
	err |= vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vcpu->secondary_ctl);
	err |= vmcs_write64(MSR_BITMAP, __pa(ksm.msr_bitmap));
	err |= vmcs_write64(IO_BITMAP_A, __pa(ksm.io_bitmap_a));
	err |= vmcs_write64(IO_BITMAP_B, __pa(ksm.io_bitmap_b));
	err |= vmcs_write16(VIRTUAL_PROCESSOR_ID, vpid_nr());

	vcpu_switch_root_eptp(vcpu, vcpu_eptp_idx(vcpu));
	if (err == 0) {
		__invvpid_all();
	}

	return err == 0;
}

static inline bool vcpu_enter_nested_hypervisor(struct vcpu *vcpu, u32 exit_reason)
{
	/* 
	 * Here we came from the nested hypervisor's guest, we have received an
	 * event that we can't help ourselves, so we need to throw it back to the
	 * nested hypervisor to handle it appropriately.
	 *
	 * Do so by setting the appropriate _nested_ VMCS fields and then setting
	 * "guest's RIP" to that of the nested hypervisor's RIP (Host RIP from their
	 * VMCS).
	 */
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;

	/*
	 * Mark it as left the nested hypervisor' guest, so we can know if the next
	 * vm-exit came from it and not from it's guest.
	*/
	nested_leave(nested);
	nested_save_guest_state(nested);
	if (!nested_prepare_hypervisor(vcpu, vmcs))
		return false;

	u16 handler = exit_reason;
	if (lapic_in_kernel() && handler == EXIT_REASON_EXTERNAL_INTERRUPT &&
	    __nested_vmcs_read(vmcs, VM_EXIT_CONTROLS) & VM_EXIT_ACK_INTR_ON_EXIT)
		;/* FIXME  */

	const u32 intr_mask = INTR_INFO_DELIVER_CODE_MASK | INTR_INFO_VALID_MASK;
	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	if ((intr_info & intr_mask) == intr_mask)
		nested_save(vmcs, VM_EXIT_INTR_ERROR_CODE);

	__nested_vmcs_write(vmcs, VM_EXIT_REASON, exit_reason);
	__nested_vmcs_write(vmcs, VM_EXIT_INTR_INFO, intr_info);
	__nested_vmcs_write(vmcs, EXIT_QUALIFICATION, vmcs_read(EXIT_QUALIFICATION));
	__nested_vmcs_write(vmcs, VM_EXIT_INSTRUCTION_LEN, vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
	if (handler == EXIT_REASON_GDT_IDT_ACCESS || handler == EXIT_REASON_LDT_TR_ACCESS ||
	   (handler >= EXIT_REASON_VMCLEAR && handler <= EXIT_REASON_VMON))
		__nested_vmcs_write(vmcs, VMX_INSTRUCTION_INFO, vmcs_read(VMX_INSTRUCTION_INFO));

	__nested_vmcs_write(vmcs, GUEST_LINEAR_ADDRESS, vmcs_read(GUEST_LINEAR_ADDRESS));
	__nested_vmcs_write64(vmcs, GUEST_PHYSICAL_ADDRESS, vmcs_read64(GUEST_PHYSICAL_ADDRESS));
	return true;
}
#endif

static bool vcpu_handle_vmcall(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

#ifdef NESTED_VMX
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	if (nested_entered(nested)) {
		vcpu_enter_nested_hypervisor(vcpu, EXIT_REASON_VMCALL);
		return true;
	}

	if (nested->current_vmxon) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMCALL_IN_VMX_ROOT_OPERATION);
		return true;
	}
#endif

	if (!vcpu_probe_cpl(0)) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
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
#ifdef EPAGE_HOOK
	case HYPERCALL_HOOK:
		vcpu_adjust_rflags(vcpu, vcpu_handle_hook(vcpu, (struct page_hook_info *)arg));
		break;
	case HYPERCALL_UNHOOK:
		vcpu_adjust_rflags(vcpu, vcpu_handle_unhook(vcpu, arg));
		break;
	case HYPERCALL_KPROTECT:
		vcpu_adjust_rflags(vcpu, kprotect_init_eptp(vcpu, arg));
		break;
#endif
	case HYPERCALL_VMFUNC:
		vcpu_adjust_rflags(vcpu, vcpu_emulate_vmfunc(vcpu, (struct h_vmfunc *)arg));
		break;
	default:
		VCPU_DEBUG("unsupported hypercall: %d\n", nr);
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		break;
	}

out:
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

#ifdef NESTED_VMX
static inline bool nested_can_exec_vmx(struct vcpu *vcpu)
{
	/* Make sure they are able to execute a VMX instruction:  */
	if (!vcpu_probe_cpl(0)) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		return false;
	}

	if (!(vmcs_read(GUEST_CR0) & X86_CR0_PE) ||
	    vcpu->cr4_guest_host_mask & X86_CR4_VMXE) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		return false;
	}

	if (!vcpu->nested_vcpu.current_vmxon) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		return false;
	}

	return true;
}

static inline u8 nested_copy(uintptr_t vmcs, u32 field)
{
	u8 err = vmcs_write(field, __nested_vmcs_read(vmcs, field));
	if (err)
		dbgbreak();

	return err;
}

static inline u8 nested_copy16(uintptr_t vmcs, u32 field)
{
	u8 err = vmcs_write16(field, __nested_vmcs_read16(vmcs, field));
	if (err)
		dbgbreak();

	return err;
}

static inline u8 nested_copy32(uintptr_t vmcs, u32 field)
{
	u8 err = vmcs_write32(field, __nested_vmcs_read32(vmcs, field));
	if (err)
		dbgbreak();

	return err;
}

static inline u8 nested_copy64(uintptr_t vmcs, u32 field)
{
	u8 err = vmcs_write64(field, __nested_vmcs_read64(vmcs, field));
	if (err)
		dbgbreak();

	return err;
}

static bool prepare_nested_guest(struct vcpu *vcpu, uintptr_t vmcs)
{
	/*
	 * Here, we are called from the nested hypervisor via either:
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
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	bool secondary = nested_has_primary(nested, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
	u8 err = 0;

	u64 cr0_guest_host_mask = __nested_vmcs_read(vmcs, CR0_GUEST_HOST_MASK) |
		vcpu->cr0_guest_host_mask;
	u64 cr4_guest_host_mask = __nested_vmcs_read(vmcs, CR4_GUEST_HOST_MASK) |
		vcpu->cr4_guest_host_mask;
	u64 cr0_read_shadow = __nested_vmcs_read(vmcs, CR0_READ_SHADOW) &
		~vcpu->cr0_guest_host_mask;
	u64 cr4_read_shadow = __nested_vmcs_read(vmcs, CR4_READ_SHADOW) &
		~vcpu->cr4_guest_host_mask;

	err |= vmcs_write(CR0_GUEST_HOST_MASK, cr0_guest_host_mask);
	err |= vmcs_write(CR4_GUEST_HOST_MASK, cr4_guest_host_mask);
	err |= vmcs_write(CR0_READ_SHADOW, cr0_read_shadow);
	err |= vmcs_write(CR4_READ_SHADOW, cr4_read_shadow);

	err |= nested_copy(vmcs, GUEST_CR0);
	err |= nested_copy(vmcs, GUEST_CR3);
	err |= nested_copy(vmcs, GUEST_CR4);

	err |= nested_copy(vmcs, GUEST_ES_BASE);
	err |= nested_copy(vmcs, GUEST_FS_BASE);
	err |= nested_copy(vmcs, GUEST_GS_BASE);
	err |= nested_copy(vmcs, GUEST_SS_BASE);
	err |= nested_copy(vmcs, GUEST_CS_BASE);
	err |= nested_copy(vmcs, GUEST_DS_BASE);
	err |= nested_copy(vmcs, GUEST_LDTR_BASE);
	err |= nested_copy(vmcs, GUEST_TR_BASE);
	err |= nested_copy(vmcs, GUEST_IDTR_BASE);
	err |= nested_copy(vmcs, GUEST_GDTR_BASE);

	err |= nested_copy16(vmcs, GUEST_ES_LIMIT);
	err |= nested_copy16(vmcs, GUEST_FS_LIMIT);
	err |= nested_copy16(vmcs, GUEST_GS_LIMIT);
	err |= nested_copy16(vmcs, GUEST_SS_LIMIT);
	err |= nested_copy16(vmcs, GUEST_CS_LIMIT);
	err |= nested_copy16(vmcs, GUEST_DS_LIMIT);
	err |= nested_copy16(vmcs, GUEST_LDTR_LIMIT);
	err |= nested_copy16(vmcs, GUEST_IDTR_LIMIT);
	err |= nested_copy16(vmcs, GUEST_GDTR_LIMIT);

	err |= nested_copy32(vmcs, GUEST_ES_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_FS_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_GS_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_SS_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_CS_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_DS_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_LDTR_AR_BYTES);
	err |= nested_copy32(vmcs, GUEST_TR_AR_BYTES);

	/* FIXME: We need to preserve our settings...  */
	if (nested_has_primary(nested, CPU_BASED_USE_MSR_BITMAPS))
		err |= nested_copy64(vmcs, MSR_BITMAP);

	if (nested_has_primary(nested, CPU_BASED_USE_IO_BITMAPS)) {
		err |= nested_copy64(vmcs, IO_BITMAP_A);
		err |= nested_copy64(vmcs, IO_BITMAP_B);
	}

	if (nested_has_primary(nested, CPU_BASED_TPR_SHADOW)) {
		err |= nested_copy64(vmcs, VIRTUAL_APIC_PAGE_ADDR);
		err |= nested_copy16(vmcs, TPR_THRESHOLD);
	}

	if (secondary && nested_has_secondary(nested, SECONDARY_EXEC_ENABLE_EPT)) {
		err |= nested_copy(vmcs, PAGE_FAULT_ERROR_CODE_MASK);
		err |= nested_copy(vmcs, PAGE_FAULT_ERROR_CODE_MATCH);
		err |= nested_copy64(vmcs, EPT_POINTER);
		err |= nested_copy64(vmcs, GUEST_PDPTR0);
		err |= nested_copy64(vmcs, GUEST_PDPTR1);
		err |= nested_copy64(vmcs, GUEST_PDPTR2);
		err |= nested_copy64(vmcs, GUEST_PDPTR3);

		if (nested_has_secondary(nested, SECONDARY_EXEC_ENABLE_VE))
			err |= nested_copy16(vmcs, EPTP_INDEX);
		else if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE)
			err |= vmcs_write16(EPTP_INDEX, 0);
		__invept_all();
	} else {
		err |= nested_copy(vmcs, PAGE_FAULT_ERROR_CODE_MASK);
		err |= nested_copy(vmcs, PAGE_FAULT_ERROR_CODE_MATCH);
	}

	err |= nested_copy32(vmcs, VM_ENTRY_INTR_INFO_FIELD);
	err |= nested_copy32(vmcs, VM_ENTRY_EXCEPTION_ERROR_CODE);
	err |= nested_copy32(vmcs, VM_ENTRY_INSTRUCTION_LEN);
	err |= nested_copy32(vmcs, GUEST_INTERRUPTIBILITY_INFO);
	err |= nested_copy32(vmcs, GUEST_PENDING_DBG_EXCEPTIONS);
	err |= nested_copy32(vmcs, EXCEPTION_BITMAP);

	err |= nested_copy(vmcs, GUEST_RIP);
	err |= nested_copy(vmcs, GUEST_RSP);
	err |= nested_copy(vmcs, GUEST_RFLAGS);
	err |= nested_copy(vmcs, GUEST_SYSENTER_CS);
	err |= nested_copy(vmcs, GUEST_SYSENTER_ESP);
	err |= nested_copy(vmcs, GUEST_SYSENTER_EIP);

	u32 entry = __nested_vmcs_read32(vmcs, VM_ENTRY_CONTROLS);
	if (entry & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
		err |= nested_copy(vmcs, GUEST_DR7);
		err |= nested_copy64(vmcs, GUEST_IA32_DEBUGCTL);
	}

	if (entry & VM_ENTRY_LOAD_IA32_PAT)
		err |= nested_copy64(vmcs, GUEST_IA32_PAT);

	if (entry & VM_ENTRY_LOAD_BNDCFGS)
		err |= nested_copy64(vmcs, GUEST_BNDCFGS);

	u32 ctl = vmcs_read(CPU_BASED_VM_EXEC_CONTROL);
	if (ctl & CPU_BASED_USE_TSC_OFFSETING)
		err |= nested_copy64(vmcs, TSC_OFFSET);

	err |= vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			    ctl | __nested_vmcs_read(vmcs, CPU_BASED_VM_EXEC_CONTROL));

	if (secondary) {
		ctl = vmcs_read(SECONDARY_VM_EXEC_CONTROL);
		if (ctl & SECONDARY_EXEC_ENABLE_VPID) {
			err |= nested_copy(vmcs, VIRTUAL_PROCESSOR_ID);
			__invvpid_all();
		}

		if (ctl & SECONDARY_EXEC_XSAVES)
			err |= nested_copy64(vmcs, XSS_EXIT_BITMAP);

		err |= vmcs_write(SECONDARY_VM_EXEC_CONTROL,
				  ctl | __nested_vmcs_read(vmcs, SECONDARY_VM_EXEC_CONTROL));
	}

	err |= nested_copy(vmcs, PIN_BASED_VM_EXEC_CONTROL);
	err |= nested_copy64(vmcs, VMCS_LINK_POINTER);
	return err == 0;
}

static inline bool vcpu_enter_nested_guest(struct vcpu *vcpu)
{
	/*
	 * We're called from the nested hypervisor to run it's guest here.
	 * Do the appropriate checks then prepare the VMCS fields with the appropriate
	 * nested guest fields.
	 */
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;

#define VMX_FAIL_MASK	(VMX_EXIT_REASONS_FAILED_VMENTRY | EXIT_REASON_INVALID_STATE)
	if (__nested_vmcs_read64(vmcs, VMCS_LINK_POINTER) != -1ULL) {
		vcpu_enter_nested_hypervisor(vcpu, VMX_FAIL_MASK);
		return false;
	}

	if (__nested_vmcs_read32(vmcs, VM_ENTRY_INTR_INFO_FIELD) & INTR_INFO_RESVD_BITS_MASK) {
		vcpu_vm_fail_valid(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		vcpu_enter_nested_hypervisor(vcpu, VMX_FAIL_MASK);
		return false;
	}

	nested_enter(nested);
	return prepare_nested_guest(vcpu, vmcs);
}

static inline bool nested_translate_gva(struct vcpu *vcpu, u64 gva, u64 mask, u64 *gpa, u64 *hpa)
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

	if ((*pte & mask) == mask) {
		*gpa = PAGE_PA(*pte);
		if (gpa_to_hpa(vcpu, *gpa, hpa))
			return true;
	}

fault:
	vcpu_inject_pf(vcpu, gva, ec);
	return false;
}

static inline bool is_canonical_addr(u64 gva)
{
	return (s64)gva >> 47 == (s64)gva >> 63;
}

static inline bool vcpu_parse_vmx_addr(struct vcpu *vcpu, u64 disp, u64 inst, u64 *out)
{
	if ((inst >> 10) & 1) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		return false;
	}

	u64 seg_offset = (inst >> 15) & 7;
	if (seg_offset > 5) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		return false;
	}

	uintptr_t base = 0;
	if (!((inst >> 27) & 1))
		base = ksm_read_reg(vcpu, (inst >> 23) & 15);

	uintptr_t index = 0;
	if (!((inst >> 22) & 1))
		index = ksm_read_reg(vcpu, (inst >> 18) & 15) << (inst & 3);

	uintptr_t gva = vmcs_read(GUEST_ES_BASE + (seg_offset << 1)) +
			base + index + disp;
	if (((inst >> 7) & 7) == 1)
		gva &= 0xFFFFFFFF;

	if (!is_canonical_addr(gva)) {
		vcpu_inject_hardirq(vcpu, seg_offset == 2 ? X86_TRAP_SS : X86_TRAP_GP, 0);
		return false;
	}

	*out = gva;
	return true;
}

static inline bool vcpu_read_vmx_addr(struct vcpu *vcpu, u64 gva, u64 *value)
{
	u64 gpa, hpa;
	if (!nested_translate_gva(vcpu, gva, PAGE_PRESENT, &gpa, &hpa))
		return false;

	if (!same_page(gva, gva + sizeof(value)))
		return false;

	char *v = kmap(hpa, PAGE_SIZE);
	if (!v)
		return false;

	*value = *(u64 *)(v + addr_offset(gva));
	kunmap(v, PAGE_SIZE);
	return true;
}

static inline bool vcpu_write_vmx_addr(struct vcpu *vcpu, u64 gva, u64 value)
{
	u64 gpa, hpa;
	if (!nested_translate_gva(vcpu, gva, PAGE_PRESENT | PAGE_WRITE, &gpa, &hpa))
		return false;

	if (!same_page(gva, gva + sizeof(value)))
		return false;

	char *v = kmap(hpa, PAGE_SIZE);
	if (!v)
		return false;

	*(u64 *)(v + addr_offset(gva)) = value;
	kunmap(v, PAGE_SIZE);
	return true;
}

static bool vcpu_handle_vmclear(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gva = 0;
	u64 gpa = 0;
	u64 hpa = 0;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	u32 disp = vmcs_read(EXIT_QUALIFICATION);
	u32 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_read_vmx_addr(vcpu, gva, &gpa) ||
	    !gpa_to_hpa(vcpu, gpa, &hpa)) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		goto out;
	}

	if (gpa == nested->vmxon_region) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);
		goto out;
	}

	nested->launch_state = VMCS_LAUNCH_STATE_CLEAR;
	vcpu_vm_succeed(vcpu);

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmlaunch(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	if (!nested_can_exec_vmx(vcpu) || !nested_has_vmcs(nested))
		goto out;

	if (nested->launch_state != VMCS_LAUNCH_STATE_CLEAR) {
		/* must be clear prior to call to vmlaunch  */
		vcpu_vm_fail_valid(vcpu, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
		goto out;
	}

	if (vcpu_enter_nested_guest(vcpu)) {
		nested->launch_state = VMCS_LAUNCH_STATE_LAUNCHED;
		return true;
	}

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmptrld(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gva = 0;
	u64 gpa = 0;
	u64 hpa = 0;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	u32 disp = vmcs_read(EXIT_QUALIFICATION);
	u32 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_read_vmx_addr(vcpu, gva, &gpa) ||
	    !gpa_to_hpa(vcpu, gpa, &hpa)) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		goto out;
	}

	if (gpa == nested->vmxon_region) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);
		goto out;
	}

	if (nested_has_vmcs(nested))
		nested_free_vmcs(nested);

	nested->vmcs = (uintptr_t)kmap(hpa, PAGE_SIZE);
	if (!nested->vmcs) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		goto out;
	}

	bool match = *(u32 *)nested->vmcs == (u32)__readmsr(MSR_IA32_VMX_BASIC);
	if (!match) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
		nested_free_vmcs(nested);
		goto out;
	}

	nested->vmcs_region = gpa;
	vcpu_vm_succeed(vcpu);

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmptrst(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gva = 0;
	u64 gpa = 0;
	u64 hpa = 0;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	u64 disp = vmcs_read(EXIT_QUALIFICATION);
	u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_write_vmx_addr(vcpu, gva, nested->vmcs_region))
		goto out;

	vcpu_vm_succeed(vcpu);
out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmread(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;
	u64 gva = 0;

	if (!nested_can_exec_vmx(vcpu) || vmcs == 0)
		goto err;

	u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	u32 field = ksm_read_reg(vcpu, (inst >> 28) & 15);
	u64 value;
	if (!nested_vmcs_read(vmcs, field, &value)) {
		vcpu_vm_fail_valid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto err;
	}

	if ((inst >> 10) & 1)
		ksm_write_reg(vcpu, (inst >> 3) & 15, value);
	else if (!vcpu_parse_vmx_addr(vcpu, vmcs_read(EXIT_QUALIFICATION), inst, &gva))
		goto err;
	else
		vcpu_write_vmx_addr(vcpu, gva, value);
	vcpu_vm_succeed(vcpu);

err:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmresume(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	/* Must be launched prior to vmresume...  */
	if (nested->launch_state != VMCS_LAUNCH_STATE_LAUNCHED) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMRESUME_NONLAUNCHED_VMCS);
		goto out;
	}

	if (vcpu_enter_nested_guest(vcpu))
		return true;

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmwrite(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;
	u64 gpa = 0;
	u64 gva = 0;
	u64 hpa = 0;

	if (!nested_can_exec_vmx(vcpu) || vmcs == 0)
		goto out;

	u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	u32 field = ksm_read_reg(vcpu, (inst >> 28) & 15);
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
		u64 disp = vmcs_read(EXIT_QUALIFICATION);
		if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
		    !vcpu_read_vmx_addr(vcpu, gva, &value))
			goto out;
	}

	if (!nested_vmcs_write(vmcs, field, value)) {
		vcpu_vm_fail_valid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto out;
	}

	vcpu_vm_succeed(vcpu);
out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmoff(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	uintptr_t vmcs = nested->vmcs;
	u64 gpa = 0;
	u64 gva = 0;

	/* can only be executed from root  */
	if (!nested_can_exec_vmx(vcpu))
		goto out;

	nested->vmcs_region = 0;
	nested->vmxon_region = 0;
	nested->launch_state = VMCS_LAUNCH_STATE_NONE;
	nested->feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL) & ~FEATURE_CONTROL_LOCKED;
	nested_free_vmcs(nested);
	nested_leave(nested);

	vcpu->cr4_guest_host_mask |= X86_CR4_VMXE;
	vmcs_write(CR4_GUEST_HOST_MASK, vcpu->cr4_guest_host_mask);
	vmcs_write(CR4_READ_SHADOW, vmcs_read(GUEST_CR4) & ~vcpu->cr4_guest_host_mask);
	vcpu_vm_succeed(vcpu);

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_vmon(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gpa = 0;
	u64 gva = 0;
	u64 hpa = 0;

	if (!vcpu_probe_cpl(0)) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
		goto out;
	}

	/*
	 * If CR4 guest-host mask has VMXE set, then it means
	 * the guest has never attempted to set it, see
	 * vcpu_handle_cr_access().
	 */
	if (vcpu->cr4_guest_host_mask & X86_CR4_VMXE) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		goto out;
	}

	/*
	 * We currently don't have a way to detect TXT, so we just have outside-smx treatment
	 * See if emulated feature control has the required bits set:
	 */
	const u64 required_feat = FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if ((nested->feat_ctl & required_feat) != required_feat) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		goto out;
	}

	if (nested->current_vmxon) {
		vcpu_vm_fail_valid(vcpu, VMXERR_VMXON_IN_VMX_ROOT_OPERATION);
		goto out;
	}

	u32 disp = vmcs_read(EXIT_QUALIFICATION);
	u32 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_read_vmx_addr(vcpu, gva, &gpa) ||
	    !gpa_to_hpa(vcpu, gpa, &hpa))
		goto out;

	char *tmp = kmap(hpa, PAGE_SIZE);
	if (!tmp) {
		vcpu_vm_fail_invalid(vcpu);
		goto out;
	}

	bool match = *(u32 *)tmp == (u32)__readmsr(MSR_IA32_VMX_BASIC);
	kunmap(tmp, PAGE_SIZE);
	if (!match) {
		vcpu_vm_fail_invalid(vcpu);
		goto out;
	}

	/* Mark them as inside root now  */
	nested->vmxon_region = gpa;
	nested->current_vmxon = gpa;
	vcpu_vm_succeed(vcpu);

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_invept(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gva;
	invept_t ept;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	u64 disp = vmcs_read(EXIT_QUALIFICATION);
	u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_read_vmx_addr(vcpu, gva, &ept))
		goto out;

	u32 info = vmcs_read32(VMX_INSTRUCTION_INFO);
	u32 type = ksm_read_reg32(vcpu, (info >> 28) & 15);
	u32 avail = (__readmsr(MSR_IA32_VMX_EPT_VPID_CAP) >> VMX_EPT_EXTENT_SHIFT) & 6;
	if (!(avail & (1 << type))) {
		vcpu_vm_fail_valid(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		goto out;
	}

	if (nested_has_vmcs(nested) &&
	    nested_has_primary(nested, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
	    nested_has_secondary(nested, SECONDARY_EXEC_ENABLE_EPT)) {
		u64 eptp = vmcs_read64(EPT_POINTER);
		nested_copy64(nested->vmcs, EPT_POINTER);
		__invept(type, &ept);
		vmcs_write64(EPT_POINTER, eptp);
	}

	vcpu_vm_succeed(vcpu);

out:
	vcpu_advance_rip(vcpu);
	return true;
}

static bool vcpu_handle_invvpid(struct vcpu *vcpu)
{
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	u64 gva;
	invvpid_t vpid;

	if (!nested_can_exec_vmx(vcpu))
		goto out;

	u64 disp = vmcs_read(EXIT_QUALIFICATION);
	u64 inst = vmcs_read(VMX_INSTRUCTION_INFO);
	if (!vcpu_parse_vmx_addr(vcpu, disp, inst, &gva) ||
	    !vcpu_read_vmx_addr(vcpu, gva, &vpid))
		goto out;

	u32 info = vmcs_read32(VMX_INSTRUCTION_INFO);
	u32 type = ksm_read_reg32(vcpu, (info >> 28) & 15);
	u32 avail = (__readmsr(MSR_IA32_VMX_EPT_VPID_CAP) >> VMX_VPID_EXTENT_SHIFT) & 7;
	if (!(avail & (1 << type))) {
		vcpu_vm_fail_valid(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		goto out;
	}

	if (nested_has_vmcs(nested) &&
	    nested_has_primary(nested, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
	    nested_has_secondary(nested, SECONDARY_EXEC_ENABLE_VPID)) {
		u16 old = vmcs_read16(VIRTUAL_PROCESSOR_ID);
		nested_copy16(nested->vmcs, VIRTUAL_PROCESSOR_ID);
		__invvpid(type, &vpid);
		vmcs_write16(VIRTUAL_PROCESSOR_ID, old);
	}

	vcpu_vm_succeed(vcpu);
out:
	vcpu_advance_rip(vcpu);
	return true;
}
#else
static bool vcpu_handle_vmx(struct vcpu *vcpu)
{
	VCPU_TRACER_START();
	vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_UD);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}
#endif

static bool vcpu_handle_cr_access(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	uintptr_t *val;
	int cr = exit & 15;
	int reg = (exit >> 8) & 15;

	switch ((exit >> 4) & 3) {
	case 0:		/* mov to cr  */
		val = ksm_reg(vcpu, reg);
		switch (cr) {
		case 0:
			if (*val & vcpu->cr0_guest_host_mask) {
				/* unsupported  */
				vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
			} else {
				vmcs_write(GUEST_CR0, *val);
				vmcs_write(CR0_READ_SHADOW, *val);
			}
			break;
		case 3:
			__invvpid_no_global(vpid_nr());
			vmcs_write(GUEST_CR3, *val);
			break;
		case 4:
			__invvpid_single(vpid_nr());
			if (*val & vcpu->cr4_guest_host_mask) {
#ifdef NESTED_VMX
				if (!(*val & (vcpu->cr4_guest_host_mask & ~X86_CR4_VMXE))) {
					vcpu->cr4_guest_host_mask &= ~X86_CR4_VMXE;
					vmcs_write(CR4_GUEST_HOST_MASK, vcpu->cr4_guest_host_mask);
					vmcs_write(CR4_READ_SHADOW,
						   vmcs_read(CR4_READ_SHADOW) & ~vcpu->cr4_guest_host_mask);
					vmcs_write(GUEST_CR4, *val);
					break;
				}
#endif

				vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
			} else {
				vmcs_write(GUEST_CR4, *val);
				vmcs_write(CR4_READ_SHADOW, *val);
			}

			break;
		case 8:
			__lapic_write((u64)vcpu->vapic_page, APIC_TASKPRI, *val);
			break;
		}
		break;
	case 1:		/* mov from cr  */
		val = ksm_reg(vcpu, reg);
		switch (cr) {
		case 3:
			*val = vmcs_read(GUEST_CR3);
			break;
		case 8:
			*val = __lapic_read((u64)vcpu->vapic_page, APIC_TASKPRI);
			break;
		}
		break;
	case 2:		/* clts  */
	{
		uintptr_t cr0 = vmcs_read(GUEST_CR0) & ~X86_CR0_TS;
		vmcs_write(GUEST_CR0, cr0);
		vmcs_write(CR0_READ_SHADOW, cr0);
		break;
	}
	case 3:		/* lmsw  */
	{
		uintptr_t msw = exit >> LMSW_SOURCE_DATA_SHIFT;
		uintptr_t cr0 = vmcs_read(GUEST_CR0);

		cr0 = (cr0 & ~(X86_CR0_MP | X86_CR0_EM | X86_CR0_TS)) |
			(msw & (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS));

		vmcs_write(GUEST_CR0, cr0);
		vmcs_write(CR0_READ_SHADOW, cr0);
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

	uintptr_t exit = vmcs_read(EXIT_QUALIFICATION);
	int dr = exit & DEBUG_REG_ACCESS_NUM;

	/*
	 * See Intel Manual, when CR4.DE is enabled, dr4/5 cannot be used,
	 * when clear, they are aliased to 6/7.
	 */
	uintptr_t cr4 = vmcs_read(GUEST_CR4);
	if (cr4 & X86_CR4_DE && (dr == 4 || dr == 5)) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		goto out;
	}

	if (!vcpu_probe_cpl(0)) {
		vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		goto out;
	}

	uintptr_t *reg = ksm_reg(vcpu, DEBUG_REG_ACCESS_REG(exit));
	if (exit & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0:	*reg = __readdr(0); break;
		case 1: *reg = __readdr(1); break;
		case 2: *reg = __readdr(2); break;
		case 3: *reg = __readdr(3); break;
		case 4: *reg = __readdr(4); break;
		case 5: *reg = __readdr(5); break;
		case 6: *reg = __readdr(6); break;
		case 7: *reg = vmcs_read(GUEST_DR7); break;
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
				vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
			else
				__writedr(6, *reg);
			break;
		case 7:
			if ((*reg >> 32) != 0)
				vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
			else
				vmcs_write(GUEST_DR7, *reg);
			break;
		}
	}

out:
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_io_port(struct vcpu *vcpu)
{
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	u64 *addr = ksm_reg(vcpu, REG_AX);
	if (exit & 16) {
		/* string  */
		addr = (u64 *)ksm_read_reg(vcpu, REG_SI);
		if (exit & 8)	/* in?  */
			addr = (u64 *)ksm_read_reg(vcpu, REG_DI);
	}

	u16 port = exit >> 16;
	u32 size = (exit & 7) + 1;
	u32 count = 1;
	if (exit & 32)
		count = ksm_read_reg32(vcpu, REG_CX);

	/* Should really just run the fucking instruction...  */
	VCPU_ENTER_GUEST();

	const char *type = "in";
	if (exit & 8) {
		if (exit & 16) {
			switch (size) {
			case 1: __inbytestring(port, (u8 *)addr, count); break;
			case 2: __inwordstring(port, (u16 *)addr, count); break;
			case 4: __indwordstring(port, (u32 *)addr, count); break;
			}
		} else {
			switch (size) {
			case 1: *(u8 *)addr = __inbyte(port); break;
			case 2: *(u16 *)addr = __inword(port); break;
			case 4: *(u32 *)addr = __indword(port); break;
			}
		}
	} else {
		type = "out";
		if (exit & 16) {
			switch (size) {
			case 1: __outbytestring(port, (u8 *)addr, count); break;
			case 2: __outwordstring(port, (u16 *)addr, count); break;
			case 4: __outdwordstring(port, (u32 *)addr, count); break;
			}
		} else {
			switch (size) {
			case 1: __outbyte(port, *(u8 *)addr); break;
			case 2: __outword(port, *(u16 *)addr); break;
			case 4: __outdword(port, *(u32 *)addr); break;
			}
		}
	}

	if (exit & 16) {
		/*
		* Update register:
		*	If the DF (direction flag) is set, decrement, otherwise
		*	increment.
		*
		* For in the register is RDI, for out it's RSI.
		*/
		u64 *reg = ksm_reg(vcpu, (exit & 8) ? REG_DI : REG_SI);
		if (vcpu->eflags & X86_EFLAGS_DF)
			*reg -= count * size;
		else
			*reg += count * size;

		if (exit & 32)
			ksm_write_reg(vcpu, REG_CX, 0);
	}

	VCPU_DEBUG("%s: port: 0x%X, addr: %p [0x%X] (str: %d, count: %d, size: %d)\n",
		   type, port, addr, *addr, exit & 16, count, size);
	VCPU_EXIT_GUEST();

	vcpu_advance_rip(vcpu);
	return true;
}

static inline u64 read_tsc_msr(void)
{
	u64 host_tsc = __rdtsc();
	u64 tsc_off = vmcs_read64(TSC_OFFSET);
	u64 tsc_mul = vmcs_read64(TSC_MULTIPLIER);

#ifndef _MSC_VER
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
	case MSR_IA32_DEBUGCTLMSR:
		val = vmcs_read64(GUEST_IA32_DEBUGCTL);
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
			vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
#else
			val = __readmsr(msr);
			switch (msr) {
			case MSR_IA32_VMX_PROCBASED_CTLS:
			case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
				val &= ~((u64)nested_unsupported_primary << 32);
				break;
			case MSR_IA32_VMX_PROCBASED_CTLS2:
				val &= ~((u64)nested_unsupported_secondary << 32);
				break;
			}
#endif
		} else if (msr >= 0x800 && msr <= 0x83F) {
			/* x2APIC  */
			u32 offset = (msr - 0x800) * 0x10;
			if (msr == 0x830)	/* ICR special case  */
				val = __lapic_read64((u64)vcpu->vapic_page, offset);
			else
				val = __lapic_read((u64)vcpu->vapic_page, offset);
		} else {
			/* XXX  */
			val = __readmsr(msr);
		}

		break;
	}

	ksm_write_reg32(vcpu, REG_AX, val);
	ksm_write_reg32(vcpu, REG_DX, val >> 32);
	vcpu_advance_rip(vcpu);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_msr_write(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 msr = ksm_read_reg32(vcpu, REG_CX);
	u64 val = ksm_combine_reg64(vcpu, REG_AX, REG_DX);

	switch (msr) {
	case MSR_IA32_DEBUGCTLMSR:
		if (val & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF))
			vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		else
			vmcs_write64(GUEST_IA32_DEBUGCTL, val);
		break;
	case MSR_IA32_FEATURE_CONTROL:
#ifdef NESTED_VMX
		vcpu->nested_vcpu.feat_ctl = val;
#else
		if (val & ~(FEATURE_CONTROL_LOCKED |
			    FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX |
			    FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX))
			__writemsr(MSR_IA32_FEATURE_CONTROL, val);
#endif
		break;
	default:
		if (msr >= MSR_IA32_VMX_BASIC && msr <= MSR_IA32_VMX_VMFUNC) {
			/* VMX MSRs are readonly.  */
			vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
		} else if (msr >= 0x800 && msr <= 0x83F) {
			/* x2APIC   */
			u32 offset = (msr - 0x800) * 0x10;
			switch (msr) {
			case 0x803:	/* APIC version register  */
			case 0x80A:	/* Processor Priority Register  */
			case 0x80D:	/* Logical Destination Register  */
			case 0x839:	/* APIC Timer: Current count register  */
			case 0x83F:	/* Self IPI  */
				vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
				break;
			case 0x830:
				/* ICR special case: 64-bit write:  */
				__lapic_write64((u64)vcpu->vapic_page, offset, val);
				break;
			default:
				if ((val >> 32) != 0 || (msr >= 0x810 && msr <= 0x827)) /* ISR through IRR  */
					vcpu_inject_hardirq(vcpu, X86_TRAP_GP, 0);
				else
					__lapic_write((u64)vcpu->vapic_page, offset, val);
				break;
			}
		} else {
			/* XXX  */
			__writemsr(msr, val);
		}

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

static bool vcpu_handle_tpr_threshold(struct vcpu *vcpu)
{
	/* should maybe congratulate them or something.  */
	VCPU_DEBUG("!!! TPR below threshold\n");
	return true;
}

static bool vcpu_handle_apic_access(struct vcpu *vcpu)
{
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	u16 offset = exit & APIC_ACCESS_OFFSET;
	u32 type = exit & APIC_ACCESS_TYPE;

	VCPU_DEBUG("!!! APIC access using offset 0x%04X and type 0x%X\n",
		   offset, type);
	return true;
}

static bool vcpu_handle_eoi_induced(struct vcpu *vcpu)
{
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	u16 vector = exit & 0xFFF;

	VCPU_DEBUG("!!! EOI induced, vector: 0x%04X\n", vector);
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
	size_t info = vmcs_read(VMX_INSTRUCTION_INFO);
	size_t disp = vmcs_read(EXIT_QUALIFICATION);
	size_t base = 0;
	if (!((info >> 27) & 1))
		base = ksm_read_reg(vcpu, (info >> 23) & 15);

	size_t index = 0;
	if (!((info >> 22) & 1))
		index = ksm_read_reg(vcpu, (info >> 18) & 15) << (info & 3);

	size_t addr = base + index + disp;
	if (((info >> 7) & 7) == 1)
		addr &= 0xFFFFFFFF;

	VCPU_DEBUG("GDT/IDT access, addr [%p] (%p, %d, %d)\n", addr, base, index, disp);
	VCPU_ENTER_GUEST();
	struct gdtr *dt = (struct gdtr *)addr;
	switch ((info >> 28) & 3) {
	case 0:		/* sgdt  */
		dt->limit = vmcs_read16(GUEST_GDTR_LIMIT);
		dt->base = vmcs_read(GUEST_GDTR_BASE);
		break;
	case 1:		/* sidt */
		dt->limit = vcpu->g_idt.limit;
		dt->base = vcpu->g_idt.base;
		break;
	case 2:		/* lgdt  */
		vmcs_write16(GUEST_GDTR_LIMIT, dt->limit);
		vmcs_write(GUEST_GDTR_BASE, dt->base);
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
	size_t info = vmcs_read(VMX_INSTRUCTION_INFO);
	size_t disp = vmcs_read(EXIT_QUALIFICATION);

	size_t addr;
	if ((info >> 10) & 1) {
		// register
		addr = (uintptr_t)ksm_reg(vcpu, (info >> 3) & 15);
		VCPU_DEBUG("LDT/TR access, addr %p\n", info);
	} else {
		// base
		size_t base = 0;
		if (!((info >> 27) & 1))
			base = ksm_read_reg(vcpu, (info >> 23) & 15);

		size_t index = 0;
		if (!((info >> 22) & 1))
			index = ksm_read_reg(vcpu, (info >> 18) & 15) << (info & 3);

		addr = base + index + disp;
		if (((info >> 7) & 7) == 1)
			addr &= 0xFFFFFFFF;

		VCPU_DEBUG("LDT/TR access, addr [%p] (%p, %d, %d)\n", addr, base, index, disp);
	}

	VCPU_ENTER_GUEST();
	u16 *selector = (u16 *)addr;
	switch ((info >> 28) & 3) {
	case 0:		/* sldt  */
		*selector = vmcs_read16(GUEST_LDTR_SELECTOR);
		break;
	case 1:		/* str  */
		*selector = vmcs_read16(GUEST_TR_SELECTOR);
		break;
	case 2:		/* lldt  */
		vmcs_write16(GUEST_LDTR_SELECTOR, *selector);
		break;
	case 3:		/* ltr  */
		vmcs_write16(GUEST_TR_SELECTOR, *selector);
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
#ifdef NESTED_VMX
		struct nested_vcpu *nested = &vcpu->nested_vcpu;
		if (nested->launch_state == VMCS_LAUNCH_STATE_LAUNCHED &&
		    nested_has_secondary(&vcpu->nested_vcpu, SECONDARY_EXEC_ENABLE_EPT) &&
		    (nested_inject_ve(vcpu) ||
		     vcpu_enter_nested_hypervisor(vcpu, EXIT_REASON_EPT_VIOLATION)))
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

	uintptr_t *epte = ept_pte(ept, EPT4(ept, eptp), gpa);
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, EPT_BUGCHECK_MISCONFIG, gpa, *epte);
	return false;
}

static bool vcpu_handle_rdtscp(struct vcpu *vcpu)
{
	VCPU_TRACER_START();

	u32 tsc_aux;
	u64 tsc = __rdtscp((unsigned int *)&tsc_aux);

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

static bool vcpu_handle_apic_write(struct vcpu *vcpu)
{
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	u16 offset = exit & 0xFF0;

	VCPU_DEBUG("!!! APIC write at offset 0x%04X\n", offset);
	return true;
}

#ifdef NESTED_VMX
static inline bool nested_can_handle_cr(const struct nested_vcpu *nested)
{
	/*
	 * In the CR access, we need to check if the cr0/cr4
	 * guest host mask matches their's, if so, then they handle it.
	 *
	 * For CR3, if any of the target cr3 values set match the one
	 * being set, then that means they don't want it, otherwise see
	 * if they have cr3-exiting.
	 */
	struct vcpu *vcpu = container_of(nested, struct vcpu, nested_vcpu);
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	uintptr_t vmcs = nested->vmcs;

	switch ((exit >> 4) & 3) {
	case 0:		/* mov to cr  */
		switch (exit & 15) {
		case 0:
		{
			u64 mask = __nested_vmcs_read(vmcs, CR0_GUEST_HOST_MASK);
			u64 shadow = __nested_vmcs_read(vmcs, CR0_READ_SHADOW);
			u64 val = ksm_read_reg(vcpu, (exit >> 8) & 15);
			return mask & (val ^ shadow);
		}
		case 3:
		{
			u64 val = ksm_read_reg(vcpu, (exit >> 8) & 15);
			u32 count = __nested_vmcs_read(vmcs, CR3_TARGET_COUNT);
			for (u32 i = 0; i < count; i++)
				if (__nested_vmcs_read(vmcs, CR3_TARGET_VALUE0 + i * 2) == val)
					return false;

			return nested_has_primary(nested, CPU_BASED_CR3_LOAD_EXITING);
		}
		case 4:
		{
			u64 mask = __nested_vmcs_read(vmcs, CR4_GUEST_HOST_MASK);
			u64 shadow = __nested_vmcs_read(vmcs, CR4_READ_SHADOW);
			u64 val = ksm_read_reg(vcpu, (exit >> 8) & 15);
			return mask & (val ^ shadow);
		}
		case 8:
			return nested_has_primary(nested, CPU_BASED_CR8_LOAD_EXITING);
		}
		break;
	case 1:		/* mov from cr  */
		switch (exit & 15) {
		case 3:
			return nested_has_primary(nested, CPU_BASED_CR3_STORE_EXITING);
		case 8:
			return nested_has_primary(nested, CPU_BASED_CR8_STORE_EXITING);
		}
		break;
	case 2:		/* clts  */
	{
		u64 mask = __nested_vmcs_read(vmcs, CR0_GUEST_HOST_MASK);
		u64 shadow = __nested_vmcs_read(vmcs, CR0_READ_SHADOW);
		return mask & X86_CR0_TS && shadow & X86_CR0_TS;
	}
	case 3:		/* lmsw  */
	{
		u64 mask = __nested_vmcs_read(vmcs, CR0_GUEST_HOST_MASK);
		u64 shadow = __nested_vmcs_read(vmcs, CR0_READ_SHADOW);
		u64 val = ksm_read_reg(vcpu, (exit >> 8) & 15);
		return (mask & (X86_CR0_PE | X86_CR0_MP) & (val ^ shadow)) ||
			(mask & X86_CR0_PE && !(shadow & X86_CR0_PE) && val & X86_CR0_PE);
	}
	}

	return false;
}

static inline bool nested_can_handle_io(const struct nested_vcpu *nested)
{
	struct vcpu *vcpu = container_of(nested, struct vcpu, nested_vcpu);
	uintptr_t vmcs = nested->vmcs;
	u32 exit = vmcs_read32(EXIT_QUALIFICATION);
	u16 port = exit;
	u16 size = (exit & 7) + 1;
	u64 bitmap = ~0ULL;
	u64 last_bitmap = ~0ULL;
	u8 byte = -1;

	while (size > 0) {
		if (port < 0x8000)
			bitmap = __nested_vmcs_read(vmcs, IO_BITMAP_A);
		else if (port < 0x10000)
			bitmap = __nested_vmcs_read(vmcs, IO_BITMAP_B);
		else
			return true;

		bitmap += (port & 0x7FFF) >> 3;
		if (last_bitmap != bitmap) {
			u64 hpa;
			if (!gpa_to_hpa(vcpu, bitmap, &hpa))
				return false;

			char *v = kmap(hpa, PAGE_SIZE);
			if (!v)
				return false;

			byte = *(u8 *)(v + addr_offset(bitmap));
			kunmap(v, PAGE_SIZE);
		}

		if ((byte >> (port & 7)) & 1)
			return true;

		last_bitmap = bitmap;
		++port;
		--size;
	}

	return false;
}

static inline bool nested_can_handle_msr(const struct nested_vcpu *nested, bool write)
{
	struct vcpu *vcpu = container_of(nested, struct vcpu, nested_vcpu);
	u32 msr = ksm_read_reg32(vcpu, REG_CX);
	u64 gpa = __nested_vmcs_read(nested->vmcs, MSR_BITMAP);
	u64 hpa;
	if (!gpa_to_hpa(vcpu, gpa, &hpa))
		return false;

	char *bitmap = kmap(hpa, PAGE_SIZE);
	if (!bitmap)
		return false;

	if (write)
		bitmap += 2048;

	if (msr >= 0xc0000000) {
		msr -= 0xc0000000;
		bitmap += 1024;
	}

	bool ret = ((*(u8 *)(bitmap + msr / 8)) >> (msr % 8)) & 1;
	kunmap(bitmap, PAGE_SIZE);
	return ret;
}

static inline bool nested_can_handle(const struct nested_vcpu *nested, u32 exit_reason)
{
	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY)
		return true;

	/*
	 * Here we check whether the nested hypervisor can actually handle
	 * the exit (e.g. it was not set unconditionally by us), exit reasons
	 * such as msr read/write, cr, io instr, etc...  are usually manipulated
	 * by us, and the nested hypervisor has no idea, so we need to check if
	 * we should be handling it on behalf or not.
	 *
	 * Unconditional exit reasons (cpuid, invd, triple fault, vm instructions, ...)
	 * are always passed to the nested hypervisor.
	 */
	u16 handler = exit_reason;
	switch (handler) {
	case EXIT_REASON_TRIPLE_FAULT:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_TASK_SWITCH:
	case EXIT_REASON_INVD:
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMOFF:
	case EXIT_REASON_VMON:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_EOI_INDUCED:
	case EXIT_REASON_INVALID_STATE:
	case EXIT_REASON_MCE_DURING_VMENTRY:
		/* unconditional exit reasons always exit to nested  */
		return true;
	case EXIT_REASON_APIC_ACCESS:
		return nested_has_secondary(nested, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		return nested_has_primary(nested, CPU_BASED_TPR_SHADOW);
	case EXIT_REASON_HLT:
		return nested_has_primary(nested, CPU_BASED_HLT_EXITING);
	case EXIT_REASON_PENDING_INTERRUPT:
		return nested_has_primary(nested, CPU_BASED_VIRTUAL_INTR_PENDING);
	case EXIT_REASON_NMI_WINDOW:
		return nested_has_primary(nested, CPU_BASED_VIRTUAL_NMI_PENDING);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return true;
	case EXIT_REASON_INVLPG:
		return nested_has_primary(nested, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_CR_ACCESS:
		return nested_can_handle_cr(nested);
	case EXIT_REASON_DR_ACCESS:
		return nested_has_primary(nested, CPU_BASED_MOV_DR_EXITING);
	case EXIT_REASON_IO_INSTRUCTION:
		if (!nested_has_primary(nested, CPU_BASED_USE_IO_BITMAPS))
			return nested_has_primary(nested, CPU_BASED_UNCOND_IO_EXITING);

		return nested_can_handle_io(nested);
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
		if (!nested_has_primary(nested, CPU_BASED_USE_MSR_BITMAPS))
			return false;

		return nested_can_handle_msr(nested, handler == EXIT_REASON_MSR_WRITE);
	case EXIT_REASON_RDPMC:
		return nested_has_primary(nested, CPU_BASED_RDPMC_EXITING);
	case EXIT_REASON_RDTSC:
	case EXIT_REASON_RDTSCP:
		return nested_has_primary(nested, CPU_BASED_RDTSC_EXITING);
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return nested_has_primary(nested, CPU_BASED_PAUSE_EXITING) ||
			nested_has_secondary(nested, SECONDARY_EXEC_PAUSE_LOOP_EXITING);
	case EXIT_REASON_EPT_VIOLATION:
		/* TODO: This needs some serious fixes  */
		return true;
	case EXIT_REASON_EPT_MISCONFIG:
		return true;
	case EXIT_REASON_WBINVD:
		return nested_has_secondary(nested, SECONDARY_EXEC_WBINVD_EXITING);
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return nested_has_primary(nested, CPU_BASED_MWAIT_EXITING);
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		return nested_has_primary(nested, CPU_BASED_MONITOR_TRAP_FLAG);
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return nested_has_primary(nested, CPU_BASED_MONITOR_EXITING);
	case EXIT_REASON_ENCLS:
		return nested_has_secondary(nested, SECONDARY_EXEC_ENABLE_ENCLS_EXITING);
	case EXIT_REASON_GDT_IDT_ACCESS:
	case EXIT_REASON_LDT_TR_ACCESS:
		return nested_has_secondary(nested, SECONDARY_EXEC_DESC_TABLE_EXITING);
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
		return nested_has_secondary(nested, SECONDARY_EXEC_XSAVES);
	}

	return true;
}
#endif

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
#ifdef NESTED_VMX
	[EXIT_REASON_VMCLEAR] = vcpu_handle_vmclear,
	[EXIT_REASON_VMLAUNCH] = vcpu_handle_vmlaunch,
	[EXIT_REASON_VMPTRLD] = vcpu_handle_vmptrld,
	[EXIT_REASON_VMPTRST] = vcpu_handle_vmptrst,
	[EXIT_REASON_VMREAD] = vcpu_handle_vmread,
	[EXIT_REASON_VMRESUME] = vcpu_handle_vmresume,
	[EXIT_REASON_VMWRITE] = vcpu_handle_vmwrite,
	[EXIT_REASON_VMOFF] = vcpu_handle_vmoff,
	[EXIT_REASON_VMON] = vcpu_handle_vmon,
	[EXIT_REASON_INVEPT] = vcpu_handle_invept,
	[EXIT_REASON_INVVPID] = vcpu_handle_invvpid,
#else
	[EXIT_REASON_VMCLEAR] = vcpu_handle_vmx,
	[EXIT_REASON_VMLAUNCH] = vcpu_handle_vmx,
	[EXIT_REASON_VMPTRLD] = vcpu_handle_vmx,
	[EXIT_REASON_VMPTRST] = vcpu_handle_vmx,
	[EXIT_REASON_VMREAD] = vcpu_handle_vmx,
	[EXIT_REASON_VMRESUME] = vcpu_handle_vmx,
	[EXIT_REASON_VMWRITE] = vcpu_handle_vmx,
	[EXIT_REASON_VMOFF] = vcpu_handle_vmx,
	[EXIT_REASON_VMON] = vcpu_handle_vmx,
	[EXIT_REASON_INVEPT] = vcpu_handle_vmx,
	[EXIT_REASON_INVVPID] = vcpu_handle_vmx,
#endif
	[EXIT_REASON_CR_ACCESS] = vcpu_handle_cr_access,
	[EXIT_REASON_DR_ACCESS] = vcpu_handle_dr_access,
	[EXIT_REASON_IO_INSTRUCTION] = vcpu_handle_io_port,
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
	[EXIT_REASON_TPR_BELOW_THRESHOLD] = vcpu_handle_tpr_threshold,
	[EXIT_REASON_APIC_ACCESS] = vcpu_handle_apic_access,
	[EXIT_REASON_EOI_INDUCED] = vcpu_handle_eoi_induced,
	[EXIT_REASON_GDT_IDT_ACCESS] = vcpu_handle_gdt_idt_access,
	[EXIT_REASON_LDT_TR_ACCESS] = vcpu_handle_ldt_tr_access,
	[EXIT_REASON_EPT_VIOLATION] = vcpu_handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG] = vcpu_handle_ept_misconfig,
#ifndef NESTED_VMX
	[EXIT_REASON_INVEPT] = vcpu_handle_vmx,
#endif
	[EXIT_REASON_RDTSCP] = vcpu_handle_rdtscp,
	[EXIT_REASON_PREEMPTION_TIMER] = vcpu_nop,
#ifndef NESTED_VMX
	[EXIT_REASON_INVVPID] = vcpu_handle_vmx,
#endif
	[EXIT_REASON_WBINVD] = vcpu_handle_wbinvd,
	[EXIT_REASON_XSETBV] = vcpu_handle_xsetbv,
	[EXIT_REASON_APIC_WRITE] = vcpu_handle_apic_write,
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
	struct pending_irq *irq = &vcpu->irq;
	bool ret = true;

	vcpu->gp = regs;
	vcpu->gp[REG_SP] = vmcs_read(GUEST_RSP);
	vcpu->eflags = vmcs_read(GUEST_RFLAGS);
	vcpu->ip = vmcs_read(GUEST_RIP);

	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);
#ifdef DBG
	prev_handler = curr_handler;
#endif
	curr_handler = (u16)exit_reason;

#ifdef NESTED_VMX
	/*
	 * See if we came from the nested hypervisor's guest, if that's
	 * the case, then throw back whatever we have to the nested hypervisor
	 * however, we need to do some checks first.
	 */
	struct nested_vcpu *nested = &vcpu->nested_vcpu;
	if (nested_entered(nested) && nested_can_handle(nested, exit_reason) &&
	    vcpu_enter_nested_hypervisor(vcpu, exit_reason))
		goto do_pending_irq;
#endif

	uintptr_t eflags = vcpu->eflags;
	if (curr_handler < sizeof(g_handlers) / sizeof(g_handlers[0]) &&
	    (ret = g_handlers[curr_handler](vcpu)) &&
	    (vcpu->eflags ^ eflags) != 0)
		vmcs_write(GUEST_RFLAGS, vcpu->eflags);

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		/*
		 * Mostly comes via invalid guest state, and is due to a cruical
		 * error that happened past VM-exit, let the handler see what it does first
		 */
		dbgbreak();
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
	} else {
#ifdef NESTED_VMX
do_pending_irq:
#endif
		if (irq->pending) {
			bool injected = false;

			if (irq->bits & INTR_INFO_DELIVER_CODE_MASK)
				injected = vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, irq->err) == 0;

			injected &= vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, irq->bits) == 0;
			if (irq->instr_len)
				injected &= vmcs_write(VM_ENTRY_INSTRUCTION_LEN, irq->instr_len) == 0;

			irq->pending = !injected;
		}
	}

	return ret;
}

static inline void vcpu_dump_state(const struct vcpu *vcpu, const struct regs *regs)
{
	VCPU_DEBUG("%p: ax=0x%016X   cx=0x%016X  dx=0x%016X\n"
		   "    bx=0x%016X   sp=0x%016X  bp=0x%016X\n"
		   "    si=0x%016X   di=0x%016X  r08=0x%016X\n"
		   "    r09=0x%016X  r10=0x%016X r11=0x%016X\n"
		   "    r12=0x%016X  r13=0x%016X r14=0x%016X\n"
		   "    r15=0x%016X  rip=0x%016X"
		   "    cs=0x%02X    ds=0x%02X   es=0x%02X\n"
		   "    fs=0x%016X   gs=0x%016X  kgs=0x%016X\n"
		   "    cr0=0x%016X  cr3=0x%016X cr4=0x%016X\n"
		   "	dr0=0x%016X  dr1=0x%016X dr2=0x%016X\n"
		   "	dr3=0x%016X  dr6=0x%016X dr7=0x%016X\n",
		   vcpu, regs->gp[REG_AX], regs->gp[REG_CX], regs->gp[REG_DX],
		   regs->gp[REG_BX], vmcs_read(GUEST_RSP), regs->gp[REG_BP],
		   regs->gp[REG_SI], regs->gp[REG_DI], regs->gp[REG_R8],
		   regs->gp[REG_R9], regs->gp[REG_R10], regs->gp[REG_R11],
		   regs->gp[REG_R12], regs->gp[REG_R13], regs->gp[REG_R14],
		   regs->gp[REG_R15], vmcs_read(GUEST_RIP),
		   vmcs_read(GUEST_CS_SELECTOR), vmcs_read(GUEST_DS_SELECTOR),
		   vmcs_read(GUEST_ES_SELECTOR), vmcs_read(GUEST_FS_BASE),
		   vmcs_read(GUEST_GS_BASE), __readmsr(MSR_IA32_KERNEL_GS_BASE),
		   vmcs_read(GUEST_CR0), vmcs_read(GUEST_CR3), vmcs_read(GUEST_CR4),
		   __readdr(0), __readdr(1), __readdr(2),
		   __readdr(3), __readdr(6), vmcs_read(GUEST_DR7));
}

void vcpu_handle_fail(struct regs *regs)
{
	/*
	 * Handle failure due to either:
	 *	1) VM entry
	 *	2) vmxoff
	 *
	 * Only called from assembly.
	 */
	u32 err = 0;
	if (regs->eflags & X86_EFLAGS_ZF)
		err = vmcs_read32(VM_INSTRUCTION_ERROR);

	vcpu_dump_state(ksm_current_cpu(), regs);
	dbgbreak();
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, err, curr_handler, prev_handler);
}
