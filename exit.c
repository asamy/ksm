#include <ntifs.h>
#include <intrin.h>

#include "ksm.h"

/* For debugging...  */
static u16 curr_handler = 0;
static u16 prev_handler = 0;

/* For easier casting  */
static inline u64 vmcs_read(u64 what)
{
	u64 x;
	__vmx_vmread(what, &x);

	return x;
}

static inline u32 vmcs_read32(u64 what)
{
	return (u32)vmcs_read(what);
}

static inline u16 vmcs_read16(u64 what)
{
	return (u16)vmcs_read32(what);
}

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

static inline void vcpu_advance_rip(struct guest_context *gc)
{
	if (gc->eflags & X86_EFLAGS_TF) {
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
	__vmx_vmwrite(GUEST_RIP, gc->ip + instr_len);

	size_t interruptibility;
	__vmx_vmread(GUEST_INTERRUPTIBILITY_INFO, &interruptibility);
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO,
		      interruptibility & ~(GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI));
}

static inline void vcpu_inject_ve(struct vcpu *vcpu)
{
	struct ve_except_info *info = &vcpu->ve;
	info->eptp = (u16)vmcs_read(EPTP_INDEX);
	info->except_mask = ~0UL;
	info->reason = EXIT_REASON_EPT_VIOLATION;
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &info->gpa);
	__vmx_vmread(GUEST_LINEAR_ADDRESS, &info->gla);
	__vmx_vmread(EXIT_QUALIFICATION, &info->exit);

	if (!vcpu_inject_hardirq_noerr(X86_TRAP_VE))
		VCPU_DEBUG_RAW("could not inject #VE into guest\n");
}

static bool vcpu_nop(struct guest_context *gc)
{
	VCPU_TRACER_START();
	VCPU_DEBUG_RAW("you need to handle the corresponding VM-exit for the handler you set.\n");
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_BUG_UNHANDLED, curr_handler, prev_handler);
	return false;
}

static bool vcpu_handle_except_nmi(struct guest_context *gc)
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
		VCPU_BUGCHECK(VCPU_IRQ_NOT_HANDLED, gc->ip, intr_type, vector);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_triplefault(struct guest_context *gc)
{
	VCPU_TRACER_START();
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_TRIPLEFAULT, curr_handler, prev_handler);
	VCPU_TRACER_END();
	return false;
}

static bool vcpu_handle_taskswitch(struct guest_context *gc)
{
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

static bool vcpu_handle_cpuid(struct guest_context *gc)
{
	VCPU_TRACER_START();

	int cpuid[4];
	int func = ksm_read_reg32(gc, REG_AX);
	int subf = ksm_read_reg32(gc, REG_CX);
	__cpuidex(cpuid, func, subf);

	if (func == 1)
		cpuid[2] &= ~(1 << (X86_FEATURE_VMX & 31));

	ksm_write_reg32(gc, REG_AX, cpuid[0]);
	ksm_write_reg32(gc, REG_BX, cpuid[1]);
	ksm_write_reg32(gc, REG_CX, cpuid[2]);
	ksm_write_reg32(gc, REG_DX, cpuid[3]);
	vcpu_advance_rip(gc);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_hlt(struct guest_context *gc)
{
	VCPU_TRACER_START();
	__halt();
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invd(struct guest_context *gc)
{
	VCPU_TRACER_START();
	__invd();
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invlpg(struct guest_context *gc)
{
	VCPU_TRACER_START();

	uintptr_t addr;
	__vmx_vmread(EXIT_QUALIFICATION, &addr);
	__invlpg((void *)addr);
	vcpu_advance_rip(gc);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_rdtsc(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u64 tsc = __rdtsc();
	ksm_write_reg32(gc, REG_AX, tsc);
	ksm_write_reg32(gc, REG_DX, tsc >> 32);
	vcpu_advance_rip(gc);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_vmfunc(struct guest_context *gc)
{
	VCPU_TRACER_START();
	VCPU_DEBUG("vmfunc caused VM-exit!  func is %d eptp index is %d\n",
		   ksm_read_reg32(gc, REG_AX), ksm_read_reg32(gc, REG_CX));
	vcpu_inject_hardirq_noerr(X86_TRAP_UD);
	vcpu_advance_rip(gc);
	VCPU_TRACER_END()
	return true;
}

#ifdef ENABLE_PML
static bool vcpu_dump_pml(struct guest_context *gc)
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

	u64 curr;
	__vmx_vmread(EPTP_INDEX, &curr);

	/* Dump it...  */
	struct vcpu *vcpu = to_vcpu(gc);
	struct ept *ept = &vcpu->ept;

	VCPU_DEBUG_RAW("PML dump start\n");
	for (; pml_index < PML_MAX_ENTRIES; ++pml_index) {
		/* CPU guarantees that the lower 12 bits (the offset) are always 0.  */
		u64 gpa = vcpu->pml[pml_index];
		u64 gva = (u64)__va(gpa);
		VCPU_DEBUG("On PML %d: GPA %p GVA %p\n", pml_index, gpa, gva);

		/* Reset AD bits now otherwise we probably won't get this page again  */
		uintptr_t *epte = ept_pte(ept, EPT4(ept, curr), gpa);
		*epte &= ~(EPT_ACCESSED | EPT_DIRTY);
	}

	/* Reset the PML index now...  */
	__vmx_vmwrite(GUEST_PML_INDEX, pml_index);
	/* We're done here  */
	VCPU_DEBUG_RAW("PML dump done\n");
	return true;
}
#endif

static bool vcpu_handle_pml_full(struct guest_context *gc)
{
#ifdef ENABLE_PML
	/* Page Modification Log is now full, dump it.  */
	VCPU_DEBUG_RAW("PML full\n");
	return vcpu_dump_pml(gc);
#else
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, VCPU_BUG_UNHANDLED, 0xDEAFDEAF, 0xBAADF00D);
	return false;
#endif
}

static inline void vcpu_vm_succeed(struct guest_context *gc)
{
	gc->eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
}

static inline void vcpu_vm_fail_invalid(struct guest_context *gc)
{
	gc->eflags |= X86_EFLAGS_CF;
	gc->eflags &= ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
}

static inline void vcpu_vm_fail_valid(struct guest_context *gc, size_t err)
{
	gc->eflags |= X86_EFLAGS_ZF;
	gc->eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_SF | X86_EFLAGS_OF);
	__vmx_vmwrite(VM_INSTRUCTION_ERROR, err);
}

static inline void vcpu_adjust_rflags(struct guest_context *gc, bool success)
{
	if (success)
		return vcpu_vm_succeed(gc);

	return vcpu_vm_fail_invalid(gc);
}

static inline void vcpu_do_exit(struct guest_context *gc)
{
	struct gdtr gdt;
	gdt.limit = (u16)vmcs_read(GUEST_GDTR_LIMIT);
	gdt.base = vmcs_read(GUEST_GDTR_BASE);
	__lgdt(&gdt);

	struct vcpu *vcpu = to_vcpu(gc);
	__lidt(&vcpu->g_idt);

	size_t ret = gc->ip + vmcs_read(VM_EXIT_INSTRUCTION_LEN);
	vcpu_vm_succeed(gc);

	u64 cr3;
	__vmx_vmread(GUEST_CR3, &cr3);
	__writecr3(cr3);

	ksm_write_reg(gc, REG_CX, ret);
	ksm_write_reg(gc, REG_DX, ksm_read_reg(gc, REG_SP));
	ksm_write_reg(gc, REG_AX, gc->eflags);
}

static bool vcpu_handle_hook(struct vcpu *vcpu, struct page_hook_info *h)
{
	VCPU_DEBUG("page hook request for %p => %p (%p)\n", h->d_pfn, h->c_pfn, h->c_va);
	h->ops->init_eptp(h, &vcpu->ept);
	return true;
}

static inline bool vcpu_handle_unhook(struct vcpu *vcpu, uintptr_t dpfn)
{
	struct ept *ept = &vcpu->ept;
	uintptr_t dpa = dpfn << PAGE_SHIFT;
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

static bool vcpu_handle_vmcall(struct guest_context *gc)
{
	VCPU_TRACER_START();

	if (!vcpu_check_cpl(0)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		goto out;
	}

	uint8_t nr = ksm_read_reg32(gc, REG_CX);
	uintptr_t arg = ksm_read_reg(gc, REG_DX);
	struct vcpu *vcpu = to_vcpu(gc);
	switch (nr) {
	case HYPERCALL_STOP:
		vcpu_do_exit(gc);
		VCPU_TRACER_END();
		return false;
	case HYPERCALL_IDT:
		vcpu_adjust_rflags(gc, vcpu_hook_idte(vcpu, (struct shadow_idt_entry *)arg));
		break;
	case HYPERCALL_UIDT:
		vcpu_adjust_rflags(gc, vcpu_unhook_idte(vcpu, (struct shadow_idt_entry *)arg));
		break;
	case HYPERCALL_HOOK:
		vcpu_adjust_rflags(gc, vcpu_handle_hook(vcpu, (struct page_hook_info *)arg));
		break;
	case HYPERCALL_UNHOOK:
		vcpu_adjust_rflags(gc, vcpu_handle_unhook(vcpu, arg));
		break;
	default:
		VCPU_DEBUG("unsupported hypercall: %d\n", nr);
		vcpu_inject_hardirq_noerr(X86_TRAP_UD);
		break;
	}

out:
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_vmx(struct guest_context *gc)
{
	VCPU_TRACER_START();
	vcpu_inject_hardirq_noerr(X86_TRAP_UD);
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_cr_access(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u64 exit;
	__vmx_vmread(EXIT_QUALIFICATION, &exit);

	int cr = exit & 15;
	int reg = (exit >> 8) & 15;
	u64 *val;
	switch ((exit >> 4) & 3) {
	case 0:		/* mov to cr  */
		val = ksm_reg(gc, reg);
		switch (cr) {
		case 0:
			__vmx_vmwrite(GUEST_CR0, *val);
			__vmx_vmwrite(CR0_READ_SHADOW, *val);
			break;
		case 3:
			__vmx_vmwrite(GUEST_CR3, *val);
			break;
		case 4:
			if (*val & X86_CR4_VMXE) {
				/* No nesting  */
				vcpu_inject_hardirq_noerr(X86_TRAP_GP);
			} else {
				__vmx_vmwrite(GUEST_CR4, *val);
				__vmx_vmwrite(CR4_READ_SHADOW, *val);
			}			
			break;
		case 8:
			gc->cr8 = *val;
			break;
		}
		break;
	case 1:		/* mov from cr  */
		val = ksm_reg(gc, reg);
		switch (cr) {
		case 3:
			__vmx_vmread(GUEST_CR3, val);
			break;
		case 8:
			*val = gc->cr8;
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

		cr0 = (cr0 & ~(X86_CR0_MP | X86_CR0_EM | X86_CR0_TS)) |
			(msw & (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS));

		__vmx_vmwrite(GUEST_CR0, cr0);
		__vmx_vmwrite(CR0_READ_SHADOW, cr0);
		break;
	}
	default:
		break;
	}

	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_dr_access(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u64 exit = vmcs_read(EXIT_QUALIFICATION);
	int dr = exit & DEBUG_REG_ACCESS_NUM;

	/* See Intel Manual, when CR4.DE is enabled, dr4/5 cannot be used,
	 * when clear, they are aliased to 6/7.  */
	u64 cr4 = vmcs_read(GUEST_CR4);
	if (cr4 & X86_CR4_DE && (dr == 4 || dr == 5)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		goto out;
	}

	if (!vcpu_check_cpl(0)) {
		vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		goto out;
	}

	u64 *reg = ksm_reg(gc, DEBUG_REG_ACCESS_REG(exit));
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
	vcpu_advance_rip(gc);
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

	return (u64)MultiplyExtract128(host_tsc, tsc_mul, 48);
}

static bool vcpu_handle_msr_read(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u32 msr = ksm_read_reg32(gc, REG_CX);
	u64 val = 0;

	struct vcpu *vcpu = to_vcpu(gc);
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
#ifdef DBG
		__vmx_vmread(GUEST_IA32_DEBUGCTL, &val);
#endif
		break;
	case MSR_IA32_FEATURE_CONTROL:
		val = __readmsr(msr) & ~(FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX);
		break;
	case MSR_IA32_VMX_CR0_FIXED0:
		val = X86_CR0_PE | X86_CR0_PG | X86_CR0_NE;
		break;
	case MSR_IA32_VMX_CR0_FIXED1:
		val = -1ULL;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		val = X86_CR4_VMXE;
		break;
	case MSR_IA32_VMX_CR4_FIXED1:
		val = -1ULL;
		break;
	case MSR_IA32_TSC:
		val = read_tsc_msr();
		break;
	default:
		if (msr >= MSR_IA32_VMX_BASIC && msr <= MSR_IA32_VMX_VMFUNC)
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		else
			val = __readmsr(msr);
		break;
	}

	ksm_write_reg32(gc, REG_AX, val);
	ksm_write_reg32(gc, REG_CX, val >> 32);
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_msr_write(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u32 msr = ksm_read_reg(gc, REG_CX);
	u64 val = ksm_combine_reg64(gc, REG_AX, REG_DX);

	struct vcpu *vcpu = to_vcpu(gc);
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
#ifdef DBG
		__vmx_vmwrite(GUEST_IA32_DEBUGCTL, val);
#endif
		break;
	case MSR_IA32_FEATURE_CONTROL:
		break;
	default:
		if (msr >= MSR_IA32_VMX_BASIC && msr <= MSR_IA32_VMX_VMFUNC)
			vcpu_inject_hardirq_noerr(X86_TRAP_GP);
		else
			__writemsr(msr, val);
		break;
	}

	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_invalid_state(struct guest_context *gc)
{
	VCPU_TRACER_START();
	VCPU_BUGCHECK(VCPU_BUGCHECK_GUEST_STATE, gc->ip, gc->eflags, prev_handler);
	VCPU_TRACER_END();
	return false;
}

static bool vcpu_handle_mtf(struct guest_context *gc)
{
	VCPU_TRACER_START();
	vcpu_set_mtf(false);
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static inline void vcpu_sync_idt(struct vcpu *vcpu, struct gdtr *idt)
{
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

static bool vcpu_handle_gdt_idt_access(struct guest_context *gc)
{
	u64 exit;
	__vmx_vmread(VMX_INSTRUCTION_INFO, &exit);

	u64 displacement;
	__vmx_vmread(EXIT_QUALIFICATION, &displacement);

	uintptr_t base = 0;
	if (!((exit >> 27) & 1))
		base = ksm_read_reg(gc, (exit >> 23) & 15);

	uintptr_t index = 0;
	if (!((exit >> 22) & 1))
		index = ksm_read_reg(gc, (exit >> 18) & 15) << (exit & 3);

	uintptr_t addr = base + index + displacement;
	if (((exit >> 7) & 7) == 1)
		addr &= 0xFFFFFFFF;

	struct vcpu *vcpu = to_vcpu(gc);
	VCPU_DEBUG("GDT/IDT access, addr [%p] (%p, %d, %d)\n", addr, base, index, displacement);

	VCPU_ENTER_GUEST();
	struct gdtr *dt = (struct gdtr *)addr;
	switch ((exit >> 28) & 3) {
	case 0:		/* sgdt  */
		dt->limit = (u16)vmcs_read(GUEST_GDTR_LIMIT);
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

	vcpu_advance_rip(gc);
	return true;
}

static bool vcpu_handle_ldt_tr_access(struct guest_context *gc)
{
	u64 exit;
	__vmx_vmread(VMX_INSTRUCTION_INFO, &exit);

	size_t displacement;
	__vmx_vmread(EXIT_QUALIFICATION, &displacement);

	uintptr_t addr;
	if ((exit >> 10) & 1) {
		// register
		addr = (uintptr_t)gc->gp[(exit >> 3) & 15];
		VCPU_DEBUG("LDT/TR access, addr %p\n", addr);
	} else {
		// base
		uintptr_t base = 0;
		if (!((exit >> 27) & 1))
			base = ksm_read_reg(gc, (exit >> 23) & 15);

		uintptr_t index = 0;
		if (!((exit >> 22) & 1))
			index = ksm_read_reg(gc, (exit >> 18) & 15) << (exit & 3);

		addr = base + index + displacement;
		if (((exit >> 7) & 7) == 1)
			addr &= 0xFFFFFFFF;
		VCPU_DEBUG("LDT/TR access, addr [%p] (%p, %d, %d)\n", addr, base, index, displacement);
	}

	VCPU_ENTER_GUEST();
	u16 *selector = (u16 *)addr;
	switch ((exit >> 28) & 3) {
	case 0:		/* sldt  */
		*selector = (u16)vmcs_read(GUEST_LDTR_SELECTOR);
		break;
	case 1:		/* str  */
		*selector = (u16)vmcs_read(GUEST_TR_SELECTOR);
		break;
	case 2:		/* lldt  */
		__vmx_vmwrite(GUEST_LDTR_SELECTOR, *selector);
		break;
	case 3:		/* ltr  */
		__vmx_vmwrite(GUEST_TR_SELECTOR, *selector);
		break;
	}
	VCPU_EXIT_GUEST();

	vcpu_advance_rip(gc);
	return true;
}

static bool vcpu_handle_ept_violation(struct guest_context *gc)
{
	VCPU_TRACER_START();

	struct vcpu *vcpu = to_vcpu(gc);
	if (!ept_handle_violation(vcpu)) {
#ifdef DBG
		u64 fault_pa;
		__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &fault_pa);

		VCPU_BUGCHECK(EPT_BUGCHECK_CODE, EPT_UNHANDLED_VIOLATION, gc->ip, fault_pa);
#else
		vcpu_inject_ve(vcpu);
#endif
	}

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_ept_misconfig(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u64 fault_pa = vmcs_read(GUEST_PHYSICAL_ADDRESS);
	u16 curr_eptp = vmcs_read(EPTP_INDEX);

	struct ept *ept = &to_vcpu(gc)->ept;
	uintptr_t *pte = ept_pte(ept, EPT4(ept, curr_eptp), fault_pa);
	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, EPT_BUGCHECK_MISCONFIG, fault_pa, *pte);
}

static bool vcpu_handle_rdtscp(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u32 tsc_aux;
	u64 tsc = __rdtscp(&tsc_aux);

	ksm_write_reg32(gc, REG_AX, tsc);
	ksm_write_reg32(gc, REG_DX, tsc >> 32);
	ksm_write_reg32(gc, REG_CX, tsc_aux);
	vcpu_advance_rip(gc);

	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_wbinvd(struct guest_context *gc)
{
	VCPU_TRACER_START();
	__wbinvd();
	vcpu_advance_rip(gc);
	VCPU_TRACER_END();
	return true;
}

static bool vcpu_handle_xsetbv(struct guest_context *gc)
{
	VCPU_TRACER_START();

	u32 ext = ksm_read_reg32(gc, REG_CX);
	u64 val = ksm_combine_reg64(gc, REG_AX, REG_DX);
	_xsetbv(ext, val);
	vcpu_advance_rip(gc);

	VCPU_TRACER_END();
	return true;
}

static bool(*g_handlers[]) (struct guest_context *) = {
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
	u64 cr8 = __readcr8();
	struct guest_context gc = {
		.vcpu = ksm_current_cpu(),
		.gp = regs,
		.cr8 = cr8,
	};
	__vmx_vmread(GUEST_RFLAGS, &gc.eflags);
	__vmx_vmread(GUEST_RIP, &gc.ip);
	__vmx_vmread(GUEST_RSP, &gc.gp[REG_SP]);

	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);
	prev_handler = curr_handler;
	curr_handler = (u16)exit_reason;

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		u64 exit_qualification;
		__vmx_vmread(EXIT_QUALIFICATION, &exit_qualification);
		VCPU_BUGCHECK(VCPU_BUGCHECK_FAILED_VMENTRY, gc.ip, exit_qualification, curr_handler);
	}

	bool ret = false;
	u64 eflags = gc.eflags;
	if (curr_handler < sizeof(g_handlers) / sizeof(g_handlers[0]) &&
	    (ret = g_handlers[curr_handler](&gc)) &&
	    (gc.eflags ^ eflags) != 0)
		__vmx_vmwrite(GUEST_RFLAGS, gc.eflags);

	if ((cr8 ^ gc.cr8) != 0)
		__writecr8(gc.cr8);
	return ret;
}

void vcpu_handle_fail(struct regs *regs)
{
	size_t err = 0;
	if (regs->eflags & X86_EFLAGS_ZF)
		__vmx_vmread(VM_INSTRUCTION_ERROR, &err);

	VCPU_BUGCHECK(VCPU_BUGCHECK_CODE, err, curr_handler, prev_handler);
}

void vcpu_dump_regs(const struct regs *regs, uintptr_t sp)
{
	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	VCPU_DEBUG("Context at %p: "
		   "rax=%p rbx=%p rcx=%p "
		   "rdx=%p rsi=%p rdi=%p "
		   "rsp=%p rbp=%p "
		   " r8=%p  r9=%p r10=%p "
		   "r11=%p r12=%p r13=%p "
		   "r14=%p r15=%p efl=%08x",
		   _ReturnAddress(), regs->gp[REG_AX], regs->gp[REG_BX], regs->gp[REG_CX],
		   regs->gp[REG_DX], regs->gp[REG_SI], regs->gp[REG_DI], regs->gp[REG_SP],
		   regs->gp[REG_BP], regs->gp[REG_R8], regs->gp[REG_R9], regs->gp[REG_R10],
		   regs->gp[REG_R11], regs->gp[REG_R12], regs->gp[REG_R13], regs->gp[REG_R14],
		   regs->gp[REG_R15], regs->eflags);
	if (irql < DISPATCH_LEVEL)
		KeLowerIrql(irql);
}

void vcpu_set_mtf(bool enable)
{
	u64 vm_cpuctl;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &vm_cpuctl);

	if (enable)
		vm_cpuctl |= CPU_BASED_MONITOR_TRAP_FLAG;
	else
		vm_cpuctl &= ~CPU_BASED_MONITOR_TRAP_FLAG;
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
}
