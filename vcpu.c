#include "ksm.h"

static inline bool enter_vmx(struct vmcs *vmxon)
{
	/* If we're running nested on a hypervisor that does not
	 * support VT-x, this will cause #GP.  */
	u64 cr0 = __readcr0();
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0);

	u64 cr4 = __readcr4();
	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4);

	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	vmxon->revision_id = (u32)vmx;

	/* Enter VMX root operation  */
	uintptr_t pa = __pa(vmxon);
	if (__vmx_on(&pa))
		return false;

	/* This is necessary here or just before we exit the VM,
	 * we do it here as it's easier.  */
	__invept_all();
	return true;
}

static inline bool init_vmcs(struct vmcs *vmcs)
{
	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	vmcs->revision_id = (u32)vmx;

	uintptr_t pa = __pa(vmcs);
	if (__vmx_vmclear(&pa))
		return false;

	return __vmx_vmptrld(&pa) == 0;
}

static inline u32 __accessright(u16 selector)
{
	if (selector)
		return (__lar(selector) >> 8) & 0xF0FF;

	return 0x10000;
}

static inline void adjust_ctl_val(u32 msr, u64 *val)
{
	u64 v = __readmsr(msr);
	*val &= (u32)(v >> 32);			/* bit == 0 in high word ==> must be zero  */
	*val |= (u32)v;				/* bit == 1 in low word  ==> must be one  */
}

#ifdef DBG
static inline unsigned char debug_vmx_vmwrite(const char *name, size_t field, size_t value)
{
	unsigned char ret = __vmx_vmwrite(field, value);
	if (ret != 0)
		VCPU_DEBUG("failed on %s (%lld => 0x%016X): %d\n", name, field, value, ret);

	return ret;
}

#define DEBUG_VMX_VMWRITE(field, value)		\
	debug_vmx_vmwrite(#field, field, value)
#else
#define DEBUG_VMX_VMWRITE(field, value)		\
	__vmx_vmwrite(field, value)
#endif

static bool setup_vmcs(struct vcpu *vcpu, uintptr_t sp, uintptr_t ip, uintptr_t stack_base)
{
	struct gdtr gdtr;
	__sgdt(&gdtr);

	struct gdtr idtr;
	__sidt(&idtr);

	/* Get this CPU's EPT  */
	struct ept *ept = &vcpu->ept;

	u64 cr0 = __readcr0();
	u64 cr4 = __readcr4();
	u64 err = 0;

	u16 es = __reades();
	u16 cs = __readcs();
	u16 ss = __readss();
	u16 ds = __readds();
	u16 fs = __readfs();
	u16 gs = __readgs();
	u16 ldt = __sldt();
	u16 tr = __str();

	vcpu->g_idt.base = idtr.base;
	vcpu->g_idt.limit = idtr.limit;

	struct kidt_entry64 *current = (struct kidt_entry64 *)idtr.base;
	struct kidt_entry64 *shadow = (struct kidt_entry64 *)vcpu->idt.base;
	unsigned count = idtr.limit / sizeof(*shadow);
	for (unsigned n = 0; n < count; ++n)
		memcpy(&shadow[n], &current[n], sizeof(*shadow));
	vcpu_put_idt(vcpu, cs, X86_TRAP_VE, __ept_violation);

	u8 msr_off = 0;
	if (__readmsr(MSR_IA32_VMX_BASIC) & VMX_BASIC_TRUE_CTLS)
		msr_off = 0xC;

	u64 vm_entry = VM_ENTRY_IA32E_MODE
#ifndef DBG
		| VM_ENTRY_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_ENTRY_CTLS + msr_off, &vm_entry);

	u64 vm_exit = VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE
#ifndef DBG
		| VM_EXIT_CONCEAL_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_EXIT_CTLS + msr_off, &vm_exit);

	u64 vm_pinctl = 0;
	adjust_ctl_val(MSR_IA32_VMX_PINBASED_CTLS + msr_off, &vm_pinctl);

	u64 vm_cpuctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_USE_TSC_OFFSETING;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS + msr_off, &vm_cpuctl);

	u64 vm_2ndctl = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_TSC_SCALING |
		SECONDARY_EXEC_DESC_TABLE_EXITING | SECONDARY_EXEC_XSAVES |
		SECONDARY_EXEC_ENABLE_VMFUNC | SECONDARY_EXEC_ENABLE_VE
#if _WIN32_WINNT == 0x0A00 	/* Windows 10  */
		| SECONDARY_EXEC_RDTSCP
#endif
#ifdef ENABLE_PML
		| SECONDARY_EXEC_ENABLE_PML
#endif
#ifndef DBG
		| SECONDARY_EXEC_CONCEAL_VMX_IPT
#endif
		;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS2, &vm_2ndctl);
	if (!(vm_2ndctl & (SECONDARY_EXEC_ENABLE_VMFUNC | SECONDARY_EXEC_ENABLE_VE)))
		return false;

	/* Processor control fields  */
	err |= DEBUG_VMX_VMWRITE(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl);
	err |= DEBUG_VMX_VMWRITE(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
	err |= DEBUG_VMX_VMWRITE(EXCEPTION_BITMAP, __EXCEPTION_BITMAP);
	err |= DEBUG_VMX_VMWRITE(PAGE_FAULT_ERROR_CODE_MASK, 0);
	err |= DEBUG_VMX_VMWRITE(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	err |= DEBUG_VMX_VMWRITE(CR3_TARGET_COUNT, 0);
	err |= DEBUG_VMX_VMWRITE(VM_EXIT_CONTROLS, vm_exit);
	err |= DEBUG_VMX_VMWRITE(VM_EXIT_MSR_STORE_COUNT, 0);
	err |= DEBUG_VMX_VMWRITE(VM_EXIT_MSR_LOAD_COUNT, 0);
	err |= DEBUG_VMX_VMWRITE(VM_ENTRY_CONTROLS, vm_entry);
	err |= DEBUG_VMX_VMWRITE(VM_ENTRY_MSR_LOAD_COUNT, 0);
	err |= DEBUG_VMX_VMWRITE(VM_ENTRY_INTR_INFO_FIELD, 0);
	err |= DEBUG_VMX_VMWRITE(SECONDARY_VM_EXEC_CONTROL, vm_2ndctl);

	/* Control Fields */
	err |= DEBUG_VMX_VMWRITE(IO_BITMAP_A, 0);
	err |= DEBUG_VMX_VMWRITE(IO_BITMAP_B, 0);
	err |= DEBUG_VMX_VMWRITE(MSR_BITMAP, __pa(ksm.msr_bitmap));
	err |= DEBUG_VMX_VMWRITE(EPT_POINTER, EPTP(ept, EPTP_DEFAULT));
	err |= DEBUG_VMX_VMWRITE(VM_FUNCTION_CTRL, VM_FUNCTION_CTL_EPTP_SWITCHING);
	err |= DEBUG_VMX_VMWRITE(EPTP_INDEX, EPTP_DEFAULT);
	err |= DEBUG_VMX_VMWRITE(EPTP_LIST_ADDRESS, __pa(&ept->ptr_list));
	err |= DEBUG_VMX_VMWRITE(VE_INFO_ADDRESS, __pa(&vcpu->ve));
#ifdef ENABLE_PML
	err |= DEBUG_VMX_VMWRITE(PML_ADDRESS, __pa(&vcpu->pml));
	err |= DEBUG_VMX_VMWRITE(GUEST_PML_INDEX, PML_MAX_ENTRIES - 1);
#endif
	err |= DEBUG_VMX_VMWRITE(CR0_GUEST_HOST_MASK, __CR0_GUEST_HOST_MASK);
	err |= DEBUG_VMX_VMWRITE(CR4_GUEST_HOST_MASK, __CR4_GUEST_HOST_MASK);
	err |= DEBUG_VMX_VMWRITE(CR0_READ_SHADOW, cr0);
	err |= DEBUG_VMX_VMWRITE(CR4_READ_SHADOW, cr4);
	err |= DEBUG_VMX_VMWRITE(VMCS_LINK_POINTER, -1ULL);

	/* Guest  */
	err |= DEBUG_VMX_VMWRITE(GUEST_ES_SELECTOR, es);
	err |= DEBUG_VMX_VMWRITE(GUEST_CS_SELECTOR, cs);
	err |= DEBUG_VMX_VMWRITE(GUEST_SS_SELECTOR, ss);
	err |= DEBUG_VMX_VMWRITE(GUEST_DS_SELECTOR, ds);
	err |= DEBUG_VMX_VMWRITE(GUEST_FS_SELECTOR, fs);
	err |= DEBUG_VMX_VMWRITE(GUEST_GS_SELECTOR, gs);
	err |= DEBUG_VMX_VMWRITE(GUEST_LDTR_SELECTOR, ldt);
	err |= DEBUG_VMX_VMWRITE(GUEST_TR_SELECTOR, tr);
	err |= DEBUG_VMX_VMWRITE(GUEST_ES_LIMIT, __segmentlimit(es));
	err |= DEBUG_VMX_VMWRITE(GUEST_CS_LIMIT, __segmentlimit(cs));
	err |= DEBUG_VMX_VMWRITE(GUEST_SS_LIMIT, __segmentlimit(ss));
	err |= DEBUG_VMX_VMWRITE(GUEST_DS_LIMIT, __segmentlimit(ds));
	err |= DEBUG_VMX_VMWRITE(GUEST_FS_LIMIT, __segmentlimit(fs));
	err |= DEBUG_VMX_VMWRITE(GUEST_GS_LIMIT, __segmentlimit(gs));
	err |= DEBUG_VMX_VMWRITE(GUEST_LDTR_LIMIT, __segmentlimit(ldt));
	err |= DEBUG_VMX_VMWRITE(GUEST_TR_LIMIT, __segmentlimit(tr));
	err |= DEBUG_VMX_VMWRITE(GUEST_GDTR_LIMIT, gdtr.limit);
	err |= DEBUG_VMX_VMWRITE(GUEST_IDTR_LIMIT, idtr.limit);
	err |= DEBUG_VMX_VMWRITE(GUEST_ES_AR_BYTES, __accessright(es));
	err |= DEBUG_VMX_VMWRITE(GUEST_CS_AR_BYTES, __accessright(cs));
	err |= DEBUG_VMX_VMWRITE(GUEST_SS_AR_BYTES, __accessright(ss));
	err |= DEBUG_VMX_VMWRITE(GUEST_DS_AR_BYTES, __accessright(ds));
	err |= DEBUG_VMX_VMWRITE(GUEST_FS_AR_BYTES, __accessright(fs));
	err |= DEBUG_VMX_VMWRITE(GUEST_GS_AR_BYTES, __accessright(gs));
	err |= DEBUG_VMX_VMWRITE(GUEST_LDTR_AR_BYTES, __accessright(ldt));
	err |= DEBUG_VMX_VMWRITE(GUEST_TR_AR_BYTES, __accessright(tr));
	err |= DEBUG_VMX_VMWRITE(GUEST_INTERRUPTIBILITY_INFO, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_ACTIVITY_STATE, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTLMSR));
	err |= DEBUG_VMX_VMWRITE(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= DEBUG_VMX_VMWRITE(GUEST_CR0, cr0);
	err |= DEBUG_VMX_VMWRITE(GUEST_CR3, ksm.origin_cr3);
	err |= DEBUG_VMX_VMWRITE(GUEST_CR4, cr4);
	err |= DEBUG_VMX_VMWRITE(GUEST_ES_BASE, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_CS_BASE, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_SS_BASE, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_DS_BASE, 0);
	err |= DEBUG_VMX_VMWRITE(GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= DEBUG_VMX_VMWRITE(GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= DEBUG_VMX_VMWRITE(GUEST_LDTR_BASE, __segmentbase(gdtr.base, ldt));
	err |= DEBUG_VMX_VMWRITE(GUEST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= DEBUG_VMX_VMWRITE(GUEST_GDTR_BASE, gdtr.base);
	err |= DEBUG_VMX_VMWRITE(GUEST_IDTR_BASE, vcpu->idt.base);
	err |= DEBUG_VMX_VMWRITE(GUEST_DR7, __readdr(7));
	err |= DEBUG_VMX_VMWRITE(GUEST_RSP, sp);
	err |= DEBUG_VMX_VMWRITE(GUEST_RIP, ip);
	err |= DEBUG_VMX_VMWRITE(GUEST_RFLAGS, __readeflags());
	err |= DEBUG_VMX_VMWRITE(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= DEBUG_VMX_VMWRITE(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	/* Host  */
	err |= DEBUG_VMX_VMWRITE(HOST_ES_SELECTOR, es & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_CS_SELECTOR, cs & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_SS_SELECTOR, ss & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_DS_SELECTOR, ds & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_FS_SELECTOR, fs & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_GS_SELECTOR, gs & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_TR_SELECTOR, tr & 0xf8);
	err |= DEBUG_VMX_VMWRITE(HOST_CR0, cr0);
	err |= DEBUG_VMX_VMWRITE(HOST_CR3, ksm.kernel_cr3);
	err |= DEBUG_VMX_VMWRITE(HOST_CR4, cr4);
	err |= DEBUG_VMX_VMWRITE(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= DEBUG_VMX_VMWRITE(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= DEBUG_VMX_VMWRITE(HOST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= DEBUG_VMX_VMWRITE(HOST_GDTR_BASE, gdtr.base);
	err |= DEBUG_VMX_VMWRITE(HOST_IDTR_BASE, idtr.base);
	err |= DEBUG_VMX_VMWRITE(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= DEBUG_VMX_VMWRITE(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= DEBUG_VMX_VMWRITE(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	err |= DEBUG_VMX_VMWRITE(HOST_RSP, stack_base);
	err |= DEBUG_VMX_VMWRITE(HOST_RIP, (uintptr_t)__vmx_entrypoint);

	return err == 0;
}

static inline void vcpu_launch(void)
{
	size_t vmerr;
	uint8_t err = __vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
	if (err)
		VCPU_DEBUG("VM_INSTRUCTION_ERROR: %zd\n", vmerr);

	err = __vmx_vmlaunch();
	if (err) {
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		VCPU_DEBUG("__vmx_vmlaunch(): failed %d %d\n", err, vmerr);
	}
}

void vcpu_init(struct vcpu *vcpu, uintptr_t sp, uintptr_t ip)
{
	RtlZeroMemory(vcpu, sizeof(*vcpu));
	if (!ept_init(&vcpu->ept))
		return;

	vcpu->idt.limit = PAGE_SIZE - 1;
	vcpu->idt.base = (uintptr_t)mm_alloc_pool(NonPagedPool, PAGE_SIZE);
	if (!vcpu->idt.base)
		return ept_exit(&vcpu->ept);

	if (!enter_vmx(&vcpu->vmxon))
		goto out;

	if (!init_vmcs(&vcpu->vmcs))
		goto out_off;

	if (setup_vmcs(vcpu, sp, ip, (uintptr_t)vcpu->stack + KERNEL_STACK_SIZE))
		vcpu_launch();

	/* setup_vmcs() failed if we got here, we had already overwritten the
	 * IDT entry for #VE (X86_TRAP_VE), restore it now otherwise PatchGuard is gonna
	 * notice and BSOD us.  */
	__lidt(&vcpu->g_idt);

out_off:
	__vmx_off();
out:
	vcpu_free(vcpu);
}

void vcpu_free(struct vcpu *vcpu)
{
	if (vcpu->idt.base)
		mm_free_pool((void *)vcpu->idt.base, PAGE_SIZE);

	ept_exit(&vcpu->ept);
}
