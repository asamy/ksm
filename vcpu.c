#include "vcpu.h"

static inline void vcpu_put_idt(struct vcpu *vcpu, u16 cs, unsigned n, void *h)
{
	struct kidt_entry64 e;
	pack_entry(&e, cs, (uintptr_t)h);
	put_entry(vcpu->idt.base, n, &e);
	vcpu->shadow_idt[n] = h;
}

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

static bool init_vmcs(struct vmcs *vmcs)
{
	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	vmcs->revision_id = (u32)vmx;

	uintptr_t pa = __pa(vmcs);
	if (__vmx_vmclear(&pa))
		return false;

	return __vmx_vmptrld(&pa) == 0;
}

static u32 __accessright(u16 selector)
{
	if (selector)
		return (__lar(selector) >> 8) & 0xF0FF;

	return 0x10000;
}

static inline void adjust_ctl_val(u32 msr, u64 *val)
{
	u64 v = __readmsr(msr);
	*val &= v >> 32;			/* bit == 0 in high word ==> must be zero  */
	*val |= (u32)v;				/* bit == 1 in low word  ==> must be one  */
}

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

	u64 vm_entry = VM_ENTRY_IA32E_MODE;// | VM_ENTRY_LOAD_IA32_PAT;
	adjust_ctl_val(MSR_IA32_VMX_ENTRY_CTLS + msr_off, &vm_entry);

	u64 vm_exit = VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE;
	adjust_ctl_val(MSR_IA32_VMX_EXIT_CTLS + msr_off, &vm_exit);

	u64 vm_pinctl = 0;
	adjust_ctl_val(MSR_IA32_VMX_PINBASED_CTLS + msr_off, &vm_pinctl);

	u64 vm_cpuctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_MOV_DR_EXITING | CPU_BASED_USE_TSC_OFFSETING;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS + msr_off, &vm_cpuctl);

	u64 vm_2ndctl = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_TSC_SCALING |
		SECONDARY_EXEC_DESC_TABLE_EXITING | SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_RDTSCP |
		SECONDARY_EXEC_ENABLE_VMFUNC | SECONDARY_EXEC_ENABLE_VE;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS2, &vm_2ndctl);

	/* Processor control fields  */
	err |= __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl);
	err |= __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
	err |= __vmx_vmwrite(EXCEPTION_BITMAP, __EXCEPTION_BITMAP);
	err |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	err |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	err |= __vmx_vmwrite(CR3_TARGET_COUNT, 0);
	err |= __vmx_vmwrite(VM_EXIT_CONTROLS, vm_exit);
	err |= __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	err |= __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	err |= __vmx_vmwrite(VM_ENTRY_CONTROLS, vm_entry);
	err |= __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	err |= __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	err |= __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, vm_2ndctl);

	/* Control Fields */
	err |= __vmx_vmwrite(IO_BITMAP_A, 0);
	err |= __vmx_vmwrite(IO_BITMAP_B, 0);
	err |= __vmx_vmwrite(MSR_BITMAP, __pa(ksm.msr_bitmap));
	err |= __vmx_vmwrite(EPT_POINTER, EPTP(ept, EPTP_DEFAULT));
	err |= __vmx_vmwrite(VM_FUNCTION_CTRL, VM_FUNCTION_CTL_EPTP_SWITCHING);
	err |= __vmx_vmwrite(EPTP_INDEX, EPTP_DEFAULT);
	err |= __vmx_vmwrite(EPTP_LIST_ADDRESS, __pa(ept->ptr_list));
	err |= __vmx_vmwrite(VE_INFO_ADDRESS, __pa(vcpu->ve));
	err |= __vmx_vmwrite(CR0_GUEST_HOST_MASK, __CR0_GUEST_HOST_MASK);
	err |= __vmx_vmwrite(CR4_GUEST_HOST_MASK, __CR4_GUEST_HOST_MASK);
	err |= __vmx_vmwrite(CR0_READ_SHADOW, cr0);
	err |= __vmx_vmwrite(CR4_READ_SHADOW, cr4);
	err |= __vmx_vmwrite(VMCS_LINK_POINTER, -1ULL);

	/* Guest  */
	err |= __vmx_vmwrite(GUEST_ES_SELECTOR, es);
	err |= __vmx_vmwrite(GUEST_CS_SELECTOR, cs);
	err |= __vmx_vmwrite(GUEST_SS_SELECTOR, ss);
	err |= __vmx_vmwrite(GUEST_DS_SELECTOR, ds);
	err |= __vmx_vmwrite(GUEST_FS_SELECTOR, fs);
	err |= __vmx_vmwrite(GUEST_GS_SELECTOR, gs);
	err |= __vmx_vmwrite(GUEST_LDTR_SELECTOR, ldt);
	err |= __vmx_vmwrite(GUEST_TR_SELECTOR, tr);
	err |= __vmx_vmwrite(GUEST_ES_LIMIT, __segmentlimit(es));
	err |= __vmx_vmwrite(GUEST_CS_LIMIT, __segmentlimit(cs));
	err |= __vmx_vmwrite(GUEST_SS_LIMIT, __segmentlimit(ss));
	err |= __vmx_vmwrite(GUEST_DS_LIMIT, __segmentlimit(ds));
	err |= __vmx_vmwrite(GUEST_FS_LIMIT, __segmentlimit(fs));
	err |= __vmx_vmwrite(GUEST_GS_LIMIT, __segmentlimit(gs));
	err |= __vmx_vmwrite(GUEST_LDTR_LIMIT, __segmentlimit(ldt));
	err |= __vmx_vmwrite(GUEST_TR_LIMIT, __segmentlimit(tr));
	err |= __vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
	err |= __vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.limit);
	err |= __vmx_vmwrite(GUEST_ES_AR_BYTES, __accessright(es));
	err |= __vmx_vmwrite(GUEST_CS_AR_BYTES, __accessright(cs));
	err |= __vmx_vmwrite(GUEST_SS_AR_BYTES, __accessright(ss));
	err |= __vmx_vmwrite(GUEST_DS_AR_BYTES, __accessright(ds));
	err |= __vmx_vmwrite(GUEST_FS_AR_BYTES, __accessright(fs));
	err |= __vmx_vmwrite(GUEST_GS_AR_BYTES, __accessright(gs));
	err |= __vmx_vmwrite(GUEST_LDTR_AR_BYTES, __accessright(ldt));
	err |= __vmx_vmwrite(GUEST_TR_AR_BYTES, __accessright(tr));
	err |= __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	err |= __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
	err |= __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTLMSR));
	err |= __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= __vmx_vmwrite(GUEST_CR0, cr0);
	err |= __vmx_vmwrite(GUEST_CR3, ksm.origin_cr3);
	err |= __vmx_vmwrite(GUEST_CR4, cr4);
	err |= __vmx_vmwrite(GUEST_ES_BASE, 0);
	err |= __vmx_vmwrite(GUEST_CS_BASE, 0);
	err |= __vmx_vmwrite(GUEST_SS_BASE, 0);
	err |= __vmx_vmwrite(GUEST_DS_BASE, 0);
	err |= __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= __vmx_vmwrite(GUEST_LDTR_BASE, __segmentbase(gdtr.base, ldt));
	err |= __vmx_vmwrite(GUEST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= __vmx_vmwrite(GUEST_GDTR_BASE, gdtr.base);
	err |= __vmx_vmwrite(GUEST_IDTR_BASE, vcpu->idt.base);
	err |= __vmx_vmwrite(GUEST_DR7, __readdr(7));
	err |= __vmx_vmwrite(GUEST_RSP, sp);
	err |= __vmx_vmwrite(GUEST_RIP, ip);
	err |= __vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	err |= __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	/* Host  */
	err |= __vmx_vmwrite(HOST_ES_SELECTOR, es & 0xf8);
	err |= __vmx_vmwrite(HOST_CS_SELECTOR, cs & 0xf8);
	err |= __vmx_vmwrite(HOST_SS_SELECTOR, ss & 0xf8);
	err |= __vmx_vmwrite(HOST_DS_SELECTOR, ds & 0xf8);
	err |= __vmx_vmwrite(HOST_FS_SELECTOR, fs & 0xf8);
	err |= __vmx_vmwrite(HOST_GS_SELECTOR, gs & 0xf8);
	err |= __vmx_vmwrite(HOST_TR_SELECTOR, tr & 0xf8);
	err |= __vmx_vmwrite(HOST_CR0, cr0);
	err |= __vmx_vmwrite(HOST_CR3, ksm.kernel_cr3);
	err |= __vmx_vmwrite(HOST_CR4, cr4);
	err |= __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= __vmx_vmwrite(HOST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= __vmx_vmwrite(HOST_GDTR_BASE, gdtr.base);
	err |= __vmx_vmwrite(HOST_IDTR_BASE, idtr.base);
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	err |= __vmx_vmwrite(HOST_RSP, stack_base);
	err |= __vmx_vmwrite(HOST_RIP, (uintptr_t)__vmx_entrypoint);

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

void vcpu_init(uintptr_t sp, uintptr_t ip, struct ksm *k)
{
	struct vcpu *vcpu = ExAllocatePool(NonPagedPoolNx, sizeof(*vcpu));
	if (!vcpu)
		return;

	RtlZeroMemory(vcpu, sizeof(*vcpu));
	if (!ept_init(&vcpu->ept))
		return ExFreePool(vcpu);

	PHYSICAL_ADDRESS highest;
	highest.QuadPart = -1;

	vcpu->stack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, highest);
	if (!vcpu->stack)
		goto out;
	RtlZeroMemory(vcpu->stack, KERNEL_STACK_SIZE);

	vcpu->vmcs = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!vcpu->vmcs)
		goto out;
	RtlZeroMemory(vcpu->vmcs, PAGE_SIZE);

	vcpu->vmxon = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!vcpu->vmxon)
		goto out;
	RtlZeroMemory(vcpu->vmxon, PAGE_SIZE);

	vcpu->ve = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!vcpu->ve)
		goto out;
	RtlZeroMemory(vcpu->ve, PAGE_SIZE);

	vcpu->idt.limit = PAGE_SIZE - 1;
	vcpu->idt.base = (uintptr_t)ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!vcpu->idt.base)
		goto out;

	for (int i = 0; i < 0x100; ++i)
		vcpu->shadow_idt[i] = NULL;

	uintptr_t stack_top = (uintptr_t)vcpu->stack + KERNEL_STACK_SIZE;
	uintptr_t stack_data = stack_top - sizeof(void *);
	uintptr_t stack_base = stack_data - sizeof(void *);

	*(uintptr_t *)stack_base = -1ULL;
	*(struct vcpu **)stack_data = vcpu;

	vcpu->nr = cpu_nr();
	k->vcpu_list[cpu_nr()] = vcpu;

	if (!enter_vmx(vcpu->vmxon))
		goto out;

	if (!init_vmcs(vcpu->vmcs))
		goto out_off;

	if (setup_vmcs(vcpu, sp, ip, stack_base))
		vcpu_launch();

out_off:
	__vmx_off();
out:
	vcpu_free(vcpu);
}

void vcpu_free(struct vcpu *vcpu)
{
	if (vcpu->stack)
		MmFreeContiguousMemory(vcpu->stack);

	if (vcpu->vmcs)
		ExFreePool(vcpu->vmcs);

	if (vcpu->vmxon)
		ExFreePool(vcpu->vmxon);

	if (vcpu->ve)
		ExFreePool(vcpu->ve);

	if (vcpu->idt.base)
		ExFreePool((void *)vcpu->idt.base);

	ept_exit(&vcpu->ept);
	ExFreePool(vcpu);
}

void vcpu_flush_idt(struct vcpu *vcpu)
{
	__vmx_vmwrite(GUEST_IDTR_LIMIT, vcpu->idt.limit);
	__vmx_vmwrite(GUEST_IDTR_BASE, vcpu->idt.base);
}

bool vcpu_hook_idte(struct vcpu *vcpu, struct shadow_idt_entry *h)
{
	u64 cs;
	__vmx_vmread(GUEST_CS_SELECTOR, &cs);

	vcpu_put_idt(vcpu, (u16)cs, h->n, h->h);
	vcpu_flush_idt(vcpu);
	return true;
}

void vcpu_subverted(void)
{
	/* Post-virtualization  */
	struct gdtr idt;
	__sidt(&idt);
	VCPU_DEBUG("Subverted, IDT: %p 0x%X\n", idt.base, idt.limit);
}
