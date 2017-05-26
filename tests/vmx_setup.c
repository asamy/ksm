#include <ntddk.h>
#include <intrin.h>

#include "../compiler.h"
#include "../asm.h"
#include "../x86.h"
#include "../mm.h"
#include "../vmx.h"
#include "../segment.h"

/* assembly  */
extern void vmx_ep(void);

/* stack  */
extern __align(PAGE_SIZE) u8 kstack[HOST_STACK_SIZE];

int initialize_features(void)
{
	__try {
		/* Required MSR_IA32_FEATURE_CONTROL bits:  */
		const u64 required_feat_bits = FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

		uintptr_t feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
		if ((feat_ctl & required_feat_bits) == required_feat_bits)
			return 0;

		/* Attempt to set bits in place  */
		__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | required_feat_bits);

		feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
		if ((feat_ctl & required_feat_bits) == required_feat_bits)
			return 0;
	} __except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return -1;
}

/* Give me a vmxon, I'll give you root access.  */
int give_me_root(void *vmxon)
{
	u64 cr0 = __readcr0();
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0);

	u64 cr4 = __readcr4();
	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4);

	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	*(u32 *)vmxon = (u32)vmx;

	uintptr_t pa = __pa(vmxon);
	if (__vmx_on(&pa))
		return -1;

	return 0;
}

/* Give me a VMCS region, I'll initialize it for you  */
int init_vmcs(void *vmcs)
{
	u64 vmx = __readmsr(MSR_IA32_VMX_BASIC);
	*(u32 *)vmcs = (u32)vmx;

	uintptr_t pa = __pa(vmcs);
	if (__vmx_vmclear(&pa))
		return false;

	return __vmx_vmptrld(&pa) == 0;
}

static inline void adjust_ctl_val(u32 msr, u32 *val)
{
	u64 v = __readmsr(msr);
	*val &= (u32)(v >> 32);			/* bit == 0 in high word ==> must be zero  */
	*val |= (u32)v;				/* bit == 1 in low word  ==> must be one  */
}

static inline u32 __accessright(u16 selector)
{
	if (selector)
		return (__lar(selector) >> 8) & 0xF0FF;

	/* unusable  */
	return 0x10000;
}

bool setup_basic_vmcs(u32 other_primary, u32 other_secondary, uintptr_t sp, uintptr_t ip)
{
	struct gdtr gdtr;
	__sgdt(&gdtr);

	struct gdtr idtr;
	__sidt(&idtr);

	u64 cr0 = __readcr0();
	u64 cr3 = __readcr3();
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

	u32 msr_off = 0;
	if (__readmsr(MSR_IA32_VMX_BASIC) & VMX_BASIC_TRUE_CTLS)
		msr_off = 0xC;

	u32 vm_entry = VM_ENTRY_IA32E_MODE;
	adjust_ctl_val(MSR_IA32_VMX_ENTRY_CTLS + msr_off, &vm_entry);

	u32 vm_exit = VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE;
	adjust_ctl_val(MSR_IA32_VMX_EXIT_CTLS + msr_off, &vm_exit);

	u32 vm_pinctl = 0;
	adjust_ctl_val(MSR_IA32_VMX_PINBASED_CTLS + msr_off, &vm_pinctl);

	u32 vm_cpuctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | other_primary;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS + msr_off, &vm_cpuctl);

	u32 vm_2ndctl = other_secondary;
	adjust_ctl_val(MSR_IA32_VMX_PROCBASED_CTLS2, &vm_2ndctl);

	/* Processor control fields  */
	err |= __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl);
	err |= __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vm_cpuctl);
	err |= __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, vm_2ndctl);
	err |= __vmx_vmwrite(VM_EXIT_CONTROLS, vm_exit);
	err |= __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	err |= __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	err |= __vmx_vmwrite(VM_ENTRY_CONTROLS, vm_entry);
	err |= __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	err |= __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	err |= __vmx_vmwrite(EXCEPTION_BITMAP, 0);
	err |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	err |= __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	err |= __vmx_vmwrite(CR3_TARGET_COUNT, 0);
	err |= __vmx_vmwrite(VMCS_LINK_POINTER, -1ULL);

	/* CR0/CR4 controls  */
	err |= __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	err |= __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
	err |= __vmx_vmwrite(CR0_READ_SHADOW, cr0);
	err |= __vmx_vmwrite(CR4_READ_SHADOW, cr4);

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
	err |= __vmx_vmwrite(GUEST_CR3, cr3);
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
	err |= __vmx_vmwrite(GUEST_IDTR_BASE, idtr.base);
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
	err |= __vmx_vmwrite(HOST_CR3, cr3);
	err |= __vmx_vmwrite(HOST_CR4, cr4);
	err |= __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
	err |= __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
	err |= __vmx_vmwrite(HOST_TR_BASE, __segmentbase(gdtr.base, tr));
	err |= __vmx_vmwrite(HOST_GDTR_BASE, gdtr.base);
	err |= __vmx_vmwrite(HOST_IDTR_BASE, idtr.base);
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	err |= __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	err |= __vmx_vmwrite(HOST_RSP, (uintptr_t)kstack + HOST_STACK_SIZE);
	err |= __vmx_vmwrite(HOST_RIP, (uintptr_t)vmx_ep);

	return err == 0;
}

int launch_vcpu(void)
{
	size_t vmerr;
	uint8_t err = __vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
	if (err)
		DbgPrint("VM_INSTRUCTION_ERROR: %zd\n", vmerr);

	err = __vmx_vmlaunch();
	if (err) {
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		DbgPrint("__vmx_vmlaunch(): failed %d %d\n", err, vmerr);
	}

	return err;
}
