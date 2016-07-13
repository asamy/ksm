#include "vcpu.h"
#include "dpc.h"

struct kum kum = {
	.active_vcpus = 0,
	.phi_count = 0,
	.c_mask = 0,
	.c_bits = 0,
};

static NTSTATUS init_msr_bitmap(struct kum *k)
{
	void *msr_bitmap = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!msr_bitmap)
		return STATUS_NO_MEMORY;

	k->msr_bitmap = msr_bitmap;
	RtlZeroMemory(msr_bitmap, PAGE_SIZE);

	/* For all MSRs...  */
	u8 *bitmap_read_lo = (u8 *)msr_bitmap;
	u8 *bitmap_read_hi = bitmap_read_lo + 1024;
	memset(bitmap_read_lo, 0xff, 1024);		// 0 -> 1fff
	memset(bitmap_read_hi, 0xff, 1024);		// c0000000 - c0001fff

	/* ... ignore MSR_IA32_MPERF and MSR_IA32_APERF  */
	RTL_BITMAP bitmap_read_lo_hdr;
	RtlInitializeBitMap(&bitmap_read_lo_hdr, (PULONG)bitmap_read_lo, 1024 * CHAR_BIT);
	RtlClearBits(&bitmap_read_lo_hdr, MSR_IA32_MPERF, 2);

	for (u32 msr = 0; msr < PAGE_SIZE; ++msr) {
		__try {
			__readmsr(msr);
		} __except (EXCEPTION_EXECUTE_HANDLER)
		{
			RtlClearBits(&bitmap_read_lo_hdr, msr, 1);
		}
	}

	/* ... and ignore MSR_IA32_GS_BASE and MSR_IA32_KERNEL_GS_BASE  */
	RTL_BITMAP bitmap_read_hi_hdr;
	RtlInitializeBitMap(&bitmap_read_hi_hdr, (PULONG)bitmap_read_hi, 1024 * CHAR_BIT);
	RtlClearBits(&bitmap_read_hi_hdr, 0x101, 2);
	return STATUS_SUCCESS;
}

static NTSTATUS set_lock_bit(void)
{
	uintptr_t feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (feat_ctl & FEATURE_CONTROL_LOCKED)
		return STATUS_SUCCESS;

	__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | FEATURE_CONTROL_LOCKED);
	feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (feat_ctl & FEATURE_CONTROL_LOCKED)
		return STATUS_SUCCESS;

	return STATUS_HV_ACCESS_DENIED;
}

static NTSTATUS __kum_init_cpu(struct kum *k)
{
	NTSTATUS status = set_lock_bit();
	if (!NT_SUCCESS(status))
		return status;

	k->kernel_cr3 = __readcr3();
	return __vmx_vminit(vcpu_init, &kum) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

STATIC_DEFINE_DPC(__call_init, __kum_init_cpu, ctx);
NTSTATUS kum_init(void)
{
#ifndef DBG
	/*  This prevents loading in a nested environment.  */
	int info[4];
	__cpuid(info, 1);
	if (!(info[2] & (1 << 16)))
		return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

	if (__readcr4() & X86_CR4_VMXE)
		return STATUS_HV_FEATURE_UNAVAILABLE;
#endif

	if (!ept_check_capabilitiy())
		return STATUS_HV_FEATURE_UNAVAILABLE;

	if (!(__readmsr(MSR_IA32_FEATURE_CONTROL) & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX))
		return STATUS_HV_FEATURE_UNAVAILABLE;

	NTSTATUS status = init_msr_bitmap(&kum);
	if (!NT_SUCCESS(status))
		return STATUS_NO_MEMORY;

	/* Caller cr3 (could be user)  */
	kum.origin_cr3 = __readcr3();
	kum_init_phi_list();

	STATIC_CALL_DPC(__call_init, &kum);
	return STATIC_DPC_RET();
}

static NTSTATUS __kum_exit_cpu(struct kum *k)
{
	VCPU_DEBUG_RAW("going down\n");

	struct vcpu *vcpu = NULL;
	size_t err = __vmx_vmcall(HYPERCALL_STOP, &vcpu);
	if (err)
		VCPU_DEBUG("%d\n", err);
	else
		VCPU_DEBUG("stopped\n");

	k->vcpu_list[vcpu->nr] = NULL;
	vcpu_free(vcpu);
	k->active_vcpus--;
	return err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

STATIC_DEFINE_DPC(__call_exit, __kum_exit_cpu, ctx);
NTSTATUS kum_exit(void)
{
	STATIC_CALL_DPC(__call_exit, &kum);

	NTSTATUS status = STATIC_DPC_RET();
	if (NT_SUCCESS(status)) {
		kum_free_phi_list();
		ExFreePool(kum.msr_bitmap);
	}

	return status;
}

struct vcpu *kum_current_cpu(void)
{
	return kum.vcpu_list[cpu_nr()];
}
