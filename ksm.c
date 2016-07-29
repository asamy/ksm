#include "vcpu.h"
#include "dpc.h"

struct ksm ksm = {
	.active_vcpus = 0,
};

static NTSTATUS init_msr_bitmap(struct ksm *k)
{
	void *msr_bitmap = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
	if (!msr_bitmap)
		return STATUS_NO_MEMORY;

	k->msr_bitmap = msr_bitmap;
	RtlZeroMemory(msr_bitmap, PAGE_SIZE);

	u8 *bitmap_read_lo = (u8 *)msr_bitmap;
	RTL_BITMAP bitmap_read_lo_hdr;
	RtlInitializeBitMap(&bitmap_read_lo_hdr, (PULONG)bitmap_read_lo, 1024 * CHAR_BIT);
	RtlClearBits(&bitmap_read_lo_hdr, MSR_IA32_MPERF, 2);

	u8 *bitmap_read_hi = bitmap_read_lo + 1024;
	RTL_BITMAP bitmap_read_hi_hdr;
	RtlInitializeBitMap(&bitmap_read_hi_hdr, (PULONG)bitmap_read_hi, 1024 * CHAR_BIT);
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

static NTSTATUS __ksm_init_cpu(struct ksm *k)
{
	NTSTATUS status = set_lock_bit();
	if (!NT_SUCCESS(status))
		return status;

	k->kernel_cr3 = __readcr3();
	return __vmx_vminit(vcpu_init, k) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static void ksm_hotplug_cpu(void *ctx, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT change_ctx, PNTSTATUS op_status)
{
	if (change_ctx->State == KeProcessorAddCompleteNotify) {
		/* virtualize it.   */
		*op_status = __ksm_init_cpu(&ksm);
	}
}

STATIC_DEFINE_DPC(__call_init, __ksm_init_cpu, ctx);
NTSTATUS ksm_init(void)
{
	NTSTATUS status;
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

	ksm.hotplug_cpu = KeRegisterProcessorChangeCallback(ksm_hotplug_cpu, &status, 0);
	if (!ksm.hotplug_cpu)
		return status;

	status = init_msr_bitmap(&ksm);
	if (!NT_SUCCESS(status))
		goto err_hotplug;

	/* Caller cr3 (could be user)  */
	ksm.origin_cr3 = __readcr3();
	htable_init(&ksm.ht, rehash, NULL);

	STATIC_CALL_DPC(__call_init, &ksm);
	return STATIC_DPC_RET();

err_hotplug:
	KeDeregisterProcessorChangeCallback(ksm.hotplug_cpu);
	return status;
}

static NTSTATUS __ksm_exit_cpu(struct ksm *k)
{
	VCPU_DEBUG_RAW("going down\n");

	struct vcpu *vcpu = NULL;
	size_t err = __vmx_vmcall(HYPERCALL_STOP, &vcpu);
	if (err)
		VCPU_DEBUG("%d\n", err);
	else
		VCPU_DEBUG("stopped\n");

	k->vcpu_list[cpu_nr()] = NULL;
	k->active_vcpus--;
	vcpu_free(vcpu);
	return err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

STATIC_DEFINE_DPC(__call_exit, __ksm_exit_cpu, ctx);
NTSTATUS ksm_exit(void)
{
	STATIC_CALL_DPC(__call_exit, &ksm);

	NTSTATUS status = STATIC_DPC_RET();
	if (NT_SUCCESS(status)) {
		if (ksm.hotplug_cpu)
			KeDeregisterProcessorChangeCallback(ksm.hotplug_cpu);
		ExFreePool(ksm.msr_bitmap);
	}

	return status;
}

STATIC_DEFINE_DPC(__call_idt_hook, __vmx_vmcall, HYPERCALL_IDT, ctx);
NTSTATUS ksm_hook_idt(unsigned n, void *h)
{
	STATIC_CALL_DPC(__call_idt_hook, &(struct shadow_idt_entry) {
		.n = n,
		.h = h,
	});
	return STATIC_DPC_RET();
}

STATIC_DEFINE_DPC(__call_idt_unhook, __vmx_vmcall, HYPERCALL_UIDT, ctx);
NTSTATUS ksm_free_idt(unsigned n)
{
	STATIC_CALL_DPC(__call_idt_unhook, &(struct shadow_idt_entry) {
		.n = n,
		.h = NULL,
	});
	return STATIC_DPC_RET();
}

struct vcpu *ksm_current_cpu(void)
{
	return ksm.vcpu_list[cpu_nr()];
}
