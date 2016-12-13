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
#include <ntddk.h>
#include <intrin.h>

#include "ksm.h"
#include "dpc.h"

struct ksm ksm = {
	.active_vcpus = 0,
};

/*
 * This file manages CPUs initialization, for per-cpu initializaiton
 * see vcpu.c, for VM-exit handlers see exit.c
 *
 * For the macro magic (aka STATIC_DEFINE_DPC, etc.) see dpc.h,
 * DPCs are for per-processor callbacks.
 */
static void init_msr_bitmap(struct ksm *k)
{
	/*
	 * Setup the MSR bitmap, opt-in for VM-exit for some MSRs
	 * Mostly the VMX msrs so we don't cause too much havoc.
	 *
	 * There are 4 things here:
	 *	- Read bitmap low (aka MSR indices of 0 to 1FFFH)
	 *	- Read bitmap high (aka MSR indices of 0xC0000000 to 0xC0001FFFH)
	 *	- Write bitmap low (same thing as read)
	 *	- Write bitmap high (same thing as read)
	 *
	 * To opt-in for an MSR vm-exit, simply set the bit of it.
	 * Note: for high msrs, subtract it with 0xC0000000.
	 */
	u8 *bitmap_read_lo = k->msr_bitmap;
	RTL_BITMAP bitmap_read_lo_hdr;
	RtlInitializeBitMap(&bitmap_read_lo_hdr, (PULONG)bitmap_read_lo, 1024 * CHAR_BIT);
	RtlSetBit(&bitmap_read_lo_hdr, MSR_IA32_FEATURE_CONTROL);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		RtlSetBit(&bitmap_read_lo_hdr, msr);

#if 0 
	if (lapic_in_kernel() && x2apic_enabled())
		RtlSetBits(&bitmap_read_lo_hdr, 0x800, 0x100);
#endif

	u8 *bitmap_read_hi = bitmap_read_lo + 1024;
	RTL_BITMAP bitmap_read_hi_hdr;
	RtlInitializeBitMap(&bitmap_read_hi_hdr, (PULONG)bitmap_read_hi, 1024 * CHAR_BIT);

	u8 *bitmap_write_lo = bitmap_read_hi + 1024;
	RTL_BITMAP bitmap_write_lo_hdr;
	RtlInitializeBitMap(&bitmap_write_lo_hdr, (PULONG)bitmap_write_lo, 1024 * CHAR_BIT);
	RtlSetBit(&bitmap_write_lo_hdr, MSR_IA32_FEATURE_CONTROL);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		RtlSetBit(&bitmap_write_lo_hdr, msr);

#if 0
	if (lapic_in_kernel() && x2apic_enabled())
		RtlSetBits(&bitmap_write_lo_hdr, 0x800, 0x100);
#endif

	u8 *bitmap_write_hi = bitmap_write_lo + 1024;
	RTL_BITMAP bitmap_write_hi_hdr;
	RtlInitializeBitMap(&bitmap_write_hi_hdr, (PULONG)bitmap_write_hi, 1024 * CHAR_BIT);
}

static void init_io_bitmaps(struct ksm *k)
{
#if 0
	/* This can be anonying  */
	RTL_BITMAP bitmap_a;
	RtlInitializeBitMap(&bitmap_a, (PULONG)k->io_bitmap_a, PAGE_SIZE * CHAR_BIT);
	RtlSetBit(&bitmap_a, 0x60);	/* PS/2 Mice  */
	RtlSetBit(&bitmap_a, 0x64);	/* PS/2 Mice and keyboard  */
#endif
}

static NTSTATUS set_lock_bit(void)
{
	/* Required MSR_IA32_FEATURE_CONTROL bits:  */
	const u64 required_feat_bits = FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	uintptr_t feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feat_ctl & required_feat_bits) == required_feat_bits)
		return STATUS_SUCCESS;

	/* Attempt to set bits in place  */
	__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | required_feat_bits);

	feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feat_ctl & required_feat_bits) == required_feat_bits)
		return STATUS_SUCCESS;

	return STATUS_HV_ACCESS_DENIED;
}

static NTSTATUS __ksm_init_cpu(struct ksm *k)
{
#ifndef __GNUC__
	__try {
#endif
		NTSTATUS status = set_lock_bit();
		if (!NT_SUCCESS(status))
			return status;

		k->kernel_cr3 = __readcr3();
		if (__vmx_vminit(&k->vcpu_list[cpu_nr()])) {
			k->active_vcpus++;
			return STATUS_SUCCESS;
		}
#ifndef __GNUC__
	} __except (EXCEPTION_EXECUTE_HANDLER)
	{
		__writecr4(__readcr4() & ~X86_CR4_VMXE);
		return GetExceptionCode();
	}
#endif

	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	return STATUS_NOT_SUPPORTED;
}

static void ksm_hotplug_cpu(void *ctx, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT change_ctx, PNTSTATUS op_status)
{
	/* CPU Hotplug callback, a CPU just came online.  */
	GROUP_AFFINITY affinity;
	GROUP_AFFINITY prev;
	PPROCESSOR_NUMBER pnr;
	NTSTATUS status;

	if (change_ctx->State == KeProcessorAddCompleteNotify) {
		pnr = &change_ctx->ProcNumber;
		affinity.Group = pnr->Group;
		affinity.Mask = 1ULL << pnr->Number;
		KeSetSystemGroupAffinityThread(&affinity, &prev);

		VCPU_DEBUG_RAW("New processor\n");
		status = __ksm_init_cpu(&ksm);
		if (!NT_SUCCESS(status))
			*op_status = status;

		KeRevertToUserGroupAffinityThread(&prev);
	}
}

STATIC_DEFINE_DPC(__call_init, __ksm_init_cpu, ctx);
NTSTATUS ksm_subvert(void)
{
	STATIC_CALL_DPC(__call_init, &ksm);
	return STATIC_DPC_RET();
}

NTSTATUS ksm_init(void)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int info[4];

	__cpuid(info, 1);
	if (!(info[2] & (1 << (X86_FEATURE_VMX & 31))))
		return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

	if (__readcr4() & X86_CR4_VMXE)
		return STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE;	/* closet...  */

	if (!ept_check_capabilitiy())
		return STATUS_HV_FEATURE_UNAVAILABLE;

	/* Zero out everything (this is allocated by the kernel device driver
	 * loader)  */
	__stosq((unsigned long long *)&ksm, 0, sizeof(ksm) >> 3);

	ksm.hotplug_cpu = KeRegisterProcessorChangeCallback(ksm_hotplug_cpu, NULL, 0);
	if (!ksm.hotplug_cpu)
		return status;

	/* Caller cr3 (could be user)  */
	ksm.origin_cr3 = __readcr3();
	htable_init(&ksm.ht, rehash, NULL);

	init_msr_bitmap(&ksm);
	init_io_bitmaps(&ksm);

	if (!NT_SUCCESS(status = ksm_subvert()))
		KeDeregisterProcessorChangeCallback(ksm.hotplug_cpu);
	
	return status;
}

static NTSTATUS __ksm_exit_cpu(struct ksm *k)
{
	size_t err;
#ifndef __GNUC__
	__try {
#endif
		err = __vmx_vmcall(HYPERCALL_STOP, NULL);
		VCPU_DEBUG("Stopped: %d\n", err);
#ifndef __GNUC__
	} __except (EXCEPTION_EXECUTE_HANDLER)
	{
		VCPU_DEBUG("this processor is not virtualized: 0x%08X\n", GetExceptionCode());
		return STATUS_HV_NOT_PRESENT;
	}
#endif

	if (err)
		return STATUS_UNSUCCESSFUL;

	k->active_vcpus--;
	vcpu_free(ksm_current_cpu());
	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	return STATUS_SUCCESS;
}

STATIC_DEFINE_DPC(__call_exit, __ksm_exit_cpu, ctx);
NTSTATUS ksm_unsubvert(void)
{
	STATIC_CALL_DPC(__call_exit, &ksm);
	return STATIC_DPC_RET();
}

NTSTATUS ksm_exit(void)
{
	if (ksm.hotplug_cpu)
		KeDeregisterProcessorChangeCallback(ksm.hotplug_cpu);

	return ksm_unsubvert();
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
	return &ksm.vcpu_list[cpu_nr()];
}
