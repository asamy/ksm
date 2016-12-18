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
#ifdef __linux__
#include <linux/kernel.h>
#include <linux/tboot.h>
#include <linux/cpu.h>
#else
#include <ntddk.h>
#include <intrin.h>
#endif

#include "ksm.h"
#include "percpu.h"
#include "bitmap.h"

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
static bool init_msr_bitmap(struct ksm *k)
{
	k->msr_bitmap = mm_alloc_page();
	if (!k->msr_bitmap)
		return false;

	/*
	 * Setup the MSR bitmap, opt-in for VM-exit for some MSRs
	 * Mostly the VMX msrs so we don't cause too much havoc.
	 *
	 * There are 4 things here:
	 *	- Read bitmap low (aka MSR indices of 0 to 1FFFH)
	 *		offset: +0
	 *	- Read bitmap high (aka MSR indices of 0xC0000000 to 0xC0001FFFH)
	 *		offset; +1024
	 *	- Write bitmap low (same thing as read)
	 *		offset: +2048
	 *	- Write bitmap high (same thing as read)
	 *		offset: +3072
	 *
	 * To opt-in for an MSR vm-exit, simply set the bit of it.
	 * Note: for high msrs, subtract it with 0xC0000000.
	 *
	 * We currently opt in for MSRs that are VT-x related, so that we can
	 * emulate nesting.
	 */
#if 0
	bitmap_t *read_lo = (bitmap_t *)k->msr_bitmap;
	set_bit(MSR_IA32_FEATURE_CONTROL, read_lo);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		set_bit(msr, read_lo);

	bitmap_t *write_lo = (bitmap_t *)(k->msr_bitmap + 2048);
	set_bit(MSR_IA32_FEATURE_CONTROL, write_lo);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		set_bit(msr, write_lo);
#endif
	return true;
}

static bool init_io_bitmaps(struct ksm *k)
{
	k->io_bitmap_a = mm_alloc_page();
	if (!k->io_bitmap_a)
		return false;

	k->io_bitmap_b = mm_alloc_page();
	if (!k->io_bitmap_b) {
		mm_free_page(k->io_bitmap_b);
		return false;
	}

#if 0	/* This can be anonying  */
	bitmap_t *bitmap_a = (bitmap_t *)(k->io_bitmap_a);
	set_bit(0x60, bitmap_a);	/* PS/2 Mice  */
	set_bit(0x64, bitmap_a);	/* PS/2 Mice and keyboard  */
#endif
	return true;
}

static void free_msr_bitmap(struct ksm *k)
{
	if (k->msr_bitmap)
		mm_free_page(k->msr_bitmap);
}

static void free_io_bitmaps(struct ksm *k)
{
	if (k->io_bitmap_a)
		mm_free_page(k->io_bitmap_a);
	if (k->io_bitmap_b)
		mm_free_page(k->io_bitmap_b);
}

int __ksm_init_cpu(struct ksm *k)
{
	/* Required MSR_IA32_FEATURE_CONTROL bits:  */
	u64 required_feat_bits = FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
#ifdef __linux__
	if (tboot_enabled())
		required_feat_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;
#endif

#ifndef __GNUC__
	__try {
#endif
		u64 feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
		if ((feat_ctl & required_feat_bits) != required_feat_bits) {
			/* Attempt to set bits in place  */
			__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | required_feat_bits);

			feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
			if ((feat_ctl & required_feat_bits) != required_feat_bits)
				return ERR_DENIED;
		}


		bool ok = __vmx_vminit(&k->vcpu_list[cpu_nr()]);
		if (ok) {
			k->active_vcpus++;
			return 0;
		}
#ifndef __GNUC__
	} __except (EXCEPTION_EXECUTE_HANDLER)
	{
		__writecr4(__readcr4() & ~X86_CR4_VMXE);
		return ERR_EXCEPT;
	}
#endif

	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	return ERR_UNSUP;
}

STATIC_DEFINE_DPC(__call_init, __ksm_init_cpu, ctx);
int ksm_subvert(void)
{
	STATIC_CALL_DPC(__call_init, &ksm);
	return STATIC_DPC_RET();
}

int ksm_init(void)
{
	int err;
	int info[4];
	__cpuidex(info, 1, 0);

	if (!(info[2] & (1 << (X86_FEATURE_VMX & 31))))
		return ERR_CPUID;

	if (__readcr4() & X86_CR4_VMXE)
		return ERR_NESTED;

	if (!ept_check_capabilitiy())
		return ERR_FEAT;

	/*
	 * Zero out everything (this is allocated by the kernel device driver
	 * loader)
	 */
	__stosq((unsigned long long *)&ksm, 0, sizeof(ksm) >> 3);

	/* Caller cr3 (could be user)  */
	ksm.origin_cr3 = __readcr3();

#ifdef EPAGE_HOOK
	htable_init(&ksm.ht, rehash, NULL);
#endif

	if (!init_msr_bitmap(&ksm))
		return ERR_NOMEM;

	if (!init_io_bitmaps(&ksm)) {
		free_msr_bitmap(&ksm);
		return ERR_NOMEM;
	}

	err = ksm_subvert();
	if (err < 0) {
		free_msr_bitmap(&ksm);
		free_io_bitmaps(&ksm);
	}

	return err;
}

static int __ksm_exit_cpu(struct ksm *k)
{
	u8 err;

#ifndef __GNUC__
	__try {
#endif
		err = __vmx_vmcall(HYPERCALL_STOP, NULL);
		VCPU_DEBUG("Stopped: %d\n", err);
#ifndef __GNUC__
	} __except (EXCEPTION_EXECUTE_HANDLER)
	{
		VCPU_DEBUG("this processor is not virtualized: 0x%08X\n", ERR_EXCEPT);
		return ERR_EXCEPT;
	}
#endif

	if (err == 0) {
		k->active_vcpus--;
		vcpu_free(ksm_current_cpu());
		__writecr4(__readcr4() & ~X86_CR4_VMXE);
	}

	return err;
}

STATIC_DEFINE_DPC(__call_exit, __ksm_exit_cpu, ctx);
int ksm_unsubvert(void)
{
	STATIC_CALL_DPC(__call_exit, &ksm);
	return STATIC_DPC_RET();
}

int ksm_exit(void)
{
	int err;
	if (ksm.active_vcpus == 0)
		return ERR_EXIST;

	err = ksm_unsubvert();
	if (err == 0) {
		free_msr_bitmap(&ksm);
		free_io_bitmaps(&ksm);
#ifdef EPAGE_HOOK
		htable_clear(&ksm.ht);
#endif
	}

	return 0;
}

STATIC_DEFINE_DPC(__call_idt_hook, __vmx_vmcall, HYPERCALL_IDT, ctx);
int ksm_hook_idt(unsigned n, void *h)
{
	STATIC_CALL_DPC(__call_idt_hook, &(struct shadow_idt_entry) {
		.n = n,
		.h = h,
	});
	return STATIC_DPC_RET();
}

STATIC_DEFINE_DPC(__call_idt_unhook, __vmx_vmcall, HYPERCALL_UIDT, ctx);
int ksm_free_idt(unsigned n)
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
