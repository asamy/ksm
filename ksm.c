/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
 * For the macro magic (aka DEFINE_DPC, etc.) see percpu.h.
 */
static inline bool init_msr_bitmap(struct ksm *k)
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
	 * Note: for high msrs, subtract it with 0xC0000000, e.g.:
	 *	set_bit(MSR_STAR - 0xC0000000, write_hi);
	 *
	 * We currently opt in for MSRs that are VT-x related, so that we can
	 * emulate nesting.
	 */
	bitmap_t *read_lo = (bitmap_t *)k->msr_bitmap;
	set_bit(MSR_IA32_FEATURE_CONTROL, read_lo);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		set_bit(msr, read_lo);

	bitmap_t *write_lo = (bitmap_t *)((char *)k->msr_bitmap + 2048);
	set_bit(MSR_IA32_FEATURE_CONTROL, write_lo);
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		set_bit(msr, write_lo);

	return true;
}

static inline bool init_io_bitmaps(struct ksm *k)
{
	/* IO bitmap A: ports 0000H through 7FFFH  */
	k->io_bitmap_a = mm_alloc_page();
	if (!k->io_bitmap_a)
		return false;

	/* IO bitmap B: ports 8000H through FFFFh  */
	k->io_bitmap_b = mm_alloc_page();
	if (!k->io_bitmap_b) {
		mm_free_page(k->io_bitmap_a);
		return false;
	}

#if 0	/* This can be anonying  */
	bitmap_t *bitmap_a = (bitmap_t *)(k->io_bitmap_a);
	set_bit(0x60, bitmap_a);	/* PS/2 Mice  */
	set_bit(0x64, bitmap_a);	/* PS/2 Mice and keyboard  */
#endif
	return true;
}

static inline void free_msr_bitmap(struct ksm *k)
{
	if (k->msr_bitmap)
		mm_free_page(k->msr_bitmap);
}

static inline void free_io_bitmaps(struct ksm *k)
{
	if (k->io_bitmap_a)
		mm_free_page(k->io_bitmap_a);
	if (k->io_bitmap_b)
		mm_free_page(k->io_bitmap_b);
}

/*
 * Virtualizes current CPU, shared stuff, i.e. MSR bitmap
 * and IO bitmaps must be initialized prior to this call.
 */
int __ksm_init_cpu(struct ksm *k)
{
	struct vcpu *vcpu;
	int ret = ERR_NOMEM;
	u64 feat_ctl;
	u64 required_feat_bits = FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

#ifdef __linux__
	if (tboot_enabled())
		required_feat_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;
#endif

	feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feat_ctl & required_feat_bits) != required_feat_bits) {
		__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | required_feat_bits);
		feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
		if ((feat_ctl & required_feat_bits) != required_feat_bits)
			return ERR_DENIED;
	}

	vcpu = ksm_current_cpu();
	if (!vcpu_create(vcpu)) {
		VCPU_DEBUG_RAW("failed to create vcpu, oom?\n");
		return ERR_NOMEM;
	}

	/*
	 * On windows, driver entry is not reliable to get kernel cr3, but the
	 * DPC callback (this one) is guaranteed to run inside kernel context.
	 *
	 * On Linux, the situation is different, this will run in whatever
	 * process-context this CPU had...
	 *
	 * This is really trivial, I am not even sure if this is right, but it
	 * works...
	 */
#ifdef __linux__
	k->origin_cr3 = __readcr3();
#else
	k->kernel_cr3 = __readcr3();
#endif

	ret = __vmx_vminit(vcpu);
	VCPU_DEBUG("Started: %d\n", !ret);

	if (ret == 0) {
		k->active_vcpus++;
		vcpu->subverted = true;
	} else {
		vcpu_free(vcpu);
		__writecr4(__readcr4() & ~X86_CR4_VMXE);
	}

	return ret;
}

/*
 * Subvert (i.e. virtualize) all processors, this should be
 * called on initialization or to re-virtualize.
 */
static DEFINE_DPC(__call_init, __ksm_init_cpu, ctx);
int ksm_subvert(void)
{
#ifndef __linux__
	/* See comments in __ksm_init_cpu...  */
	ksm.origin_cr3 = __readcr3();
#endif

	CALL_DPC(__call_init, &ksm);
	return DPC_RET();
}

/*
 * Only called once, initializes all shared stuff, MSR bitmap,
 * and IO bitmaps, then virtualizes all available processors.
 */
int ksm_init(void)
{
	int info[4];
	u64 vpid;
	u64 req = KSM_EPT_REQUIRED_EPT
#ifdef ENABLE_PML
		| VMX_EPT_AD_BIT
#endif
#ifdef EPAGE_HOOK
		| VMX_EPT_EXECUTE_ONLY_BIT
#endif
		;

	__cpuidex(info, 1, 0);
	if (!(info[2] & (1 << (X86_FEATURE_VMX & 31))))
		return ERR_CPUID;

	if (__readcr4() & X86_CR4_VMXE)
		return ERR_BUSY;

	vpid = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if ((vpid & req) != req)
		return ERR_FEAT;

#ifdef EPAGE_HOOK
	htable_init(&ksm.ht, rehash, NULL);
#endif

	if (!init_msr_bitmap(&ksm))
		return ERR_NOMEM;

	if (!init_io_bitmaps(&ksm)) {
		/*
		 * Hashtable is on-demand allocation, no need to clear it
		 * here...
		 */
		free_msr_bitmap(&ksm);
		return ERR_NOMEM;
	}

	return 0;
}

/*
 * Devirtualizes current processor, if the current processor
 * is not virtualized, an error is returned.
 */
int __ksm_exit_cpu(struct ksm *k)
{
	int ret = ERR_NOTH;
	struct vcpu *vcpu = ksm_current_cpu();

	if (!vcpu->subverted)
		return ret;

	ret = __vmx_vmcall(HYPERCALL_STOP, NULL);
	if (ret == 0) {
		k->active_vcpus--;
		vcpu->subverted = false;
		vcpu_free(vcpu);
		__writecr4(__readcr4() & ~X86_CR4_VMXE);
	}

	return ret;
}

/*
 * Devirtualize all processors, returning an error if one or
 * more aren't virtualized...
 */
DEFINE_DPC(__call_exit, __ksm_exit_cpu, ctx);
int ksm_unsubvert(void)
{
	if (ksm.active_vcpus == 0)
		return ERR_NOTH;

	CALL_DPC(__call_exit, &ksm);
	return DPC_RET();
}

/*
 * Frees resources and devirtualizes all processors,
 * Only called on driver unload...
 */
int ksm_exit(void)
{
	int err;

	err = ksm_unsubvert();
	if (err == 0) {
		free_msr_bitmap(&ksm);
		free_io_bitmaps(&ksm);
#ifdef EPAGE_HOOK
		htable_clear(&ksm.ht);
#endif
	}

	return err;
}

/*
 * Hook the IDT entry at index @n, and redirect it to the function
 * @h, should always succeed unless one of the processors are not
 * virtualized, may throw an exception since it does __vmx_vmcall
 * without checking.
 */
static DEFINE_DPC(__call_idt_hook, __vmx_vmcall, HYPERCALL_IDT, ctx);
int ksm_hook_idt(unsigned n, void *h)
{
	CALL_DPC(__call_idt_hook, &(struct shadow_idt_entry) {
		.n = n,
		.h = h,
	});
	return DPC_RET();
}

/*
 * Unhook an IDT entry at index @n, restoring last known one.
 * Note: if you call `ksm_hook_idt` on same entry twice, then this will
 * restore first call, not the original!
 *
 * IDT is always restored to the real one when devirtualization happens,
 * disregarding all entries that were set prior.
 */
static DEFINE_DPC(__call_idt_unhook, __vmx_vmcall, HYPERCALL_UIDT, ctx);
int ksm_free_idt(unsigned n)
{
	CALL_DPC(__call_idt_unhook, &(struct shadow_idt_entry) {
		.n = n,
		.h = NULL,
	});
	return DPC_RET();
}

