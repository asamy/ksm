/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
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

/*
 * This file mostly manages CPUs initialization and deinitialization
 * but is not limited to that, it also initializes shared stuff and defines
 * some shared functions such as ksm_read_virt()/ksm_write_virt(), which can
 * be called from root mode to read/write to a guest virtual address.
 *
 * For per-cpu initializaiton see vcpu.c.
 * For VM-exit handlers see exit.c.
 * For the macro magic (aka DEFINE_DPC, etc.) see percpu.h.
 *
 * The `ksm' structure is a shared structure, it shares common things between
 * all CPUs such as I/O bitmaps, MSR bitmap, etc, however, this global variable
 * `ksm' is not supposed to be used inside root, you should instead utilize the
 * function (defined in ksm.h): vcpu_to_ksm() as follows:
 *	struct ksm *k = vcpu_to_ksm(vcpu);
 */
struct ksm *ksm = NULL;

/*
 * Setup the MSR bitmap.
 * There are 4 things here:
 *	- Read bitmap low (aka MSR indices of 0 to 1FFFH)
 *		offset: +0
 *	- Read bitmap high (aka MSR indices of 0xC0000000 to 0xC0001FFFH)
 *		offset; +1024
 *	- Write bitmap low (same thing as read low)
 *		offset: +2048
 *	- Write bitmap high (same thing as read high)
 *		offset: +3072
 *
 * To opt-in for an MSR vm-exit, simply set the bit of it.
 * Note: for high msrs, subtract it with 0xC0000000, e.g.:
 *	set_bit(MSR_STAR - 0xC0000000, write_hi);
 *
 * We currently opt in for reads to MSRs that are VT-x related, so that we can
 * emulate VT-x ("nesting").
 *
 * Note: No real reason to opt-in for writes to VT-x MSRs, those are readonly
 * anyway and the CPU will throw #GP to any writes there.
 *
 * See also:
 *	vcpu_handle_rdmsr()  in exit.c
 *	vcpu_handle_wrmsr()  in exit.c
 */
static inline void init_msr_bitmap(struct ksm *k)
{
	unsigned long *read_lo = (unsigned long *)k->msr_bitmap;
	set_bit(MSR_IA32_FEATURE_CONTROL, read_lo);
#ifdef NESTED_VMX
	for (u32 msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; ++msr)
		set_bit(msr, read_lo);
#endif

#ifdef NESTED_VMX
	unsigned long *write_lo = (unsigned long *)((char *)k->msr_bitmap + 2048);
	set_bit(MSR_IA32_FEATURE_CONTROL, write_lo);
#endif
}

static inline void init_io_bitmaps(struct ksm *k)
{
	/*
	 * Setuo I/O bitmaps, see:
	 *	vcpu_handle_io_instr() in exit.c
	*/

#if 0	/* This can be anonying  */
	unsigned long *bitmap_a = (unsigned long *)(k->io_bitmap_a);
	set_bit(0x60, bitmap_a);	/* PS/2 Mice  */
	set_bit(0x64, bitmap_a);	/* PS/2 Mice and keyboard  */
#endif
}

/*
 * Virtualizes current CPU.
 */
int __ksm_init_cpu(struct ksm *k)
{
	struct vcpu *vcpu;
	int ret = ERR_NOMEM;
	u64 feat_ctl;
	u64 required_feat_bits = FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	vcpu = ksm_cpu(k);
	if (vcpu->subverted) {
		KSM_DEBUG_RAW("CPU already subverted\n");
		return 0;
	}

#ifdef __linux__
	if (tboot_enabled())
		required_feat_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;
#endif

	feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feat_ctl & required_feat_bits) != required_feat_bits) {
		if (feat_ctl & FEATURE_CONTROL_LOCKED)
			return ERR_BUSY;

		__writemsr(MSR_IA32_FEATURE_CONTROL, feat_ctl | required_feat_bits);
		feat_ctl = __readmsr(MSR_IA32_FEATURE_CONTROL);
		if ((feat_ctl & required_feat_bits) != required_feat_bits)
			return ERR_DENIED;
	}

	ret = vcpu_init(vcpu);
	if (ret < 0) {
		KSM_DEBUG_RAW("failed to create vcpu, oom?\n");
		return ret;
	}

	/* Saves state and calls vcpu_run() (Defined in assembly, vmx.{S,asm} */
	ret = __vmx_vminit(vcpu);
	KSM_DEBUG("%s: Started: %d\n", proc_name(), !ret);

	if (ret < 0)
		goto out;

	vcpu->subverted = true;
	k->active_vcpus++;
	return 0;

out:
	vcpu_free(vcpu);
	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	return ret;
}

/*
 * Subvert (i.e. virtualize) all processors, this should be
 * called on initialization or to re-virtualize.
 */
static DEFINE_DPC(__call_init, __ksm_init_cpu, ctx);
int ksm_subvert(struct ksm *k)
{
	CALL_DPC(__call_init, k);
	return DPC_RET();
}

/*
 * Initialize and allocate the shared structure.
 */
int ksm_init(struct ksm **kp)
{
	struct mtrr_range *range;
	struct ksm *k;
	int info[4];
	int ret = ERR_NOMEM;
	int i;
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

	k = mm_alloc_pool(sizeof(*k));
	if (!k)
		return ret;

	k->vpid_ept = vpid;
	KSM_DEBUG("EPT/VPID caps: 0x%016llX\n", vpid);

	ret = mm_cache_ram_ranges(&k->ranges[0], &k->range_count);
	if (ret < 0)
		goto out_ksm;

	KSM_DEBUG("%d physical memory ranges\n", k->range_count);
	for (i = 0; i < k->range_count; ++i)
		KSM_DEBUG("Range: 0x%016llX -> 0x%016llX\n", k->ranges[i].start, k->ranges[i].end);

	/* MTRR   */
	mm_cache_mtrr_ranges(&k->mtrr_ranges[0], &k->mtrr_count, &k->mtrr_def);
	KSM_DEBUG("%d MTRR ranges (%d default type)\n", k->mtrr_count, k->mtrr_def);
	for (i = 0; i < k->mtrr_count; i++) {
		range = &k->mtrr_ranges[i];
		KSM_DEBUG("MTRR Range: 0x%016llX -> 0x%016llX fixed: %d type: %d\n",
			  range->start, range->end, range->fixed, range->type);
	}

#ifdef EPAGE_HOOK
	ret = ksm_epage_init(k);
	if (ret < 0)
		goto out_ksm;
#endif

#ifdef PMEM_SANDBOX
	ret = ksm_sandbox_init(k);
	if (ret < 0)
		goto out_epage;
#endif

#ifdef INTROSPECT_ENGINE
	ret = ksm_introspect_init(k);
	if (ret < 0)
		goto out_sbox;
#endif

	ret = register_power_callback();
	if (ret < 0)
		goto out_intro;

	ret = register_cpu_callback();
	if (ret == 0) {
		init_msr_bitmap(k);
		init_io_bitmaps(k);
		*kp = k;
		return ret;
	}

	unregister_power_callback();
out_intro:
#ifdef INTROSPECT_ENGINE
	ksm_introspect_exit(k);
out_sbox:
#endif
#ifdef PMEM_SANDBOX
	ksm_sandbox_exit(k);
out_epage:
#endif
#ifdef EPAGE_HOOK
	ksm_epage_exit(k);
#endif
out_ksm:
	mm_free_pool(k, sizeof(*k));
	return ret;
}

/*
 * Devirtualizes current processor, if the current processor
 * is not virtualized, an error is returned.
 */
int __ksm_exit_cpu(struct ksm *k)
{
	int ret = ERR_NOTH;
	struct vcpu *vcpu = ksm_cpu(k);
	if (!vcpu->subverted)
		return ret;

	ret = __vmx_vmcall(HCALL_STOP, NULL);
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
int ksm_unsubvert(struct ksm *k)
{
	if (k->active_vcpus == 0)
		return ERR_NOTH;

	CALL_DPC(__call_exit, k);
	return DPC_RET();
}

/*
 * Frees resources and devirtualizes all processors,
 * Only called on driver unload...
 */
int ksm_free(struct ksm *k)
{
	int ret;

	/* These may need virtualization active...  */
#ifdef PMEM_SANDBOX
	ksm_sandbox_exit(k);
#endif
#ifdef INTROSPECT_ENGINE
	ksm_introspect_exit(k);
#endif

	/* Desubvert all:  */
	ret = ksm_unsubvert(k);

#ifdef EPAGE_HOOK
	ksm_epage_exit(k);
#endif

	unregister_cpu_callback();
	unregister_power_callback();
	mm_free_pool(k, sizeof(*k));
	return ret;
}

/*
 * Hook the IDT entry at index @n, and redirect it to the function
 * @h, should always succeed unless one of the processors are not
 * virtualized, may throw an exception since it does __vmx_vmcall
 * without checking.
 */
static DEFINE_DPC(__call_idt_hook, __vmx_vmcall, HCALL_IDT, ctx);
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
 * restore the one from first call, not the original!
 *
 * IDT is always restored to the real one when devirtualization happens,
 * disregarding all entries that were set prior.
 */
static DEFINE_DPC(__call_idt_unhook, __vmx_vmcall, HCALL_UIDT, ctx);
int ksm_free_idt(unsigned n)
{
	CALL_DPC(__call_idt_unhook, &(struct shadow_idt_entry) {
		.n = n,
		.h = NULL,
	});
	return DPC_RET();
}

/*
 * Write @data of length @len into @gva.
 * If it returns false, a fault should be injected.
 */
bool ksm_write_virt(struct vcpu *vcpu, u64 gva, const u8 *data, size_t len)
{
	pte_t *pte;
	u64 hpa;
	size_t off;
	size_t copy;
	uintptr_t cr3;
	char *tmp;

	off = 0;
	cr3 = vmcs_read(GUEST_CR3);
	while (len) {
		pte = __gva_to_gpa(vcpu, cr3, gva,
				   PAGE_PRESENT | PAGE_WRITE);
		if (!pte)
			return false;

		if (!gpa_to_hpa(vcpu, PAGE_PPA(pte), &hpa))
			return false;

		tmp = mm_remap(hpa, PAGE_SIZE);
		if (!tmp)
			return false;

		/* Write up to remaining in the page, not in len.  */
		off = addr_offset(gva);
		copy = min(len, PAGE_SIZE - off);
		memcpy(tmp + off, data, copy);
		mm_unmap(tmp, PAGE_SIZE);

		/* Mark it dirty  */
		mark_pte_dirty(pte);

		len -= copy;
		data += copy;
		gva += copy;
	}

	return true;
}

/*
 * Read from @gpa into @data of length @len
 * If it returns false, a fault should be injected.
 */
bool ksm_read_virt(struct vcpu *vcpu, u64 gva, u8 *data, size_t len)
{
	pte_t *pte;
	u64 hpa;
	size_t off;
	size_t copy;
	uintptr_t cr3;
	u8 *tmp;
	u8 *d;

	d = data;
	off = 0;
	cr3 = vmcs_read(GUEST_CR3);
	while (len) {
		pte = __gva_to_gpa(vcpu, cr3, gva, PAGE_PRESENT);
		if (!pte)
			return false;

		if (!gpa_to_hpa(vcpu, PAGE_PPA(pte), &hpa))
			return false;

		tmp = mm_remap(hpa, PAGE_SIZE);
		if (!tmp)
			return false;

		/* Read up to remaining in the page, not in len.  */
		off = addr_offset(gva);
		copy = min(len, PAGE_SIZE - off);
		memcpy(d, tmp + off, copy);
		mm_unmap(tmp, PAGE_SIZE);

		/* Mark it accessed  */
		mark_pte_accessed(pte);

		len -= copy;
		d += copy;
		gva += copy;
	}

	return true;
}
