/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Executable page hooking, see comments down below for more
 * information.
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
#ifdef EPAGE_HOOK
#ifdef __linux__
#include <linux/vmalloc.h>
#else
#include <ntddk.h>
#endif

#include "ksm.h"
#include "percpu.h"

/*!
 * To use this interface, call ksm_hook_epage() on the target function,
 * e.g.:
 * \code
 *	ksm_hook_epage(MmMapIoSpace, hkMmMapIoSpace);
 * \endcode
 *
 * And for original function call:
 * \code
 *	vcpu_vmfunc(EPTP_NORMAL, 0);
 *	void *ret = MmMapIoSpace(x, y, z);
 *	vcpu_vmfunc(EPTP_EXHOOK, 0);
 *	return ret;
 * \endcode
 */
static inline void epage_init_eptp(struct page_hook_info *phi, struct ept *ept)
{
	/* Called from vmcall (exit.c)  */
	ept_alloc_page(EPT4(ept, EPTP_EXHOOK), EPT_ACCESS_EXEC, phi->dpa, phi->cpa);
	ept_alloc_page(EPT4(ept, EPTP_RWHOOK), EPT_ACCESS_RW, phi->dpa, phi->dpa);
	ept_alloc_page(EPT4(ept, EPTP_NORMAL), EPT_ACCESS_EXEC, phi->dpa, phi->dpa);

	__invvpid_all();
	__invept_all();
}

static inline u16 epage_select_eptp(struct page_hook_info *phi, u16 cur, u8 ar, u8 ac)
{
	/* called from an EPT violation  */
	if (ac & EPT_ACCESS_RW)
		return EPTP_RWHOOK;

	return EPTP_EXHOOK;
}

static struct phi_ops epage_ops = {
	.init_eptp = epage_init_eptp,
	.select_eptp = epage_select_eptp,
};

static inline bool ht_cmp(const void *candidate, void *cmp)
{
	const struct page_hook_info *phi = candidate;
	return phi->origin == (uintptr_t)cmp;
}

#ifndef __linux__
#include <pshpack1.h>
#endif
struct trampoline {
	u8 push;
	u32 lo;
	u32 mov;
	u32 hi;
	u32 ret;
} __packed;
#ifndef __linux__
#include <poppack.h>
#endif

static void epage_init_trampoline(struct trampoline *trampo, u64 to)
{
	// push lo
	// mov dword ptr [rsp + 0x4], hi
	// ret
	trampo->push = 0x68;
	trampo->lo = (u32)to;
	trampo->mov = 0x042444C7;
	trampo->hi = to >> 32;
	trampo->ret = 0xC3;
}

static DEFINE_DPC(__do_hook_page, __vmx_vmcall, HYPERCALL_HOOK, ctx);
static DEFINE_DPC(__do_unhook_page, __vmx_vmcall, HYPERCALL_UNHOOK, ctx);

/*
 * Note!!!
 * This function is not very robust, e.g. pages that are not
 * physically contiguous will cause havoc, on the Linux kernel
 * this can be a problem when hooking kernel pages, specfiically
 * module pages as those are allocated using vmalloc() and are not
 * physically contiguous, so be careful.
 *
 * On windows, kernel pages are always physically contiguous unless they are
 * in the PAGE section, so this will handle most cases.
 *
 * On windows, you can lock pages using:
 * \code
 *	PMDL mdl = IoAllocateMdl(original, PAGE_SIZE, FALSE, FALSE, NULL);
 *	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
 * \endcode
 *
 * Then unlock in unhook:
 * \code
 *	MmUnlockPages(mdl);
 *	IoFreeMdl(mdl);
 * \endcode
 *
 * On Linux this can be something like:
 * \code
 *	struct page *page = vmalloc_to_page(original);
 *	void *tmp = kmap(page);
 *	u64 pa = __pa(tmp);
 * \endcode
 *
 * On unlock:
 * \code
 *	kunmap(page);
 * \endcode
 *
 *	Notes on hooking out-of-kernel pages (e.g. userspace pages or similar):
 *	
 * When hooking a userspace specific function, you should first attach to that
 * specific process (if not already), to make sure that the current CR3 is
 * updated.  Also do note that userspace pages tend to be paged out all the
 * time, so the above notes also apply.
 *
 * On windows, this can be something like:
 *
 * \code
 *	HANDLE pid = ...;
 *	PEPROCESS process;
 *	KAPC_STATE apc;
 *	NTSTATUS ret = STATUS_NOT_FOUND;
 *	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
 *		return ret;
 *
 *	KeStackAttachProcess(process, &apc);
 *		ret = ksm_hook_epage(original, redirect);
 *	KeUnStackDeAttachProcess(&apc);
 *	ObfDereferenceObject(process);
 *	return ret;
 * \endcode
 *
 * On Linux:
 *
 * \code
 *	pid_t pid = ...;
 *	struct pid *tsk_pid = find_vpid(pid);
 *	unsigned long cr3 = __readcr3();
 *	int ret = -ENOENT;
 *
 *	if (!tsk_pid);
 *		return ret;
 *
 *	struct task_struct *tsk = pid_task(tsk_pid, PIDTYPE_PID);
 *	if (!tsk)
 *		return ret;
 *
 *	preempt_disable();
 *		__writecr3(__pa(tsk->active_mm->pgd));
 *		ret = ksm_hook_epage(original, redirect);
 *		__writecr3(cr3);
 *	preempt_enable();
 *	return ret;
 * \endcode
 *
 * Do also note the inline-code provided above is not tested, but should work.
 */
int ksm_hook_epage(void *original, void *redirect)
{
	struct page_hook_info *phi;
	u8 *code_page;
	void *aligned = (void *)page_align(original);
	uintptr_t code_start = (uintptr_t)original - (uintptr_t)aligned;

	struct trampoline trampo;
	epage_init_trampoline(&trampo, (uintptr_t)redirect);
	
	phi = ksm_find_page(original);
	if (phi) {
		/*
		 * Hooking another function in same page.
		 *
		 * Simply just overwrite the start of the
		 * function to the trampoline...
		 */
		code_page = phi->c_va;
		memcpy(code_page + code_start, &trampo, sizeof(trampo));
		__wbinvd();	/* necessary?  */
		return 0;
	}

	phi = mm_alloc_pool(sizeof(*phi));
	if (!phi)
		return ERR_NOMEM;

	code_page = mm_alloc_page();
	if (!code_page) {
		mm_free_pool(phi, sizeof(*phi));
		return ERR_NOMEM;
	}

	memcpy(code_page, aligned, PAGE_SIZE);
	memcpy(code_page + code_start, &trampo, sizeof(trampo));

	phi->c_va = code_page;
	phi->cpa = __pa(code_page);
	phi->dpa = __pa(original);
	phi->origin = (u64)aligned;
	phi->ops = &epage_ops;

	CALL_DPC(__do_hook_page, phi);
	htable_add(ksm.ht, page_hash(phi->origin), phi);
	return 0;
}

int ksm_unhook_page(void *va)
{
	struct page_hook_info *phi = ksm_find_page(va);
	if (!phi)
		return ERR_NOTH;

	return __ksm_unhook_page(phi);
}

int __ksm_unhook_page(struct page_hook_info *phi)
{
	CALL_DPC(__do_unhook_page, (void *)phi->dpa);
	htable_del(ksm.ht, page_hash(phi->origin), phi);
	mm_free_page(phi->c_va);
	mm_free_pool(phi, sizeof(*phi));
	return DPC_RET();
}

struct page_hook_info *ksm_find_page(void *va)
{
	const void *align = (const void *)page_align(va);
	return htable_get(ksm.ht, page_hash((u64)align), ht_cmp, align);
}

struct page_hook_info *ksm_find_page_pfn(uintptr_t pfn)
{
	struct htable_iter i;
	struct page_hook_info *phi;

	for (phi = htable_first(ksm.ht, &i); phi; phi = htable_next(ksm.ht, &i))
		if (phi->dpa >> PAGE_SHIFT == pfn)
			return phi;
	return NULL;
}
#endif
