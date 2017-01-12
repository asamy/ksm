/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Userspace physical memory sandbox.
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
#ifdef PMEM_SANDBOX
#ifdef __linux__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#else
#include <ntifs.h>
#include <intrin.h>
#endif

#include "ksm.h"
#include "mm.h"
#include "percpu.h"

/*
 * Note #1:
 *	Not to be confused with full-application sandboxing (e.g. filesystem,
 *	etc.), this is just a physical memory sandboxer.
 *
 *	This is basically CoW (copy-on-write) implementation but on the
 *	physical level, so when a registered application writes to a
 *	memory region, another region is allocated and the original one is
 *	redirected to that one with a copy of the contents in it, then only
 *	that application will see that copy and not others.
 *
 * Note #2:
 *	we can't re-use the epage-hook mechanism here, because the
 *	pages are not known yet, they are just set to read-execute access only, no
 *	write-access, when there is a write, we copy the page.
 *
 * Note #3:
 *	This still needs a lot of work, and is quite "barebones" for now...
 *	Some work would be perhaps replacing the cr3-load-exiting with something less
 *	costy.
 *
 * Note #4:
 *	Be careful with this, it's not well tested and quite frankly, may not be very
 *	good performance wise, you have been warned...
 */
struct cow_page {
	u64 gpa;
	u64 hpa;
	void *hva;
	struct list_head link;
};

struct sa_task {
	pid_t pid;
	u64 pgd;
	u16 eptp[KSM_MAX_VCPUS];
	spinlock_t lock;
	struct list_head pages;
	struct list_head link;
};

static inline u16 task_eptp(struct sa_task *task)
{
	return task->eptp[cpu_nr()];
}

static inline void free_cow_page(struct cow_page *page)
{
	list_del(&page->link);
	mm_free_page(page->hva);
	__mm_free_pool(page);
}

bool ksm_sandbox_handle_vmcall(struct vcpu *vcpu, uintptr_t arg)
{
	struct sa_task *task = (struct sa_task *)arg;
	u16 eptp = task_eptp(task);
	if (vcpu_eptp_idx(vcpu) == eptp) {
		if (vcpu->last_switch)
			vcpu_switch_root_eptp(vcpu, vcpu->eptp_before);
		else
			vcpu_switch_root_eptp(vcpu, EPTP_DEFAULT);
	}

	vcpu->last_switch = NULL;
	if (eptp != EPT_MAX_EPTP_LIST)
		ept_free_ptr(&vcpu->ept, eptp);

	return true;
}

static DEFINE_DPC(__free_sa_task, __vmx_vmcall, HYPERCALL_SA_TASK, ctx);
static inline void __free_sa_task(struct ksm *k, struct sa_task *task)
{
	struct cow_page *page = NULL;
	struct cow_page *next = NULL;

	list_for_each_entry_safe(page, next, &task->pages, link)
		free_cow_page(page);

	list_del(&task->link);
	__mm_free_pool(task);
}

static inline void free_sa_task(struct ksm *k, struct sa_task *task)
{
	CALL_DPC(__free_sa_task, task);
	__free_sa_task(k, task);
}

int ksm_sandbox_init(struct ksm *k)
{
	spin_lock_init(&k->task_lock);
	INIT_LIST_HEAD(&k->task_list);
	return 0;
}

int ksm_sandbox_exit(struct ksm *k)
{
	struct sa_task *task = NULL;
	struct sa_task *next = NULL;
	list_for_each_entry_safe(task, next, &k->task_list, link)
		__free_sa_task(k, task);

	return 0;
}

static inline int create_sa_task(struct ksm *k, pid_t pid, u64 pgd)
{
	struct sa_task *task;
	int i;

	task = mm_alloc_pool(sizeof(*task));
	if (!task)
		return ERR_NOMEM;

	task->pgd = pgd;
	task->pid = pid;
	INIT_LIST_HEAD(&task->pages);
	spin_lock_init(&task->lock);
	for (i = 0; i < KSM_MAX_VCPUS; ++i)
		task->eptp[i] = EPT_MAX_EPTP_LIST;

	spin_lock(&k->task_lock);
	list_add(&task->link, &k->task_list);
	spin_unlock(&k->task_lock);
	return 0;
}

static inline struct cow_page *ksm_sandbox_copy_page(struct vcpu *vcpu,
						     struct sa_task *task,
						     u64 gpa)
{
	char *hva;
	char *h;
	u64 hpa;
	struct cow_page *page;

	if (!gpa_to_hpa(vcpu, gpa, &hpa))
		return false;

	h = mm_remap(hpa, PAGE_SIZE);
	if (!h)
		return false;

	page = mm_alloc_pool(sizeof(*page));
	if (!page)
		goto err_page;

	hva = mm_alloc_page();
	if (!hva)
		goto err_cow;

	memcpy(hva, h, PAGE_SIZE);
	mm_unmap(h, PAGE_SIZE);

	page->gpa = gpa;
	page->hpa = __pa(hva);
	page->hva = hva;

	spin_lock(&task->lock);
	list_add(&page->link, &task->pages);
	spin_unlock(&task->lock);
	return page;

err_cow:
	__mm_free_pool(page);
err_page:
	mm_unmap(h, PAGE_SIZE);
	return NULL;
}

int ksm_sandbox(struct ksm *k, pid_t pid)
{
#ifdef __linux__
	struct pid *tsk_pid = find_vpid(pid);
	struct task_struct *tsk;

	if (!tsk_pid)
		return -ESRCH;

	tsk = pid_task(tsk_pid, PIDTYPE_PID);
	if (!tsk)
		return -EINVAL;		/* can this happen?  */

	/* Ignore anonymous processes  */
	WARN_ON(!tsk->mm);
	if (!tsk->mm)
		return -EFAULT;

	return create_sa_task(k, pid, __pa(tsk->mm->pgd) & PAGE_PA_MASK);
#else
	NTSTATUS status;
	PEPROCESS process;
	KAPC_STATE apc;
	uintptr_t pgd;

	status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(process, &apc);
	pgd = __readcr3() & PAGE_PA_MASK;
	KeUnstackDetachProcess(&apc);
	ObfDereferenceObject(process);
	return create_sa_task(k, pid, pgd);
#endif
}

static struct sa_task *find_sa_task(struct ksm *k, pid_t pid)
{
	struct sa_task *task = NULL;
	struct sa_task *ret = NULL;

	spin_lock(&k->task_lock);
	list_for_each_entry(task, &k->task_list, link) {
		if (task->pid == pid) {
			ret = task;
			break;
		}
	}
	spin_unlock(&k->task_lock);
	return ret;
}

int ksm_unbox(struct ksm *k, pid_t pid)
{
	struct sa_task *task = NULL;
	int ret = ERR_NOTH;

	spin_lock(&k->task_lock);
	list_for_each_entry(task, &k->task_list, link) {
		if (task->pid == pid) {
			free_sa_task(k, task);
			ret = 0;
			break;
		}
	}
	spin_unlock(&k->task_lock);
	return ret;
}

static struct sa_task *find_sa_task_pgd(struct ksm *k, u64 pgd)
{
	struct sa_task *task = NULL;
	struct sa_task *ret = NULL;

	spin_lock(&k->task_lock);
	list_for_each_entry(task, &k->task_list, link) {
		if (task->pgd == pgd) {
			ret = task;
			break;
		}
	}
	spin_unlock(&k->task_lock);
	return ret;
}

static struct sa_task *find_sa_task_pgd_pid(struct ksm *k, pid_t pid, u64 pgd)
{
	struct sa_task *task = NULL;
	struct sa_task *ret = NULL;

	spin_lock(&k->task_lock);
	list_for_each_entry(task, &k->task_list, link) {
		if (task->pgd == pgd || task->pid == pid) {
			ret = task;
			break;
		}
	}
	spin_unlock(&k->task_lock);
	return ret;
}

static struct sa_task *__find_sa_task_eptp(struct ksm *k, u16 eptp)
{
	struct sa_task *task = NULL;

	list_for_each_entry(task, &k->task_list, link)
		if (task_eptp(task) == eptp)
			return task;
	return NULL;
}

static struct sa_task *find_sa_task_eptp(struct ksm *k, u16 eptp)
{
	struct sa_task *task;

	spin_lock(&k->task_lock);
	task = __find_sa_task_eptp(k, eptp);
	spin_unlock(&k->task_lock);
	return task;
}

bool ksm_sandbox_handle_ept(struct ept_ve_around *ve)
{
	struct sa_task *task;
	struct cow_page *page;
	struct ve_except_info *info;
	struct vcpu *vcpu;
	struct ept *ept;
	struct ksm *k;
	u64 *epte;

	vcpu = ve->vcpu;
	ept = &vcpu->ept;
	info = ve->info;
	k = vcpu_to_ksm(vcpu);
	task = find_sa_task_eptp(k, info->eptp);
	if (!task) {
		ve->eptp_next = EPTP_DEFAULT;
		BREAK_ON(1);
		return true;
	}

	epte = ept_pte(EPT4(ept, info->eptp), info->gpa);
	BUG_ON(!epte);

	if (info->exit & EPT_ACCESS_WRITE) {
		KSM_DEBUG("allocating cow page for GPA %p GVA %p AC %X)\n",
			  info->gpa, info->gla, info->exit & EPT_AR_MASK);

		page = ksm_sandbox_copy_page(vcpu, task, info->gpa);
		WARN_ON(!page);
		if (!page)
			goto manually_fix;

		__set_epte_ar_inplace(epte, info->exit & EPT_AR_MASK);
		__set_epte_pfn(epte, page->hpa >> PAGE_SHIFT);
	} else {
manually_fix:
		BREAK_ON(1);
		KSM_DEBUG("Manually fixing AR for %p (0x%X)\n", info->gpa, info->exit & EPT_AR_MASK);
		__set_epte_ar_inplace(epte, info->exit & EPT_AR_MASK);
	}

	ve->invalidate = true;
	return true;
}

void ksm_sandbox_handle_cr3(struct vcpu *vcpu, u64 cr3)
{
	struct ksm *k;
	struct sa_task *task;
	u16 *eptp;

	k = vcpu_to_ksm(vcpu);
	task = find_sa_task_pgd(k, cr3 & PAGE_PA_MASK);
	if (task) {
		eptp = &task->eptp[cpu_nr()];
		if (*eptp == EPT_MAX_EPTP_LIST)
			BUG_ON(!ept_create_ptr(&vcpu->ept, EPT_ACCESS_RX, eptp));

		vcpu->last_switch = task;
		vcpu->eptp_before = vcpu_eptp_idx(vcpu);
		vcpu_switch_root_eptp(vcpu, *eptp);
	} else if (vcpu->last_switch) {
		vcpu_switch_root_eptp(vcpu, vcpu->eptp_before);
		vcpu->last_switch = NULL;
	}
}

#endif
