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
	mm_free_page(page);
}

bool ksm_sandbox_handle_vmcall(struct vcpu *vcpu, uintptr_t arg)
{
	struct sa_task *task = (struct sa_task *)arg;
	u16 eptp = task_eptp(task);
	if (vcpu_eptp_idx(vcpu) == eptp) {
		if (vcpu->last_switch) {
			vcpu_switch_root_eptp(vcpu, vcpu->eptp_before);
			vcpu->last_switch = NULL;
		} else {
			vcpu_switch_root_eptp(vcpu, EPTP_DEFAULT);
		}
	}

	ept_free_ptr(&vcpu->ept, eptp);
	return true;
}

static DEFINE_DPC(__free_sa_task, __vmx_vmcall, HYPERCALL_SA_TASK, ctx);
static inline void free_sa_task(struct ksm *k, struct sa_task *task, bool call)
{
	struct cow_page *page = NULL;
	struct cow_page *next = NULL;

	if (call)
		CALL_DPC(__free_sa_task, task);

	list_for_each_entry_safe(page, next, &task->pages, link)
		free_cow_page(page);

	list_del(&task->link);
	__mm_free_pool(task);
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
		free_sa_task(k, task, false);

	return 0;
}

static inline int create_sa_task(struct ksm *k, pid_t pid, u64 pgd)
{
	struct sa_task *task;
	unsigned long flags;
	int i;

	task = mm_alloc_pool(sizeof(*task));
	if (!task)
		return ERR_NOMEM;

	task->pgd = pgd;
	task->pid = pid;
	INIT_LIST_HEAD(&task->pages);
	for (i = 0; i < KSM_MAX_VCPUS; ++i)
		task->eptp[i] = EPT_MAX_EPTP_LIST;

	spin_lock_irqsave(&k->task_lock, flags);
	list_add(&task->link, &k->task_list);
	spin_unlock_irqrestore(&k->task_lock, flags);
	return 0;
}

static inline struct cow_page *ksm_sandbox_copy_page(struct sa_task *task, u64 gpa)
{
	char *hva;
	char *h;
	struct cow_page *page;

	h = mm_remap(gpa, PAGE_SIZE);
	if (!h)
		return false;

	page = mm_alloc_pool(sizeof(*page));
	if (!page)
		goto err_page;

	hva = mm_alloc_page();
	if (!hva)
		goto err_cow;

	memcpy(hva, h, PAGE_SIZE);
	page->gpa = gpa;
	page->hpa = __pa(hva);
	page->hva = hva;
	list_add(&page->link, &task->pages);
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
		return -EINVAL;

	tsk = pid_task(tsk_pid, PIDTYPE_PID);
	if (!tsk)
		return -ENOENT;

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
			free_sa_task(k, task, true);
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

	list_for_each_entry(task, &k->task_list, link) {
		if (task->pgd == pgd) {
			ret = task;
			break;
		}
	}
	return ret;
}

static struct sa_task *find_sa_task_pgd_pid(struct ksm *k, pid_t pid, u64 pgd)
{
	struct sa_task *task = NULL;
	struct sa_task *ret = NULL;

	list_for_each_entry(task, &k->task_list, link) {
		if (task->pgd == pgd || task->pid == pid) {
			ret = task;
			break;
		}
	}
	return ret;
}

bool ksm_sandbox_handle_ept(struct ept *ept, int dpl, u64 gpa,
			    u64 gva, u64 cr3, u16 curr, u8 ar, u8 ac,
			    bool *invd, u16 *eptp_switch)
{
	struct sa_task *task;
	struct cow_page *page;
	struct vcpu *vcpu;
	struct ksm *k;
	u64 *epte;
	u16 eptp;
	pid_t pid;

	vcpu = container_of(ept, struct vcpu, ept);
	k = vcpu_to_ksm(vcpu);

	pid = proc_id();
	task = find_sa_task_pgd_pid(k, pid, cr3 & PAGE_PA_MASK);
	if (!task) {
		/* Crashed maybe  */
		*eptp_switch = EPTP_DEFAULT;
		return true;
	}

	eptp = task_eptp(task);
	BUG_ON(eptp == EPT_MAX_EPTP_LIST);

	epte = ept_pte(EPT4(ept, curr), gpa);
	BUG_ON(eptp != curr);

	if (dpl != 0 && ac & EPT_ACCESS_WRITE) {
		page = ksm_sandbox_copy_page(task, gpa);
		if (!page)
			return false;

		__set_epte_ar_pfn(epte, ar | ac, page->hpa >> PAGE_SHIFT);
		*invd = true;
	} else {
		__set_epte_ar(epte, ar | ac);
		*invd = true;
	}

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
