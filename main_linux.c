/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * Main entrypoint for the Linux kernel module.
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/syscore_ops.h>

#include "ksm.h"

static struct mm_struct *mm;
static struct workqueue_struct *wq;

static void ksm_worker(struct work_struct *w)
{
	int r = ksm_subvert();
	VCPU_DEBUG("ret: %d (%d active)\n", r, ksm.active_vcpus);
}
static DECLARE_DELAYED_WORK(work, ksm_worker);

static inline void do_cpu(void *v)
{
	int (*f) (struct ksm *) = v;
	VCPU_DEBUG("On CPU calling %p\n", f);
	f(&ksm);
}

static int cpu_callback(struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	unsigned long cpu = (unsigned long)hcpu;

	VCPU_DEBUG("CPU %d action: %d\n", cpu, action);
	switch (action) {
	case CPU_ONLINE:
		smp_call_function_single(cpu, do_cpu, __ksm_init_cpu, 1);
		break;
	case CPU_DOWN_PREPARE:
		smp_call_function_single(cpu, do_cpu, __ksm_exit_cpu, 1);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block cpu_notify = {
	.notifier_call = cpu_callback
};

#ifdef ENABLE_RESUBV
/*
 * On S1-3 S4 states the CPU automatically disables virtualization, so shut it
 * down gracefully.  On S0 state, restore virtualization.
 */
static void ksm_resume(void)
{
	VCPU_DEBUG("in resume: %d\n", ksm_subvert());
}

static int ksm_suspend(void)
{
	VCPU_DEBUG("in suspend: %d\n", ksm_unsubvert());
	return 0;
}

static struct syscore_ops syscore_ops = {
	.resume = ksm_resume,
	.suspend = ksm_suspend,
};
#endif

int __init ksm_start(void)
{
	int ret = -ENOMEM;

	/*
	 * Zero out everything (this is allocated by the kernel device driver
	 * loader)
	 */
	__stosq((u64 *)&ksm, 0, sizeof(ksm) >> 3);

	ret = ksm_init();
	if (ret < 0)
		return ret;

	wq = create_singlethread_workqueue("worker_ksm");
	if (!wq)
		goto out_exit;

	if (!queue_delayed_work(wq, &work, 100))
		goto out_wq;

	mm = current->active_mm;
	atomic_inc(&mm->mm_count);
	ksm.host_pgd = __pa(mm->pgd);

	register_hotcpu_notifier(&cpu_notify);
#ifdef ENABLE_RESUBV
	register_syscore_ops(&syscore_ops);
#endif
	return ret;

out_wq:
	destroy_workqueue(wq);
out_exit:
	ksm_exit();
	return ret;
}

void __exit ksm_cleanup(void)
{
	int ret, active;

	destroy_workqueue(wq);
	unregister_hotcpu_notifier(&cpu_notify);
#ifdef ENABLE_RESUBV
	unregister_syscore_ops(&syscore_ops);
#endif

	active = ksm.active_vcpus;
	ret = ksm_exit();
	VCPU_DEBUG("%d active: exit: %d\n", active, ret);
	mmdrop(mm);
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

