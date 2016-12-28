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

#include "ksm.h"

/*
 * FIXME: Get rid of this work queue stuff.
 * Currently they are just a workaround since init_mm / init_task /
 * init_level4_pgd aren't exported, so we need some way to hack some resident
 * CR3 which is kworker in this case...  Rather than using insmod/modprobe's
 * CR3 which will die eventually.
 */
static void ksm_worker(struct work_struct *);
static struct workqueue_struct *wq;
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

static void ksm_worker(struct work_struct *w)
{
	int ret;
	VCPU_DEBUG("in ksm_worker(): %s\n", current->comm);

	ksm.kernel_cr3 = __readcr3();
	ret = ksm_init();
	VCPU_DEBUG("init: %d\n", ret);
}

int __init ksm_start(void)
{
	wq = create_singlethread_workqueue("worker_ksm");
	if (!wq)
		return -ENOMEM;

	if (!queue_delayed_work(wq, &work, 100)) {
		destroy_workqueue(wq);
		return -EINVAL;
	}

	VCPU_DEBUG_RAW("Done, wait for wq to fire\n");
	register_hotcpu_notifier(&cpu_notify);
	return 0;
}

void __exit ksm_cleanup(void)
{
	unregister_hotcpu_notifier(&cpu_notify);
	destroy_workqueue(wq);
	VCPU_DEBUG("exit: %d\n", ksm_exit());
	VCPU_DEBUG("Bye\n");
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

