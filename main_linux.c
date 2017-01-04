/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
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

#include "ksm.h"

static struct mm_struct *mm;
static struct workqueue_struct *wq;

static void ksm_worker(struct work_struct *w)
{
	int r = ksm_subvert(ksm);
	VCPU_DEBUG("ret: %d (%d active)\n", r, ksm->active_vcpus);
}
static DECLARE_DELAYED_WORK(work, ksm_worker);

static int __init ksm_start(void)
{
	int ret = -ENOMEM;

	ret = ksm_init(&ksm);
	if (ret < 0)
		return ret;

	wq = create_singlethread_workqueue("worker_ksm");
	if (!wq)
		goto out_exit;

	if (!queue_delayed_work(wq, &work, 100))
		goto out_wq;

	mm = current->active_mm;
	atomic_inc(&mm->mm_count);
	ksm->host_pgd = __pa(mm->pgd);
	return ret;

out_wq:
	destroy_workqueue(wq);
out_exit:
	ksm_free(ksm);
	return ret;
}

static void __exit ksm_cleanup(void)
{
	int ret, active;	

	active = ksm->active_vcpus;
	destroy_workqueue(wq);
	ret = ksm_free(ksm);
	VCPU_DEBUG("%d were active: ret: %d\n", active, ret);
	mmdrop(mm);
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

