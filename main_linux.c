/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * Main entrypoint for the Linux kernel module.
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>

#include "ksm.h"

static void ksm_worker(struct work_struct *);
static struct workqueue_struct *wq;
static DECLARE_DELAYED_WORK(work, ksm_worker);

static void ksm_worker(struct work_struct *w)
{
	VCPU_DEBUG("in ksm_worker(): %s\n", current->comm);
	VCPU_DEBUG("virtualizing: %d\n", ksm_init());
}

int __init ksm_start(void)
{
	int ret;

	wq = create_singlethread_workqueue("worker_ksm");
	if (!wq)
		return -ENOMEM;

	if (!queue_delayed_work(wq, &work, 100)) {
		destroy_workqueue(wq);
		return -EINVAL;
	}

	VCPU_DEBUG_RAW("Done, wait for wq to fire\n");
	return 0;
}

void __exit ksm_cleanup(void)
{
	destroy_workqueue(wq);
	VCPU_DEBUG("exit: %d\n", ksm_exit());
	VCPU_DEBUG("Bye\n");
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

