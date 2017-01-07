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
#include <linux/device.h>
#include <linux/reboot.h>

#include "ksm.h"
#include "um/um.h"

static struct mm_struct *mm = NULL;
static int major_no = 0;
static struct class *class;

static long ksm_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret = -EINVAL;
	int __maybe_unused pid = 0;
	VCPU_DEBUG("ioctl from %s: cmd(0x%08X) args(%p)\n",
		   current->comm, cmd, args);

	if (mm && current->mm != mm) {
		VCPU_DEBUG("not processing ioctl from %s\n", current->comm);
		goto out;
	}

	switch (cmd) {
#ifdef PMEM_SANDBOX
	case KSM_IOCTL_SANDBOX:
		ret = copy_from_user(&pid, (const void __force *)args, sizeof(pid));
		if (ret < 0)
			break;

		VCPU_DEBUG("sandboxing %d\n", pid);
		ret = ksm_sandbox(ksm, pid);
		break;
	case KSM_IOCTL_UNBOX:
		ret = copy_from_user(&pid, (const void __force *)args, sizeof(pid));
		if (ret < 0)
			break;

		VCPU_DEBUG("unsandboxing %d\n", pid);
		ret = ksm_unbox(ksm, pid);
		break;
#endif
	case KSM_IOCTL_SUBVERT:
		if (!mm) {
			/* Steal their mm...  */
			mm = current->active_mm;
			atomic_inc(&mm->mm_count);
			ksm->host_pgd = __pa(mm->pgd);
		}

		ret = ksm_subvert(ksm);
		break;
	case KSM_IOCTL_UNSUBVERT:
		ret = ksm_unsubvert(ksm);
		if (ret == 0 && mm) {
			VCPU_DEBUG("derefering stolen mm\n");
			mmdrop(mm);
			mm = NULL;
		}

		break;
	default:
		VCPU_DEBUG("unknown ioctl code %X\n", cmd);
		ret = -EINVAL;
		break;
	}

out:
	VCPU_DEBUG("ioctl ret: %d\n", ret);
	return ret;
}

static int ksm_open(struct inode *node, struct file *filp)
{
	VCPU_DEBUG("open() from %s\n", current->comm);
	return 0;
}

static int ksm_release(struct inode *inode, struct file *filp)
{
	VCPU_DEBUG("release() from %s\n", current->comm);
	return 0;
}

static struct file_operations ksm_fops = {
	.open = ksm_open,
	.release = ksm_release,
	.unlocked_ioctl = ksm_ioctl,
};

static int ksm_reboot(struct notifier_block *nb, unsigned long action,
		      void *data)
{
	ksm_exit(ksm);
	return 0;
}

static struct notifier_block reboot_notify = {
	.notifier_call = ksm_reboot,
};

static int __init ksm_start(void)
{
	int ret = -ENOMEM;
	struct device *dev;

	ret = ksm_init(&ksm);
	if (ret < 0)
		return ret;

	major_no = register_chrdev(0, UM_DEVICE_NAME, &ksm_fops);
	if (major_no < 0)
		goto out_exit;

	VCPU_DEBUG("Major: %d\n", major_no);
	class = class_create(THIS_MODULE, UM_DEVICE_NAME);
	if (!class)
		goto out_unregister;

	dev = device_create(class, NULL, MKDEV(major_no, 0), NULL, UM_DEVICE_NAME);
	if (dev) {
		register_reboot_notifier(&reboot_notify);
		VCPU_DEBUG_RAW("ready\n");
		return ret;
	}

	ret = -EINVAL;
	VCPU_DEBUG_RAW("failed to create device\n");
	class_unregister(class);
	class_destroy(class);

out_unregister:
	unregister_chrdev(major_no, UM_DEVICE_NAME);
out_exit:
	ksm_free(ksm);
	return ret;
}

static void __exit ksm_cleanup(void)
{
	int ret, active;

	device_destroy(class, MKDEV(major_no, 0));
	class_unregister(class);
	class_destroy(class);
	unregister_chrdev(major_no, UM_DEVICE_NAME);
	unregister_reboot_notifier(&reboot_notify);

	active = ksm->active_vcpus;
	ret = ksm_free(ksm);
	VCPU_DEBUG("%d were active: ret: %d\n", active, ret);

	if (mm)
		mmdrop(mm);
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

