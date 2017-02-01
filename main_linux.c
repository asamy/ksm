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
static int major_no;
static struct class *class;

static long ksm_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret = -EINVAL;
	int __maybe_unused pid = 0;
	struct watch_ioctl *watch = NULL;
	KSM_DEBUG("ioctl from %s: cmd(0x%08X)\n",
		   current->comm, cmd);

	if (mm && current->mm != mm) {
		KSM_DEBUG("not processing ioctl from %s\n", current->comm);
		goto out;
	}

#ifdef INTROSPECT_ENGINE
	if (cmd >= KSM_IOCTL_INTRO_WATCH && cmd <= KSM_IOCTL_INTRO_STATS) {
		watch = kmalloc(sizeof(*watch), GFP_KERNEL | __GFP_ZERO);
		if (!watch)
			return -ENOMEM;
	}
#endif

	switch (cmd) {
#ifdef PMEM_SANDBOX
	case KSM_IOCTL_SANDBOX:
		ret = -EFAULT;
		if (copy_from_user(&pid, (const void __force *)args, sizeof(pid)))	
			break;

		KSM_DEBUG("sandboxing %d\n", pid);
		ret = ksm_sandbox(ksm, pid);
		break;
	case KSM_IOCTL_UNBOX:
		ret = -EFAULT;
		if (copy_from_user(&pid, (const void __force *)args, sizeof(pid)))
			break;

		KSM_DEBUG("unsandboxing %d\n", pid);
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
			KSM_DEBUG("derefering stolen mm\n");
			mmdrop(mm);
			mm = NULL;
		}
		break;
#ifdef INTROSPECT_ENGINE
	case KSM_IOCTL_INTRO_START:
		ret = ksm_introspect_start(ksm);
		break;
	case KSM_IOCTL_INTRO_STOP:
		ret = ksm_introspect_stop(ksm);
		break;
	case KSM_IOCTL_INTRO_WATCH:
		ret = -EFAULT;
		if (copy_from_user(watch, (const void __force *)args, sizeof(*watch)))
			break;

		ret = ksm_introspect_add_watch(ksm, watch);
		break;
	case KSM_IOCTL_INTRO_UNWATCH:
		ret = -EFAULT;
		if (copy_from_user(watch, (const void __force *)args, sizeof(*watch)))
			break;

		ret = ksm_introspect_rem_watch(ksm, watch);
		break;
	case KSM_IOCTL_INTRO_STATS:
		ret = -EFAULT;
		if (copy_from_user(watch, (const void __force *)args, sizeof(*watch)))
			break;

		ret = ksm_introspect_collect(ksm, watch);
		if (ret < 0)
			break;

		if (copy_to_user((void __force *)args, watch, sizeof(*watch)))
			ret = -EFAULT;
		break;
#endif
	default:
		KSM_DEBUG("unknown ioctl code 0x%08X\n", cmd);
		ret = -EINVAL;
		break;
	}

out:
	if (watch)
		kfree(watch);

	KSM_DEBUG("ioctl ret: %d\n", ret);
	return ret;
}

static int ksm_open(struct inode *node, struct file *filp)
{
	KSM_DEBUG("open() from %s\n", current->comm);
	return 0;
}

static int ksm_release(struct inode *inode, struct file *filp)
{
	KSM_DEBUG("release() from %s\n", current->comm);
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
	ksm_unsubvert(ksm);
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

	ret = -ENODEV;
	KSM_DEBUG("Major: %d\n", major_no);

	class = class_create(THIS_MODULE, UM_DEVICE_NAME);
	if (!class)
		goto out_unregister;

	dev = device_create(class, NULL, MKDEV(major_no, 0), NULL, UM_DEVICE_NAME);
	if (dev) {
		register_reboot_notifier(&reboot_notify);
		KSM_DEBUG_RAW("ready\n");
		return 0;
	}

	KSM_DEBUG_RAW("failed to create device\n");
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
	class_destroy(class);
	unregister_chrdev(major_no, UM_DEVICE_NAME);
	unregister_reboot_notifier(&reboot_notify);

	active = ksm->active_vcpus;
	ret = ksm_free(ksm);
	KSM_DEBUG("%d were active: ret: %d\n", active, ret);

	if (mm)
		mmdrop(mm);
}

module_init(ksm_start);
module_exit(ksm_cleanup);

MODULE_AUTHOR("Ahmed Samy");
MODULE_LICENSE("GPL");

