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
#ifdef INTROSPECT_ENGINE
#ifdef __linux__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#else
#include <ntifs.h>
#include <intrin.h>
#endif

#include "ksm.h"
#include "percpu.h"
#include "um/um.h"

#define INTROSPECT_WATCH	1
#define INTROSPECT_UNWATCH	2

struct introspect_addr {
	u64 gpa;
	u64 gva;
	int access;
	int hits;
	int miss;
	struct list_head link;
};

struct introspect_call {
	int type;
	struct introspect_addr *addr;
};
static DEFINE_DPC(__call_introspect, __vmx_vmcall, HYPERCALL_INTROSPECT, ctx);

int ksm_introspect_init(struct ksm *k)
{
	spin_lock_init(&k->watch_lock);
	INIT_LIST_HEAD(&k->watch_list);
	return 0;
}

int ksm_introspect_exit(struct ksm *k)
{
	int r = 0;
	struct introspect_addr *addr = NULL;
	struct introspect_addr *next = NULL;

	list_for_each_entry_safe(addr, next, &k->watch_list, link) {
		list_del(&addr->link);
		__mm_free_pool(addr);
	}

	return r;
}

static inline struct introspect_addr *__find_watched_addr(struct ksm *k, u64 gpa)
{
	struct introspect_addr *addr = NULL;
	struct introspect_addr *ret = NULL;

	list_for_each_entry(addr, &k->watch_list, link) {
		if (addr->gpa >> PAGE_SHIFT == gpa >> PAGE_SHIFT) {
			ret = addr;
			break;
		}
	}

	return ret;
}

static inline struct introspect_addr *find_watched_addr(struct ksm *k, u64 gpa)
{
	struct introspect_addr *ret;
	spin_lock(&k->watch_lock);
	ret = __find_watched_addr(k, gpa);
	spin_unlock(&k->watch_lock);
	return ret;
}

bool ksm_introspect_handle_vmcall(struct vcpu *vcpu, uintptr_t arg)
{
	struct ept *ept = &vcpu->ept;
	struct ksm *k = vcpu_to_ksm(vcpu);
	struct introspect_call *call;
	struct introspect_addr *addr;
	u64 *epte;

	call = (struct introspect_call *)arg;
	addr = call->addr;
	switch (call->type) {
	case INTROSPECT_WATCH:
		/*
		 * ->access is what they want to monitor, so take those bits
		 * out so we can trap on that access.
		 */
		epte = ept_alloc_page(EPT4(ept, EPTP_DEFAULT),
				      addr->access ^ EPT_ACCESS_ALL, addr->gpa, addr->gpa);
		if (!epte)
			return false;

		cpu_invept(k, addr->gpa, EPTP(ept, EPTP_DEFAULT));
		return true;
	case INTROSPECT_UNWATCH:
		epte = ept_pte(EPT4(ept, EPTP_DEFAULT), addr->gpa);
		if (!epte)
			return false;

		__set_epte_ar(epte, EPT_ACCESS_ALL);
		cpu_invept(k, addr->gpa, EPTP(ept, EPTP_DEFAULT));
		return true;
	default:
		KSM_DEBUG("unknown call type %d\n", call->type);
		break;
	}

	return false;
}

bool ksm_introspect_handle_ept(struct ept_ve_around *ve)
{
	struct vcpu *vcpu;
	struct ve_except_info *info;
	struct introspect_addr *addr;
	struct ksm *k;
	struct ept *ept;
	u64 *epte;

	info = ve->info;
	vcpu = ve->vcpu;
	ept = &vcpu->ept;
	k = vcpu_to_ksm(vcpu);

	addr = find_watched_addr(k, info->gpa);
	WARN_ON(!addr);
	if (!addr) {
		/* This can happen?  */
		ve->eptp_next = EPTP_DEFAULT;
		return true;
	}

	epte = ept_pte(EPT4(ept, info->eptp), info->gpa);
	BUG_ON(!epte);

	if (info->exit & addr->access) {
		__set_epte_ar(epte, info->exit & EPT_AR_MASK);

		/* It's a hit only if the offset matches...  */
		if (addr_offset(info->gpa) >= addr_offset(addr->gpa)) {
			addr->hits++;
			KSM_DEBUG_RAW("Hit!\n");
		} else {
			addr->miss++;
			KSM_DEBUG_RAW("Miss offset\n");
		}
	} else {
		addr->miss++;
		__set_epte_ar(epte, addr->access ^ EPT_ACCESS_ALL);
		KSM_DEBUG_RAW("Miss!\n");
	}

	KSM_DEBUG("Addr %p: %d hits %d miss\n", info->gpa, addr->hits, addr->miss);
	ve->invalidate = true;
	return true;
}

int ksm_introspect_start(struct ksm *k)
{
	if (k->active_vcpus == 0)
		return ERR_NOTH;

	return vcpu_vmfunc(EPTP_DEFAULT, 0);
}

int ksm_introspect_stop(struct ksm *k)
{
	if (k->active_vcpus == 0)
		return ERR_NOTH;

	return vcpu_vmfunc(EPTP_NORMAL, 0);
}

int ksm_introspect_add_watch(struct ksm *k, struct watch_ioctl *watch)
{
	struct introspect_addr *addr;
	int r;

	addr = find_watched_addr(k, watch->addr);
	if (addr)
		return ERR_EXIST;

	addr = mm_alloc_pool(sizeof(*addr));
	if (!addr)
		return ERR_NOMEM;

	addr->gpa = watch->addr;
	addr->access = watch->access;
	CALL_DPC(__call_introspect, &(struct introspect_call) {
		.type = INTROSPECT_WATCH,
		.addr = addr,
	});
	r = DPC_RET();
	if (r != 0) {
		__mm_free_pool(addr);
		return r;
	}

	spin_lock(&k->watch_lock);
	list_add(&addr->link, &k->watch_list);
	spin_unlock(&k->watch_lock);
	return 0;
}

int ksm_introspect_rem_watch(struct ksm *k, struct watch_ioctl *watch)
{
	struct introspect_addr *addr;
	int ret = ERR_INVAL;

	addr = find_watched_addr(k, watch->addr);
	if (!addr)
		return ret;

	CALL_DPC(__call_introspect, &(struct introspect_call) {
		.type = INTROSPECT_UNWATCH,
		.addr = addr
	});
	ret = DPC_RET();

	spin_lock(&k->watch_lock);
	list_del(&addr->link);
	__mm_free_pool(addr);
	spin_unlock(&k->watch_lock);
	return ret;
}

int ksm_introspect_collect(struct ksm *k, struct watch_ioctl *watch)
{
	struct introspect_addr *addr;
	void *v;

	addr = find_watched_addr(k, watch->addr);
	if (!addr)
		return ERR_INVAL;

	v = mm_remap(page_align(watch->addr), PAGE_SIZE);
	if (!v)
		return ERR_NOMEM;

	memcpy(watch->buf, v, PAGE_SIZE);
	mm_unmap(v, PAGE_SIZE);

	watch->hits = addr->hits;
	watch->miss = addr->miss;
	return 0;
}

#endif
