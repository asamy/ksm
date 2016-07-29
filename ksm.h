#ifndef __KSM_H
#define __KSM_H

#include "types.h"

#include <intrin.h>
#include <ntifs.h>

#include "htable.h"

#define KSM_MAX_VCPUS	32

struct phi_ops {
	void (*init_eptp) (struct page_hook_info *phi, struct ept *ept);
	u16 (*select_eptp) (struct page_hook_info *phi, u16 cur, u8 ar, u8 ac);
};

struct page_hook_info {
	u64 d_pfn;
	u64 c_pfn;
	u64 origin;
	void *c_va;
	struct phi_ops *ops;
	u32 size;
	u8 data[128];
};

static size_t page_hash(u64 h)
{
	h = ~h + (h << 15);
	h = h ^ (h >> 12);
	h = h + (h << 2);
	h = h ^ (h >> 4);
	h = h * 2057;
	h = h ^ (h >> 16);
	return h;
}

static inline size_t rehash(const void *e, void *unused)
{
	return page_hash(((struct page_hook_info *)e)->origin);
}

struct ksm {
	int active_vcpus;
	struct vcpu *vcpu_list[KSM_MAX_VCPUS];
	void *hotplug_cpu;
	void *msr_bitmap;
	u64 kernel_cr3;
	u64 origin_cr3;
	struct htable ht;
};
extern struct ksm ksm;

/* ksm.c  */
extern NTSTATUS ksm_init(void);
extern NTSTATUS ksm_exit(void);
extern NTSTATUS ksm_hook_idt(unsigned n, void *h);
extern NTSTATUS ksm_free_idt(unsigned n);
extern struct vcpu *ksm_current_cpu(void);

/* page.c  */
extern NTSTATUS ksm_hook_epage(void *original, void *redirect);
extern NTSTATUS ksm_unhook_page(void *original);
extern NTSTATUS __ksm_unhook_page(struct page_hook_info *phi);
extern struct page_hook_info *ksm_find_page(void *va);
extern struct page_hook_info *ksm_find_page_pfn(uintptr_t pfn);

#endif
