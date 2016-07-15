#ifndef __KSM_H
#define __KSM_H

#include "types.h"

#include <intrin.h>
#include <ntifs.h>

#define KSM_MAX_PAGES	32
#define KSM_FREE_PAGE	1ULL
#define KSM_MAX_VCPUS	32

/* Executable pages only...  */
struct page_hook_info {
	uintptr_t d_pfn;
	uintptr_t c_pfn;
	void *c_va;
	u32 size;
	u8 data[128];
};

struct ksm {
	int active_vcpus;
	struct vcpu *vcpu_list[KSM_MAX_VCPUS];
	void *hotplug_cpu;
	void *msr_bitmap;
	u64 kernel_cr3;
	u64 origin_cr3;
	unsigned int phi_count;
	uintptr_t c_mask, c_bits;
	uintptr_t phi_pages[KSM_MAX_PAGES];
};
extern struct ksm ksm;

/* ksm.c  */
extern NTSTATUS ksm_init(void);
extern NTSTATUS ksm_exit(void);
extern NTSTATUS ksm_hook_idt(unsigned n, void *h);
extern NTSTATUS ksm_free_idt(unsigned n);
extern struct vcpu *ksm_current_cpu(void);

/* page.c  */
extern int ksm_hook_page(void *original, void *redirect);
extern NTSTATUS ksm_unhook_page(int);
extern void ksm_init_phi_list(void);
extern void ksm_free_phi(struct page_hook_info *phi);
extern void ksm_free_phi_list(void);
extern struct page_hook_info *ksm_find_hook(int i);
extern struct page_hook_info *ksm_find_hook_pfn(uintptr_t pfn);

#endif
