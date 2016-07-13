#ifndef __KUM_H
#define __KUM_H

#include <intrin.h>
#include <ntddk.h>

#define KUM_MAX_PAGES	32
#define KUM_FREE_PAGE	1ULL
#define KUM_MAX_VCPUS	32

/* Executable pages only...  */
struct page_hook_info {
	uintptr_t d_pfn;
	uintptr_t c_pfn;
	uintptr_t c_va;
	u32 size;
	u8 data[128];
};

struct kum {
	int active_vcpus;
	struct vcpu *vcpu_list[KUM_MAX_VCPUS];
	void *msr_bitmap;
	u64 kernel_cr3;
	u64 origin_cr3;
	unsigned int phi_count;
	uintptr_t c_mask, c_bits;
	uintptr_t phi_pages[KUM_MAX_PAGES];
};
extern struct kum kum;

/* kum.c  */
extern NTSTATUS kum_init(void);
extern NTSTATUS kum_exit(void);
extern struct vcpu *kum_current_cpu(void);

/* page.c  */
extern int kum_hook_page(void *original, void *redirect);
extern NTSTATUS kum_unhook_page(int);
extern void kum_init_phi_list(void);
extern void kum_free_phi(struct page_hook_info *phi);
extern void kum_free_phi_list(void);
extern struct page_hook_info *kum_find_hook(int i);
extern struct page_hook_info *kum_find_hook_pfn(uintptr_t pfn);

#endif
