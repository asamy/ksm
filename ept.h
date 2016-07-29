/* Do not include this file, include vcpu.h instead!
 * Per-CPU EPT definitions, see ept.c  */
#ifndef __EPT_H
#define __EPT_H

#include "mm.h"

 /* EPT Memory type  */
#define EPT_MT_UNCACHABLE		0
#define EPT_MT_WRITECOMBINING		1
#define EPT_MT_WRITETHROUGH		4
#define EPT_MT_WRITEPROTECTED		5
#define EPT_MT_WRITEBACK		6
#define EPT_MT_UNCACHED			7

/* EPT Access bits  */
#define EPT_ACCESS_NONE			0
#define EPT_ACCESS_READ			0x1
#define EPT_ACCESS_WRITE		0x2
#define EPT_ACCESS_RW			(EPT_ACCESS_READ | EPT_ACCESS_WRITE)
#define EPT_ACCESS_EXEC			0x4
#define EPT_ACCESS_RWX			(EPT_ACCESS_RW | EPT_ACCESS_EXEC)
#define EPT_ACCESS_ALL			EPT_ACCESS_RWX
#define EPT_ACCESS_MAX_BITS		EPT_ACCESS_ALL

/* Accessed dirty flags  */
#define EPT_ACCESSED			0x100
#define EPT_DIRTY			0x200

/* #VE (ept violation) bits (Exit qualification) and suppress bit  */
#define EPT_VE_READABLE			0x8			/* EPTE is readable	 */
#define EPT_VE_WRITABLE			0x10			/* EPTE is writable  */
#define EPT_VE_EXECUTABLE		0x20			/* EPTE is executable  */
#define EPT_VE_RWX			0x38			/* All of the above OR'd  */
#define EPT_VE_SHIFT			0x3
#define EPT_VE_MASK			0x7
#define EPT_VE_VALID_GLA		0x80			/* Valid guest linear address */
#define EPT_VE_TRANSLATION		0x100			/* Translation fault  */
#define EPT_VE_NMI_UNBLOCKING		0x2000			/* NMI unblocking due to IRET  */
#define EPT_SUPPRESS_VE_BIT		0x8000000000000000	/* Suppress convertible EPT violations */

#define EPT_MAX_EPTP_LIST		512			/* Processor defined size  */
#define EPTP_EXHOOK			0			/* hook eptp index, executable hooks only  */
#define EPTP_RWHOOK			1			/* hook eptp index, readwrite hooks, no exec  */
#define EPTP_NORMAL			2			/* sane eptp index, no hooks  */
#define EPTP_DEFAULT			EPTP_EXHOOK
#define EPTP_USED			3			/* number of unique ptrs currently in use and should be freed  */
#define EPT_MAX_PREALLOC		64*EPTP_USED
#define EPTP(e, i)			(e)->ptr_list[(i)]
#define EPT4(e, i)			(e)->pml4_list[(i)]
#define for_each_eptp(i)		for (int i = 0; i < EPTP_USED; ++i)

#define EPT_BUGCHECK_CODE		0x3EDFAAAA
#define EPT_BUGCHECK_TOOMANY		0xFFFFFFFE
#define EPT_BUGCHECK_MISCONFIG		0xE3E3E3E3
#define EPT_BUGCHECK_EPTP_LIST		0xDFDFDFDF
#define EPT_UNHANDLED_VIOLATION		0xEEEEEEEE

#define EPT_VPID_CAP_REQUIRED		(VMX_EPT_PAGE_WALK_4_BIT | VMX_EPT_EXECUTE_ONLY_BIT |	\
					 VMX_EPTP_WB_BIT | VMX_EPT_INVEPT_BIT |		\
					 VMX_EPT_EXTENT_CONTEXT_BIT | VMX_EPT_EXTENT_GLOBAL_BIT |	\
					 VMX_EPT_AD_BIT)

/* #VE (EPT Violation via IDT exception informaiton)  */
struct ve_except_info {
	u32 reason;		/* EXIT_REASON_EPT_VIOLATION  */
	u32 except_mask;	/* FFFFFFFF (set to 0 to deliver more)  */
	u64 exit;		/* normal exit qualification bits, see above  */
	u64 gla;		/* guest linear address */
	u64 gpa;		/* guest physical address  */
	u16 eptp;		/* current EPTP index  */
};

struct ept {
	uintptr_t *ptr_list;
	uintptr_t *pml4_list[EPTP_USED];
	uintptr_t *pre_alloc[EPT_MAX_PREALLOC];
	int pre_alloc_used;
};

static inline void __set_epte_pfn(uintptr_t *epte, uintptr_t pfn)
{
	*epte &= ~PAGE_MASK;
	*epte |= (pfn & PTI_MASK) << PTI_SHIFT;
}

static inline void __set_epte_ar(uintptr_t *epte, uintptr_t ar)
{
	*epte &= ~(ar ^ EPT_ACCESS_ALL);
	*epte |= ar & EPT_ACCESS_MAX_BITS;
}

static inline void __set_epte_ar_inplace(uintptr_t *epte, uintptr_t ar)
{
	__set_epte_ar(epte, ar | (*epte & EPT_ACCESS_MAX_BITS));
}

static inline void __set_epte_ar_pfn(uintptr_t *epte, uintptr_t ar, uintptr_t pfn)
{
	__set_epte_pfn(epte, pfn);
	__set_epte_ar(epte, ar);
}

extern bool ept_check_capabilitiy(void);
extern bool ept_init(struct ept *ept);
extern void ept_exit(struct ept *ept);
extern bool ept_setup_p(struct ept *ept, uintptr_t **pml4, uintptr_t *ptr);
extern uintptr_t *ept_alloc_page(struct ept *ept, uintptr_t *pml4, uint8_t access, uintptr_t phys);
extern uintptr_t *ept_pte(struct ept *ept, uintptr_t *pml, uintptr_t phys);
extern void ept_switch_root_p(struct ept *ept, u16 index);
extern bool ept_handle_violation(struct vcpu *vcpu);
extern void __ept_handle_violation(u64 cs, uintptr_t rip);

#ifdef DBG
static inline const char *ar_get_bits(u8 ar)
{
	if (test_bit(ar, EPT_ACCESS_RWX))
		return "rwx";
	else if (test_bit(ar, EPT_ACCESS_RW))
		return "rw-";
	else if (test_bit(ar, EPT_ACCESS_WRITE))
		return "-w-";
	else if (test_bit(ar, EPT_ACCESS_EXEC))
		return "--x";
	else if (test_bit(ar, EPT_ACCESS_READ))
		return "r--";

	return "---";
}

static inline const char *__get_epte_ar(uintptr_t *epte)
{
	return ar_get_bits((u8)*epte & EPT_ACCESS_MAX_BITS);
}

static inline const char *get_epte_ar(struct ept *ept, uintptr_t *pml, uintptr_t pa)
{
	return __get_epte_ar(ept_pte(ept, pml, pa));
}
#endif
#endif
