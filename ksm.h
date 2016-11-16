/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
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
#ifndef __KSM_H
#define __KSM_H

#ifndef _MSC_VER
/* Annoying warning from ntddk */
struct _DISK_GEOMETRY_EX;
#endif

#include <intrin.h>
#include <ntddk.h>

#include "compiler.h"
#include "x86.h"
#include "vmx.h"
#include "asm.h"
#include "segment.h"
#include "mm.h"
#include "htable.h"

/* Avoid NT retardism  */
#define container_of(address, type, field)	CONTAINING_RECORD(address, type, field)

#define KSM_MAX_VCPUS		32
#define __CR0_GUEST_HOST_MASK	0
#define __CR4_GUEST_HOST_MASK	X86_CR4_VMXE
#define __EXCEPTION_BITMAP	0

#define HYPERCALL_STOP		0	/* Stop virtualization on this CPU  */
#define HYPERCALL_IDT		1	/* Hook IDT entry (see idt.h, exit.c)  */
#define HYPERCALL_UIDT		2	/* Unhook IDT entry  */
#define HYPERCALL_HOOK		3	/* Hook page  */
#define HYPERCALL_UNHOOK	4	/* Unhook page  */
#define HYPERCALL_VMFUNC	5	/* Emulate VMFunc  */

#define REG_AX			0
#define REG_CX			1
#define REG_DX			2
#define REG_BX			3
#define REG_SP			4
#define REG_BP			5
#define REG_SI			6
#define REG_DI			7
#define REG_R8			8
#define REG_R9			9
#define REG_R10			10
#define REG_R11			11
#define REG_R12			12
#define REG_R13			13
#define REG_R14			14
#define REG_R15			15
#define REG_MAX			16

#define VCPU_BUGCHECK_CODE		0xCCDDFF11
#define VCPU_TRIPLEFAULT		0x33DDE83A
#define VCPU_BUG_UNHANDLED		0xBAADF00D
#define VCPU_IRQ_NOT_HANDLED		0xCAFEBABE
#define VCPU_BUGCHECK_FAILED_VMENTRY	0xBAADBABE
#define VCPU_BUGCHECK_GUEST_STATE	0xBAAD7A1E
#define VCPU_BUGCHECK_UNEXPECTED	0xEEEEEEE9
#ifdef DBG
#define VCPU_BUGCHECK(a, b, c, d)	KeBugCheckEx(MANUALLY_INITIATED_CRASH, a, b, c, d)
#else
#define VCPU_BUGCHECK(a, b, c, d)	(void)0
#endif

/* Short name:  */
#define cpu_nr()			KeGetCurrentProcessorNumberEx(NULL)
#define vpid_nr()			(cpu_nr() + 1)
#define proc_nr()			PsGetCurrentProcessId()

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifdef DBG
#ifdef _MSC_VER
#define VCPU_DEBUG(fmt, ...)		do_print("CPU %d: " __func__ ": " fmt, cpu_nr(), __VA_ARGS__)
#define VCPU_DEBUG_RAW(str)		do_print("CPU %d: " __func__ ": " str, cpu_nr())
#else
/* avoid warning on empty argument list  */
#define VCPU_DEBUG(fmt, args...)	do_print("CPU %d: %s: " fmt, cpu_nr(), __func__, ##args)
#define VCPU_DEBUG_RAW(str)		do_print("CPU %d: %s: " str, cpu_nr(), __func__)
#endif
#else
#define VCPU_DEBUG(fmt, ...)
#define VCPU_DEBUG_RAW(str)
#endif

/* can be very noisy, used only during first-phase testing  */
#ifdef VCPU_TRACER_LOG
#define VCPU_TRACER_START()		VCPU_DEBUG("%p\n", gc)
#define VCPU_TRACER_END()		VCPU_DEBUG("%p handled\n", gc)
#else
#define VCPU_TRACER_START()
#define VCPU_TRACER_END()
#endif

#define VCPU_ENTER_GUEST()	\
	uintptr_t __g_cr3;		\
	__vmx_vmread(GUEST_CR3, &__g_cr3);	\
	uintptr_t __save_cr3 = __readcr3();		\
	__writecr3(__g_cr3)

#define VCPU_EXIT_GUEST()	\
	__writecr3(__save_cr3)

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
#define EPT_AR_SHIFT			0x3
#define EPT_AR_MASK			0x7
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
#define EPT_MAX_PREALLOC		256			/* FIXME:  This is retarded!  */
#define EPTP(e, i)			(e)->ptr_list[(i)]
#define EPT4(e, i)			(e)->pml4_list[(i)]
#define for_each_eptp(i)		for (int i = 0; i < EPTP_USED; ++i)

#define EPT_BUGCHECK_CODE		0x3EDFAAAA
#define EPT_BUGCHECK_TOOMANY		0xFFFFFFFE
#define EPT_BUGCHECK_MISCONFIG		0xE3E3E3E3
#define EPT_BUGCHECK_EPTP_LIST		0xDFDFDFDF
#define EPT_UNHANDLED_VIOLATION		0xEEEEEEEE

#define KSM_EPT_REQUIRED_EPT		(VMX_EPT_PAGE_WALK_4_BIT | VMX_EPT_EXECUTE_ONLY_BIT |	\
					 VMX_EPTP_WB_BIT | VMX_EPT_INVEPT_BIT | VMX_EPT_EXTENT_GLOBAL_BIT)
#ifdef ENABLE_PML
#define EPT_VPID_CAP_REQUIRED		(KSM_EPT_REQUIRED_EPT | VMX_EPT_AD_BIT)
#else
#define EPT_VPID_CAP_REQUIRED		KSM_EPT_REQUIRED_EPT
#endif

struct regs {
	u64 gp[REG_MAX];
	u64 eflags;
};

struct shadow_idt_entry {
	unsigned n;
	void *h;
};

struct vmcs {
	u32 revision_id;
	u32 abort;
	u32 data[1];
};

#pragma warning(disable:4201)	/* stupid nonstandard bullshit  */

/* Posted interrupt descriptor */
struct pi_desc {
	/* 256 bits of posted interrupt requests
	* The bit index is the vector in IDT.  */
	u32 pir[8];
	union {
		struct {
			/* bit 256 - Outstanding notification, must be set to notify
			* the processor when interrupt vector is set in the PIR.  */
			u16 on : 1;
			/* bit 257 - suppress notification  */
			u16 sn : 1;
			/* bits 271:258 - reserved  */
			u16 rsvd0 : 14;
			/* bit 279:272 -  notification vector  */
			u8 nv;
			/* bits 287:280 - reserved  */
			u16 rsvd1;
			/* bits 319:288 - notification destination  */
			u32 ndst;
		};
		u64 control;
	};
	u32 rsvd[6];
};

static inline bool pi_test_bit(struct pi_desc *d, u8 vector)
{
	return d->pir[vector / 32] & (1 << (vector % 32));
}

static inline void pi_set_irq(struct pi_desc *d, u8 vector)
{
	d->pir[vector / 32] |= 1 << (vector % 32);
	d->on = 1;
}

static inline void pi_clear_irq(struct pi_desc *d, u8 vector)
{
	d->pir[vector / 32] &= ~(1 << (vector % 32));
	d->on = 0;
}

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
	__align(PAGE_SIZE) uintptr_t ptr_list[EPT_MAX_EPTP_LIST];
	uintptr_t *pml4_list[EPTP_USED];
	uintptr_t *pre_alloc[EPT_MAX_PREALLOC];
	u32 pre_alloc_used;
};

#ifdef NESTED_VMX
#define VMCS_LAUNCH_STATE_CLEAR		0
#define VMCS_LAUNCH_STATE_LAUNCHED	1

struct nested_vcpu {
	bool vmxon;
	/* The following are all physical addresses.  */
	uintptr_t vmxon_region;
	uintptr_t vmcs_region;
	uintptr_t current_vmxon;
	uintptr_t vmcs;
	u32 launch_state;
	u64 feat_ctl;
};
#endif

#ifdef ENABLE_PML
#define PML_MAX_ENTRIES		512
#endif

struct vcpu {
	__align(PAGE_SIZE) u8 stack[KERNEL_STACK_SIZE];
	__align(PAGE_SIZE) u8 vapic_page[PAGE_SIZE];
#ifdef ENABLE_PML
	__align(PAGE_SIZE) uintptr_t pml[PML_MAX_ENTRIES];
#endif
	__align(PAGE_SIZE) struct vmcs vmxon;
	__align(PAGE_SIZE) struct vmcs vmcs;
	__align(PAGE_SIZE) struct ve_except_info ve;
	__align(64) struct pi_desc pi_desc;
	u32 secondary_ctl;	/* Emulation purposes of VE / VMFUNC  */
	u32 vm_func_ctl;	/* Same as above  */
	u64 *gp;
	u64 eflags;
	u64 ip;
	struct ept ept;
	/* Guest IDT (emulated)  */
	struct gdtr g_idt;
	/* Shadow IDT (working)  */
	struct gdtr idt;
	/* Shadow entires we know about so we can restore them appropriately.  */
	struct kidt_entry64 shadow_idt[X86_TRAP_VE + 1];
#ifdef NESTED_VMX
	/* Nested  */
	struct nested_vcpu nested_vcpu;
#endif
};

static inline void ksm_write_reg16(struct vcpu *vcpu, int reg, u16 val)
{
	*(u16 *)&vcpu->gp[reg] = val;
}

static inline void ksm_write_reg32(struct vcpu *vcpu, int reg, u32 val)
{
	*(u32 *)&vcpu->gp[reg] = val;
}

static inline void ksm_write_reg(struct vcpu *vcpu, int reg, u64 val)
{
	*(u64 *)&vcpu->gp[reg] = val;
}

static inline u16 ksm_read_reg16(struct vcpu *vcpu, int reg)
{
	return (u16)vcpu->gp[reg];
}

static inline u32 ksm_read_reg32(struct vcpu *vcpu, int reg)
{
	return (u32)vcpu->gp[reg];
}

static inline u64 ksm_read_reg(struct vcpu *vcpu, int reg)
{
	return vcpu->gp[reg];
}

static inline u32 ksm_combine_reg32(struct vcpu *vcpu, int lo, int hi)
{
	return (u32)ksm_read_reg32(vcpu, lo) | (u32)ksm_read_reg32(vcpu, hi) << 16;
}

static inline u64 ksm_combine_reg64(struct vcpu *vcpu, int lo, int hi)
{
	return (u64)ksm_read_reg32(vcpu, lo) | (u64)ksm_read_reg32(vcpu, hi) << 32;
}

static inline u64 *ksm_reg(struct vcpu *vcpu, int reg)
{
	return &vcpu->gp[reg];
}

struct page_hook_info;	/* avoid declared inside parameter list...  */
struct phi_ops {
	void(*init_eptp) (struct page_hook_info *phi, struct ept *ept);
	u16(*select_eptp) (struct page_hook_info *phi, u16 cur, u8 ar, u8 ac);
};

struct page_hook_info {
	u64 d_pfn;
	u64 c_pfn;
	u64 origin;
	void *c_va;
	struct phi_ops *ops;
};

static inline size_t page_hash(u64 va)
{
	/* Just take out the offset.  */
	return va >> PAGE_SHIFT;
}

static inline size_t rehash(const void *e, void *unused)
{
	return page_hash(((struct page_hook_info *)e)->origin);
}

#ifdef ENABLE_ACPI
typedef struct _DEV_EXT {
	PVOID CbRegistration;
	PCALLBACK_OBJECT CbObject;
} DEV_EXT, *PDEV_EXT;

extern NTSTATUS register_power_callback(PDEV_EXT ext);
extern void deregister_power_callback(PDEV_EXT ext);
#endif

struct ksm {
	int active_vcpus;
	struct vcpu vcpu_list[KSM_MAX_VCPUS];
	void *hotplug_cpu;
	u64 kernel_cr3;
	u64 origin_cr3;
	struct htable ht;
	__align(PAGE_SIZE) u8 msr_bitmap[PAGE_SIZE];
	__align(PAGE_SIZE) u8 io_bitmap_a[PAGE_SIZE];
	__align(PAGE_SIZE) u8 io_bitmap_b[PAGE_SIZE];
};
extern struct ksm ksm;

#ifdef DBG
/* print.c  */
extern NTSTATUS print_init(void);
extern void print_exit(void);
extern void do_print(const char *fmt, ...);
#endif

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

/* ept.c  */
extern bool ept_check_capabilitiy(void);
extern bool ept_init(struct ept *ept);
extern void ept_exit(struct ept *ept);
extern uintptr_t *ept_alloc_page(struct ept *ept, uintptr_t *pml4, uint8_t access, uintptr_t phys);
extern uintptr_t *ept_pte(struct ept *ept, uintptr_t *pml, uintptr_t phys);
extern bool ept_handle_violation(struct vcpu *vcpu);
extern void __ept_handle_violation(u64 cs, uintptr_t rip);

/* vcpu.c  */
extern void vcpu_init(struct vcpu *vcpu, uintptr_t sp, uintptr_t ip);
extern void vcpu_free(struct vcpu *vcpu);
extern void vcpu_set_mtf(bool enable);
extern void vcpu_switch_root_eptp(struct vcpu *vcpu, u16 index);

struct h_vmfunc {
	u32 eptp;
	u32 func;
};

static inline u16 vcpu_eptp_idx(const struct vcpu *vcpu)
{
	if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE)
		return vmcs_read16(EPTP_INDEX);

	const struct ve_except_info *ve = &vcpu->ve;
	return ve->eptp;
}

static inline u8 vcpu_vmfunc(u32 eptp, u32 func)
{
	struct vcpu *vcpu = ksm_current_cpu();
	if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VMFUNC)
		return __vmx_vmfunc(eptp, func);

	return __vmx_vmcall(HYPERCALL_VMFUNC, &(struct h_vmfunc) {
		.eptp = eptp,
		.func = func,
	});
}

/* Execute function on a CPU.  */
typedef NTSTATUS(*oncpu_fn_t) (void *);
static inline NTSTATUS exec_on_cpu(int cpu, oncpu_fn_t oncpu, void *param)
{
	PROCESSOR_NUMBER nr;
	NTSTATUS status = KeGetProcessorNumberFromIndex(cpu, &nr);
	if (!NT_SUCCESS(status))
		return status;

	GROUP_AFFINITY affinity = {
		.Group = nr.Group,
		.Mask = 1ULL << nr.Number
	};

	/* Switch to specified CPU, storing old.  */
	GROUP_AFFINITY prev;
	KeSetSystemGroupAffinityThread(&affinity, &prev);

	/* Fire in the hole!  */
	status = oncpu(param);

	/* Switch back to old CPU.  */
	KeRevertToUserGroupAffinityThread(&prev);
	return status;
}

static inline NTSTATUS sleep_ms(s32 ms)
{
	return KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER) {
		.QuadPart = -(10000 * ms)
	});
}

static inline void vcpu_put_idt(struct vcpu *vcpu, u16 cs, unsigned n, void *h)
{
	struct kidt_entry64 *e = idt_entry(vcpu->idt.base, n);
	memcpy(&vcpu->shadow_idt[n], e, sizeof(*e));
	__set_intr_gate(n, cs, vcpu->idt.base, (uintptr_t)h);
}

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
