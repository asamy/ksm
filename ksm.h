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
#ifndef __KSM_H
#define __KSM_H

#ifdef __linux__
#include <linux/kernel.h>
#endif

#include "compiler.h"
#include "x86.h"
#include "vmx.h"
#include "mm.h"
#include "bitmap.h"
#include "htable.h"

#define KSM_MAX_VCPUS		32
#define __EXCEPTION_BITMAP	0

#define HYPERCALL_STOP		0	/* Stop virtualization on this CPU  */
#define HYPERCALL_IDT		1	/* Hook IDT entry (see vcpu_put_idt())  */
#define HYPERCALL_UIDT		2	/* Unhook IDT entry */
#ifdef EPAGE_HOOK
#define HYPERCALL_HOOK		3	/* Hook page  */
#define HYPERCALL_UNHOOK	4	/* Unhook page  */
#endif
#define HYPERCALL_VMFUNC	5	/* Emulate VMFunc  */
#ifdef PMEM_SANDBOX
#define HYPERCALL_SA_TASK	6	/* Sandbox: free EPTPs */
#endif
#ifdef INTROSPECT_ENGINE
#define HYPERCALL_INTROSPECT	7	/* Introspect: create eptp  */
#endif

/*
 * NOTE:
 *	All of these are relative to the per-cpu host stack
 *	pointer, do not change!!!  These are supposed
 *	to match ones defined by Intel in Exit Qualification.
 *	Those are also matched with the assembly code, see PUSH_REGS.
 *
 *	For a brief look on how the stack looks like when passed over to
 *	vcpu_handle_exit(), see vmx.S
 *
 * Note for the last 2:
 *	STACK_EFL_VCPU: in vcpu_do_exit(), this is vcpu.
 *	STACK_EFL_VCPU: in vcpu_handle_fail(), this is the eflags.
 *	STACK_VCPU:	in vcpu_handle_fail(), this is vcpu,
 */
#define STACK_REG_AX			0
#define STACK_REG_CX			1
#define STACK_REG_DX			2
#define STACK_REG_BX			3
#define STACK_REG_SP			4
#define STACK_REG_BP			5
#define STACK_REG_SI			6
#define STACK_REG_DI			7
#define STACK_REG_R8			8
#define STACK_REG_R9			9
#define STACK_REG_R10			10
#define STACK_REG_R11			11
#define STACK_REG_R12			12
#define STACK_REG_R13			13
#define STACK_REG_R14			14
#define STACK_REG_R15			15
#define STACK_EFL_VCPU			16
#define STACK_VCPU			17

#define KSM_PANIC_CODE		0xCCDDFF11
#define VCPU_TRIPLEFAULT		0x33DDE83A
#define VCPU_BUG_UNHANDLED		0xBAADF00D
#define VCPU_IRQ_NOT_HANDLED		0xCAFEBABE
#define KSM_PANIC_FAILED_VMENTRY	0xBAADBABE
#define KSM_PANIC_GUEST_STATE	0xBAAD7A1E
#define KSM_PANIC_UNEXPECTED	0xEEEEEEE9
#ifdef DBG
#ifndef __linux__
#define KSM_PANIC(a, b, c, d)	KeBugCheckEx(MANUALLY_INITIATED_CRASH, a, b, c, d)
#else
#define KSM_PANIC(a, b, c, d)panic("bugcheck 0x%016X 0x%016X 0x%016X 0x%016X\n", a, b, c, d)
#endif
#else
#define KSM_PANIC(a, b, c, d)	(void)0
#endif

/* Short name:  */
#ifdef __linux__
#define cpu_nr()			smp_processor_id()
#else
#define cpu_nr()			KeGetCurrentProcessorNumberEx(NULL)
#endif

/* VPID 0 is used by VMX root.  */
#define vpid_nr()			(cpu_nr() + 1)
#ifdef __linux__
#define proc_name()			current->comm
#define proc_id()			current->pid
#else
#define current				PsGetCurrentProcess()
#define proc_name()			PsGetProcessImageFileName(current)
#define proc_id()			PsGetProcessId(current)
#endif

#ifdef ENABLE_PRINT
#ifdef __linux__
#define KSM_DEBUG(fmt, args...)	printk(KERN_INFO "ksm: CPU %d: %s: " fmt, cpu_nr(), __func__, ##args)
#define KSM_DEBUG_RAW(str)		printk(KERN_INFO "ksm: CPU %d: %s: " str, cpu_nr(), __func__)
#else
#ifdef _MSC_VER
#define KSM_DEBUG(fmt, ...)		do_print("ksm: CPU %d: " __func__ ": " fmt, cpu_nr(), __VA_ARGS__)
#define KSM_DEBUG_RAW(str)		do_print("ksm: CPU %d: " __func__ ": " str, cpu_nr())
#else
/* avoid warning on empty argument list  */
#define KSM_DEBUG(fmt, args...)	do_print("ksm: CPU %d: %s: " fmt, cpu_nr(), __func__, ##args)
#define KSM_DEBUG_RAW(str)		do_print("ksm: CPU %d: %s: " str, cpu_nr(), __func__)
#endif
#endif
#else
#define KSM_DEBUG(fmt, ...)
#define KSM_DEBUG_RAW(str)
#endif

/*
 * Should definitely replace this with something more useful, right now this is
 * utterly useless...
 */
#ifdef VCPU_TRACER_LOG
#define VCPU_TRACER_START()		KSM_DEBUG("%p\n", vcpu)
#define VCPU_TRACER_END()		KSM_DEBUG("%p handled\n", vcpu)
#else
#define VCPU_TRACER_START()
#define VCPU_TRACER_END()
#endif

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
#define EPT_ACCESS_RX			(EPT_ACCESS_READ | EPT_ACCESS_EXEC)
#define EPT_ACCESS_RWX			(EPT_ACCESS_RW | EPT_ACCESS_EXEC)
#define EPT_ACCESS_ALL			EPT_ACCESS_RWX

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
#define EPTP_INIT_USED			3			/* number of unique ptrs currently in use and should be freed  */
#define EPTP(e, i)			(e)->ptr_list[(i)]
#define EPT4(e, i)			(e)->pml4_list[(i)]
#define for_each_eptp(ept, i)		\
	for (int i = 0; i < EPT_MAX_EPTP_LIST; ++i)	\
		if (test_bit(i, ept->ptr_bitmap))

#define EPT_BUGCHECK_CODE		0x3EDFAAAA
#define EPT_BUGCHECK_TOOMANY		0xFFFFFFFE
#define EPT_BUGCHECK_MISCONFIG		0xE3E3E3E3
#define EPT_BUGCHECK_EPTP_LIST		0xDFDFDFDF
#define EPT_UNHANDLED_VIOLATION		0xEEEEEEEE
#define KSM_EPT_REQUIRED_EPT		(VMX_EPT_PAGE_WALK_4_BIT | VMX_EPTP_WB_BIT |\
					 VMX_EPT_INVEPT_BIT | VMX_EPT_EXTENT_GLOBAL_BIT)

struct shadow_idt_entry {
	unsigned n;
	void *h;
};

struct vmcs {
	u32 revision_id;
	u32 abort;
	u32 data[1];
};

#ifdef _MSC_VER
#pragma warning(disable:4201)	/* stupid nonstandard bullshit  */
#endif

/* Posted interrupt descriptor */
struct pi_desc {
	/*
	 * 256 bits of posted interrupt requests
	 * The bit index is the vector in IDT.
	 */
	u32 pir[8];
	union {
		struct {
			/*
			 * bit 256 - Outstanding notification, must be set to notify
			 * the processor when interrupt vector is set in the PIR.
			 */
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
} __align(64);

static inline bool pi_test_bit(struct pi_desc *d, int vector)
{
	return test_bit(vector, (unsigned long *)d->pir);
}

static inline void pi_set_irq(struct pi_desc *d, int vector)
{
	set_bit(vector, (unsigned long *)d->pir);
	d->on = 1;
}

static inline void pi_clear_irq(struct pi_desc *d, int vector)
{
	clear_bit(vector, (unsigned long *)d->pir);
	d->on = 0;
}

#ifdef NESTED_VMX
#define VMCS_LAUNCH_STATE_NONE		0	/* no state  */
#define VMCS_LAUNCH_STATE_CLEAR		1	/* vmclear was executed  */
#define VMCS_LAUNCH_STATE_LAUNCHED	2	/* vmlaunch was executed  */

struct nested_vcpu {
	uintptr_t vmcs;			/* mapped via gpa->hpa (vmcs_region)  */
	uintptr_t vmcs_region;		/* gpa  */
	uintptr_t vmxon_region;		/* gpa  */
	uintptr_t current_vmxon;	/* gpa (set if nested in root)  */
	u32 launch_state;		/* vmcs launch state  */
	u64 feat_ctl;			/* MSR_IA32_FEATURE_CONTROL  */
	bool inside_guest;		/* set if inside nested's guest  */
};

static inline void nested_enter(struct nested_vcpu *nested)
{
	/*
	 * About to enter nested guest due to a vmlaunch /
	 * vmresume exuected by the nested hypervisor.
	 */
	nested->inside_guest = true;
	nested->current_vmxon = 0;
}

static inline void nested_leave(struct nested_vcpu *nested)
{
	/*
	 * About to leave nested guest to enter nested hypervisor
	 * to process an event coming from the nested guest.
	 */
	nested->inside_guest = false;
	nested->current_vmxon = nested->vmxon_region;
}

static inline bool nested_entered(const struct nested_vcpu *nested)
{
	/*
	 * If this value is false, then it means the event came from
	 * the nested hypervisor and therefore needs to be processed
	 * by us, otherwise, it came from the nested guest and we should
	 * probably exit to the nested hypervisor, see exit.c
	 */
	return nested->inside_guest;
}

/*
 * Should probably map and unmap vmcs as needed, but this is OK for the time
 * being...
 * */
static inline bool nested_has_vmcs(const struct nested_vcpu *nested)
{
	return nested->vmcs != 0;
}

static inline void nested_free_vmcs(struct nested_vcpu *nested)
{
	if (nested->vmcs != 0) {
		mm_unmap((void *)nested->vmcs, PAGE_SIZE);
		nested->vmcs = 0;
	}
}
#endif

/*
 * IRQs are queued to incase we inject another interrupt
 * (or we were unable to past VM exit), so that we can inject
 * contributory faults appropriately, e.g. #PF into #DF, etc.
 *
 * See exit.c on how this is used.
 */
struct pending_irq {
	bool pending;
	u32 err;
	u32 bits;
	u32 instr_len;
};

#ifdef ENABLE_PML
#define PML_MAX_ENTRIES		512
#endif

/* #VE (EPT Violation via IDT exception informaiton)  */
struct ve_except_info {
	u32 reason;		/* EXIT_REASON_EPT_VIOLATION  */
	u32 except_mask;	/* FFFFFFFF (set to 0 to deliver more)  */
	u64 exit;		/* normal exit qualification bits, see above  */
	u64 gla;		/* guest linear address */
	u64 gpa;		/* guest physical address  */
	u16 eptp;		/* current EPTP index  */
};

struct ept_ve_around {
	struct vcpu *vcpu;
	struct ve_except_info *info;
	uintptr_t rip;
	uintptr_t cr3;
	int dpl;
	u16 eptp_next;
	bool invalidate;
};

struct ept {
	u64 *ptr_list;
	u64 *pml4_list[EPT_MAX_EPTP_LIST];
	unsigned long
		ptr_bitmap[EPT_MAX_EPTP_LIST / sizeof(unsigned long)];
};

struct vcpu {
	void *stack;
	void *vapic_page;
#ifdef ENABLE_PML
	void *pml;
#endif
	struct vmcs *vmxon;
	struct vmcs *vmcs;
	struct ve_except_info *ve;
	struct pi_desc pi_desc;
	u32 entry_ctl;
	u32 exit_ctl;
	u32 pin_ctl;
	u32 cpu_ctl;
	u32 secondary_ctl;	/* Emulation purposes of VE / VMFUNC  */
	u64 vm_func_ctl;	/* Same as above  */
	bool subverted;
	/* Those are set during VM-exit only:  */
	uintptr_t *hsp;		/* stack ptr when passed to vcpu_handle_exit()  */
	uintptr_t eflags;	/* guest eflags  */
	uintptr_t ip;		/* guest IP  */	
	u16 curr_handler;	/* Current VM exit handler  */
#ifdef DBG
	u16 prev_handler;	/* Previous VM exit handler  */
#endif
	/* These bits are also masked from CRx_READ_SHADOW.  */
	uintptr_t cr0_guest_host_mask;
	uintptr_t cr4_guest_host_mask;
	/* Pending IRQ  */
	struct pending_irq irq;
	/* EPT for this CPU  */
	struct ept ept;
	/* Guest IDT (emulated)  */
	struct gdtr g_idt;
	/* Shadow IDT (working)  */
	struct gdtr idt;
	/* Shadow entires we know about so we can restore them appropriately.  */
	struct kidt_entry64 shadow_idt[256];
#ifdef PMEM_SANDBOX
	/* EPTP before switch to per-task eptp.  */
	u16 eptp_before;
	void *last_switch;
#endif
#ifdef NESTED_VMX
	/* Nested  */
	struct nested_vcpu nested_vcpu;
#endif
};

static inline bool vcpu_has_pending_irq(const struct vcpu *vcpu)
{
	return vcpu->irq.pending;
}

static inline void ksm_write_reg16(struct vcpu *vcpu, int reg, u16 val)
{
	*(u16 *)&vcpu->hsp[reg] = val;
}

static inline void ksm_write_reg32(struct vcpu *vcpu, int reg, u32 val)
{
	*(u32 *)&vcpu->hsp[reg] = val;
}

static inline void ksm_write_reg(struct vcpu *vcpu, int reg, uintptr_t val)
{
	*(uintptr_t *)&vcpu->hsp[reg] = val;
}

static inline u16 ksm_read_reg16(struct vcpu *vcpu, int reg)
{
	return (u16)vcpu->hsp[reg];
}

static inline u32 ksm_read_reg32(struct vcpu *vcpu, int reg)
{
	return (u32)vcpu->hsp[reg];
}

static inline uintptr_t ksm_read_reg(struct vcpu *vcpu, int reg)
{
	return vcpu->hsp[reg];
}

static inline u32 ksm_combine_reg32(struct vcpu *vcpu, int lo, int hi)
{
	return (u32)ksm_read_reg16(vcpu, lo) | (u32)ksm_read_reg16(vcpu, hi) << 16;
}

static inline u64 ksm_combine_reg64(struct vcpu *vcpu, int lo, int hi)
{
	return (u64)ksm_read_reg32(vcpu, lo) | (u64)ksm_read_reg32(vcpu, hi) << 32;
}

static inline uintptr_t *ksm_reg(struct vcpu *vcpu, int reg)
{
	return &vcpu->hsp[reg];
}

#ifdef EPAGE_HOOK
struct page_hook_info;	/* avoid declared inside parameter list...  */
struct phi_ops {
	void(*init_eptp) (struct page_hook_info *phi, struct ept *ept);
	u16(*select_eptp) (struct page_hook_info *phi, struct ept_ve_around *ve);
};

struct page_hook_info {
	u64 dpa;
	u64 cpa;
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
#endif

struct ksm {
	int active_vcpus;
	struct vcpu vcpu_list[KSM_MAX_VCPUS];
	struct pmem_range ranges[MAX_RANGES];
	int range_count;
	uintptr_t host_pgd;
	u64 vpid_ept;
#ifdef EPAGE_HOOK
	struct htable ht;
#endif
#ifdef PMEM_SANDBOX
	struct list_head task_list;
	spinlock_t task_lock;
#endif
#ifdef INTROSPECT_ENGINE
	struct list_head watch_list;
	spinlock_t watch_lock;
#endif
	void *msr_bitmap;
	void *io_bitmap_a;
	void *io_bitmap_b;
};

/*
 * Do NOT use inside VMX root mode, use vcpu_to_ksm() instead...
 * Use this and I'll come after you.
 */
extern struct ksm *ksm;

#if !defined(__linux__) && defined(ENABLE_PRINT)
/* print.c  */
extern NTSTATUS print_init(void);
extern void print_exit(void);
extern void do_print(const char *fmt, ...);
#endif

/* ksm.c  */
extern int ksm_init(struct ksm **kp);
extern int ksm_free(struct ksm *k);
extern int ksm_subvert(struct ksm *k);
extern int ksm_unsubvert(struct ksm *k);
extern int __ksm_init_cpu(struct ksm *k);
extern int __ksm_exit_cpu(struct ksm *k);
extern int ksm_hook_idt(unsigned n, void *h);
extern int ksm_free_idt(unsigned n);
extern bool ksm_write_virt(struct vcpu *vcpu, u64 gva, const u8 *data, size_t len);
extern bool ksm_read_virt(struct vcpu *vcpu, u64 gva, u8 *data, size_t len);

static inline struct vcpu *ksm_cpu_at(struct ksm *k, int cpu)
{
	return &k->vcpu_list[cpu];
}

static inline struct vcpu *ksm_cpu(struct ksm *k)
{
	return ksm_cpu_at(k, cpu_nr());
}

static inline struct vcpu *ksm_current_cpu(void)
{
	BUG_ON(!ksm);
	return ksm_cpu(ksm);
}

static inline struct ksm *vcpu_to_ksm(struct vcpu *vcpu)
{
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif
	uintptr_t k = (uintptr_t)container_of(vcpu, struct ksm, vcpu_list);
	return (struct ksm *)(k - cpu_nr() * sizeof(*vcpu));
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
}

struct h_vmfunc {
	u32 eptp;
	u32 func;
};

static inline u16 vcpu_eptp_idx(const struct vcpu *vcpu)
{
	if (vcpu->secondary_ctl & SECONDARY_EXEC_ENABLE_VE)
		return vmcs_read16(EPTP_INDEX);

	const struct ve_except_info *ve = vcpu->ve;
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

static inline void vcpu_put_idt(struct vcpu *vcpu, u16 cs, unsigned n, void *h)
{
	struct kidt_entry64 *e = idt_entry(vcpu->idt.base, n);
	memcpy(&vcpu->shadow_idt[n], e, sizeof(*e));
	set_intr_gate(n, cs, vcpu->idt.base, (uintptr_t)h);
}

static inline bool cpu_supports_invvpidtype(const struct ksm *k, int type)
{
	int avail = (k->vpid_ept >> VMX_VPID_EXTENT_SHIFT) & 7;
	return avail & (1 << type);
}

static inline bool cpu_supports_invepttype(const struct ksm *k, int type)
{
	int avail = (k->vpid_ept >> VMX_EPT_EXTENT_SHIFT) & 6;
	return avail & (1 << type);
}

static inline u8 cpu_invept(struct ksm *k, u64 gpa, u64 ptr)
{
	if (cpu_supports_invepttype(k, VMX_EPT_EXTENT_CONTEXT))
		return __invept_gpa(ptr, gpa);

	return __invept_all();
}

#ifdef EPAGE_HOOK
/* page.c  */
extern int ksm_hook_epage(void *original, void *redirect);
extern int ksm_unhook_page(struct ksm *k, void *original);
extern int __ksm_unhook_page(struct page_hook_info *phi);
extern struct page_hook_info *ksm_find_page(struct ksm *k, void *va);
extern struct page_hook_info *ksm_find_page_pfn(struct ksm *k, uintptr_t pfn);
#endif

/* sandbox.c  */
#ifdef PMEM_SANDBOX
#ifndef __linux__
typedef HANDLE pid_t;
#endif

extern int ksm_sandbox_init(struct ksm *k);
extern int ksm_sandbox_exit(struct ksm *k);
extern bool ksm_sandbox_handle_ept(struct ept_ve_around *ve);
extern void ksm_sandbox_handle_cr3(struct vcpu *vcpu, u64 cr3);
extern bool ksm_sandbox_handle_vmcall(struct vcpu *vcpu, uintptr_t arg);
extern int ksm_sandbox(struct ksm *k, pid_t pid);
extern int ksm_unbox(struct ksm *k, pid_t pid);
#endif

/* introspect.c  */
#ifdef INTROSPECT_ENGINE
extern int ksm_introspect_init(struct ksm *k);
extern int ksm_introspect_exit(struct ksm *k);
extern int ksm_introspect_start(struct ksm *k);
extern int ksm_introspect_stop(struct ksm *k);
extern bool ksm_introspect_handle_vmcall(struct vcpu *vcpu, uintptr_t arg);
extern bool ksm_introspect_handle_ept(struct ept_ve_around *ve);
extern int ksm_introspect_add_watch(struct ksm *k, struct watch_ioctl *watch);
extern int ksm_introspect_rem_watch(struct ksm *k, struct watch_ioctl *watch);
#endif

/* vcpu.c  */
extern int vcpu_init(struct vcpu *vcpu);
extern void vcpu_free(struct vcpu *vcpu);
extern void vcpu_switch_root_eptp(struct vcpu *vcpu, u16 index);
extern u64 *ept_alloc_page(u64 *pml4, int access, u64 gpa, u64 hpa);
extern u64 *ept_pte(u64 *pml4, u64 gpa);
extern bool ept_handle_violation(struct vcpu *vcpu);
extern bool ept_create_ptr(struct ept *ept, int access, u16 *out_eptp);
extern void ept_free_ptr(struct ept *ept, u16 eptp);

static inline void __set_epte_pfn(u64 *epte, u64 pfn)
{
	*epte &= ~PAGE_PA_MASK;
	*epte |= (pfn & PTI_MASK) << PTI_SHIFT;
}

static inline void __set_epte_ar(u64 *epte, int ar)
{
	*epte &= ~(ar ^ EPT_ACCESS_ALL);
	*epte |= ar & EPT_AR_MASK;
}

static inline void __set_epte_ar_inplace(u64 *epte, int ar)
{
	__set_epte_ar(epte, ar | (*epte & EPT_AR_MASK));
}

static inline void __set_epte_ar_pfn(u64 *epte, int ar, u64 pfn)
{
	__set_epte_pfn(epte, pfn);
	__set_epte_ar(epte, ar);
}

static inline void ept_set_hpa(struct ept *ept, int eptp, u64 gpa, u64 hpa)
{
	u64 *epte = ept_pte(EPT4(ept, eptp), gpa);
	if (epte)
		__set_epte_pfn(epte, hpa >> PAGE_SHIFT);
}

static inline void ept_set_ar(struct ept *ept, int eptp, u64 gpa, int ar)
{
	u64 *epte = ept_pte(EPT4(ept, eptp), gpa);
	if (epte)
		__set_epte_ar(epte, ar);
}

static inline bool ept_gpa_to_hpa(struct ept *ept, int eptp, u64 gpa, u64 *hpa)
{
	u64 *epte = ept_pte(EPT4(ept, eptp), gpa);
	if (!epte || !(*epte & EPT_AR_MASK))
		return false;

	*hpa = PAGE_PA(*epte);
	return true;
}

static inline bool gva_to_gpa(struct vcpu *vcpu, uintptr_t cr3,
			      uintptr_t gva, u32 ac, u64 *gpa)
{
	pte_t *pte = pte_from_cr3_va(cr3, gva);
	if (!pte || (pte->pte & ac) != ac)
		return false;

	*gpa = PAGE_PA(pte->pte);
	return true;
}

static inline bool gpa_to_hpa(struct vcpu *vcpu, u64 gpa, u64 *hpa)
{
	return ept_gpa_to_hpa(&vcpu->ept, vcpu_eptp_idx(vcpu), gpa, hpa);
}

static inline void ar_get_bits(u8 ar, char *p)
{
	p[0] = p[1] = p[2] = '-';
	p[3] = '\0';

	if (ar & EPT_ACCESS_READ)
		p[0] = 'r';

	if (ar & EPT_ACCESS_WRITE)
		p[1] = 'w';

	if (ar & EPT_ACCESS_EXEC)
		p[2] = 'x';
}

static inline void __get_epte_ar(u64 *epte, char *p)
{
	return ar_get_bits((u8)*epte & EPT_AR_MASK, p);
}

static inline void get_epte_ar(u64 *pml4, u64 gpa, char *p)
{
	return __get_epte_ar(ept_pte(pml4, gpa), p);
}

/* resubv.c  */
#ifdef ENABLE_RESUBV
extern int register_power_callback(void);
extern void unregister_power_callback(void);
#else
static int register_power_callback(void) { return 0; }
static void unregister_power_callback(void) { }
#endif

/* hotplug.c  */
extern int register_cpu_callback(void);
extern void unregister_cpu_callback(void);

#endif
