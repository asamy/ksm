/* Per-CPU based stuff.  */
#ifndef __VCPU_H
#define __VCPU_H

#include "x86.h"
#include "vmx.h"
#include "asm.h"
#include "ksm.h"
#include "ept.h"
#include "idt.h"

#ifndef NonPagedPoolNx
#define NonPagedPoolNx	512
#endif

/* Avoid NT retardism  */
#define container_of(address, type, field)	CONTAINING_RECORD(address, type, field)

static inline uintptr_t __pa(uintptr_t *va)
{
	return (uintptr_t)MmGetPhysicalAddress((void *)va).QuadPart;
}

static inline uintptr_t *__va(uintptr_t phys)
{
	PHYSICAL_ADDRESS p;
	p.QuadPart = phys;

	return (uintptr_t *)MmGetVirtualForPhysical(p);
}

static inline uintptr_t __pfn(uintptr_t phys)
{
	return phys >> PAGE_SHIFT;
}

#define __CR0_GUEST_HOST_MASK	0
#define __CR4_GUEST_HOST_MASK	0
#define __EXCEPTION_BITMAP	0

#define HYPERCALL_STOP		0	/* Stop virtualization on this CPU  */
#define HYPERCALL_IDT		1	/* Hook IDT entry (see idt.h, exit.c)  */
#define HYPERCALL_UIDT		2	/* Unhook IDT entry  */
#define HYPERCALL_HOOK		3	/* Hook page  */
#define HYPERCALL_UNHOOK	4	/* Unhook page  */

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

struct regs {
	u64 gp[REG_MAX];
	u64 eflags;
};

struct guest_context {
	struct vcpu *vcpu;
	u64 *gp;
	u64 eflags;
	u64 ip;
	u64 cr8;
	KIRQL irql;
};

static inline struct vcpu *to_vcpu(struct guest_context *gc)
{
	return gc->vcpu;
}

struct shadow_idt_entry {
	unsigned n;
	void *h;
};

struct vmcs {
	u32 revision_id;
	u32 abort;
	u32 data[1];
};

/* Page Modification Logging  */
#define PML_MAX_ENTRIES		512

struct vcpu {
	void *stack;
	uintptr_t *pml;
	struct vmcs *vmxon;
	struct vmcs *vmcs;
	struct ept ept;
	struct ve_except_info *ve;
	struct gdtr g_idt;			/* Guest IDT (emulated)  */
	struct gdtr idt;			/* Shadow IDT (working)  */
	struct kidt_entry64 shadow_idt[0x100];	/* Shadow IDT entries  */
};

#define VCPU_EXIT_IRQL			DISPATCH_LEVEL
#define VCPU_BUGCHECK_CODE		0xCCDDFF11
#define VCPU_TRIPLEFAULT		0x33DDE83A
#define VCPU_BUG_UNHANDLED		0xBAADF00D
#define VCPU_IRQ_NOT_HANDLED		0xCAFEBABE
#define VCPU_BUGCHECK_FAILED_VMENTRY	0xBAADBABE
#ifdef DBG
#define VCPU_BUGCHECK(a, b, c, d)	KeBugCheckEx(MANUALLY_INITIATED_CRASH, a, b, c, d)
#else
#define VCPU_BUGCHECK(a, b, c, d)	(void)0
#endif

/* Short name:  */
#define cpu_nr()			KeGetCurrentProcessorNumberEx(NULL)
#define proc_nr()			PsGetCurrentProcessId()

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifdef DBG
#define VCPU_DEBUG(fmt, ...)		DbgPrint("CPU %d: " __func__ ": " fmt, cpu_nr(), __VA_ARGS__)
#define VCPU_DEBUG_RAW(str)		DbgPrint("CPU %d: " __func__ ": " str, cpu_nr())
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

#define VCPU_ENTER_GIRQL()	\
	KIRQL __save_irql = KeGetCurrentIrql();		\
	KeLowerIrql(gc->irql)						\

#define VCPU_EXIT_GIRQL()	\
	KfRaiseIrql(__save_irql)

static inline void vcpu_put_idt(struct vcpu *vcpu, u16 cs, unsigned n, void *h)
{
	struct kidt_entry64 *e = idt_entry(vcpu->idt.base, n);
	memcpy(&vcpu->shadow_idt[n], e, sizeof(*e));
	__set_intr_gate(n, cs, vcpu->idt.base, (uintptr_t)h);
}

/* exit.c  */
extern bool vcpu_handle_exit(u64 *regs);
extern void vcpu_handle_fail(struct regs *regs);
extern void vcpu_dump_regs(const struct regs *regs, uintptr_t sp);
extern void vcpu_set_mtf(bool enable);

/* vcpu.c  */
extern void vcpu_init(uintptr_t sp, uintptr_t ip, struct ksm *k);
extern void vcpu_free(struct vcpu *vcpu);
extern void vcpu_subverted(void);

#endif
