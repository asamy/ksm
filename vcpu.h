/* Per-CPU based stuff.  */
#ifndef __VCPU_H
#define __VCPU_H

#include "x86.h"
#include "vmx.h"
#include "asm.h"
#include "ept.h"
#include "ksm.h"
#include "idt.h"

/* Avoid NT retardism  */
#define container_of(address, type, field)	CONTAINING_RECORD(address, type, field)

static __forceinline uintptr_t __pa(uintptr_t *va)
{
	return (uintptr_t)MmGetPhysicalAddress((void *)va).QuadPart;
}

static __forceinline uintptr_t *__va(uintptr_t phys)
{
	PHYSICAL_ADDRESS p;
	p.QuadPart = phys;

	return (uintptr_t *)MmGetVirtualForPhysical(p);
}

static __forceinline uintptr_t __pfn(uintptr_t phys)
{
	return phys >> PAGE_SHIFT;
}

static __forceinline uintptr_t *va_to_pxe(uintptr_t va)
{
	uintptr_t off = (va >> PXI_SHIFT) & PTX_MASK;
	return (uintptr_t *)(PXE_BASE + off * sizeof(uintptr_t));
}

static __forceinline uintptr_t *va_to_ppe(uintptr_t va)
{
	uintptr_t off = (va >> PPI_SHIFT) & PPI_MASK;
	return (uintptr_t *)(PPE_BASE + off * sizeof(uintptr_t));
}

static __forceinline uintptr_t *va_to_pde(uintptr_t va)
{
	uintptr_t off = (va >> PDI_SHIFT) & PDI_MASK;
	return (uintptr_t *)(PDE_BASE + off * sizeof(uintptr_t));
}

static __forceinline uintptr_t *va_to_pte(uintptr_t va)
{
	uintptr_t off = (va >> PTI_SHIFT) & PTI_MASK;
	return (uintptr_t *)(PTE_BASE + off * sizeof(uintptr_t));
}

static __forceinline void *pte_to_va(uintptr_t *pte)
{
	return (void *)((((uintptr_t)pte - PTE_BASE) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);
}

static __forceinline bool is_phys(uintptr_t va)
{
	return *va_to_pxe(va) & PAGE_PRESENT && *va_to_ppe(va) & PAGE_PRESENT &&
		(((*va_to_pde(va) & 0x81) == 0x81) || *va_to_pte(va) & PAGE_PRESENT);
}

#define __CR0_GUEST_HOST_MASK	0
#define __CR4_GUEST_HOST_MASK	0
#define __EXCEPTION_BITMAP	0

#define HYPERCALL_STOP		0	/* Stop virtualization on this CPU  */
#define HYPERCALL_IDT		1	/* Hook this CPUs IDT (see idt.h, exit.c)  */
#define HYPERCALL_HOOK		2	/* Hook page  */
#define HYPERCALL_UNHOOK	3	/* Unhook page  */

struct gp_regs {
	u64 r15;
	u64 r14;
	u64 r13;
	u64 r12;
	u64 r11;
	u64 r10;
	u64 r9;
	u64 r8;
	u64 di;
	u64 si;
	u64 bp;
	u64 sp;
	u64 bx;
	u64 dx;
	u64 cx;
	u64 ax;
};

struct regs {
	struct gp_regs gp;
	uintptr_t eflags;
};

struct exit_stack {
	struct gp_regs regs;
	uintptr_t pad;
	struct vcpu *vcpu;
};

struct guest_context {
	struct exit_stack *stack;
	u64 eflags;
	u64 ip;
	u64 cr8;
	KIRQL irql;
};

static inline struct gp_regs *__gp_regs(struct exit_stack *stack)
{
	return &stack->regs;
}

static inline struct gp_regs *gp_regs(struct guest_context *gc)
{
	return __gp_regs(gc->stack);
}

static inline struct vcpu *__to_vcpu(struct exit_stack *stack)
{
	return stack->vcpu;
}

static inline struct vcpu *to_vcpu(struct guest_context *gc)
{
	return __to_vcpu(gc->stack);
}

static inline uintptr_t *gp_reg(struct gp_regs *regs, unsigned index)
{
	return &((uintptr_t *)regs)[15 - index];
}

static inline void vcpu_do_succeed(struct guest_context *gc)
{
	gc->eflags &= ~(X86_EFLAGS_ZF | X86_EFLAGS_CF);
}

static inline void vcpu_do_fail(struct guest_context *gc)
{
	gc->eflags |= X86_EFLAGS_CF | X86_EFLAGS_ZF;
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

struct vcpu {
	int nr;
	void *stack;
	struct vmcs *vmxon;
	struct vmcs *vmcs;
	struct ept ept;
	struct ve_except_info *ve;
	struct gdtr g_idt;		/* Guest IDT (emulated)  */
	struct gdtr idt;		/* Shadow IDT (working)  */
	void *shadow_idt[0x100];	/* Shadow IDT entries  */
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

/* exit.c  */
extern bool vcpu_handle_exit(struct exit_stack *stack);
extern void vcpu_handle_fail(struct regs *regs);
extern void vcpu_dump_regs(const struct regs *regs, uintptr_t sp);
extern void vcpu_set_mtf(bool enable);

/* vcpu.c  */
extern void vcpu_init(uintptr_t sp, uintptr_t ip, struct ksm *k);
extern void vcpu_free(struct vcpu *vcpu);
extern void vcpu_flush_idt(struct vcpu *vcpu);
extern bool vcpu_hook_idte(struct vcpu *vcpu, struct shadow_idt_entry *h);
extern void vcpu_subverted(void);

#endif
