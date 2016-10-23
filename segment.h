#ifndef __SEGMENT_H
#define __SEGMENT_H

#include <pshpack1.h>
struct gdtr {
	u16 limit;
	uintptr_t base;
};

struct tss {
	u32 reserved1;
	u64 sp0;
	u64 sp1;
	u64 sp2;
	u64 reserved2;
	u64 ist[7];
	u32 reserved3;
	u32 reserved4;
	u16 reserved5;
	u16 io_bitmap_base;
	u64 io_bitmap[PAGE_SIZE*2 + 1];
};

typedef union {
	u64 i;
	struct {
		u16 lo;
		u16 sel;
		u8 ist : 3;
		u8 zero : 5;
		u8 type : 5;
		u8 dpl : 2;
		u8 p : 1;
		u16 mid;
	};
} kidt_entry_t;

struct kidt_entry64 {
	kidt_entry_t e32;
	u32 hi;
	u32 zero;
};
#include <poppack.h>

#define LOW_U16_U64(x) ((u64)(x) & 0xFFFF)
#define MID_U16_U64(x) (((u64)(x) >> 16) & 0xFFFF)
#define HIGH_U32_U64(x) ((u64)(x) >> 32)

static inline bool idte_present(const struct kidt_entry64 *e)
{
	return e->e32.p;
}

static inline u16 idte_sel(const struct kidt_entry64 *e)
{
	return e->e32.sel;
}

static inline u64 idte_addr(const struct kidt_entry64 *e)
{
	const kidt_entry_t *e32 = &e->e32;
	return (u64)e->hi << 32 | ((u32)e32->mid << 16 | e32->lo);
}

static inline struct kidt_entry64 *idt_entry(uintptr_t base, unsigned n)
{
	struct kidt_entry64 *table = (struct kidt_entry64 *)base;
	return &table[n];
}

static inline void pack_entry(struct kidt_entry64 *entry, u16 selector, uintptr_t addr)
{
	entry->hi = HIGH_U32_U64(addr);
	entry->zero = 0;

	kidt_entry_t *e = &entry->e32;
	e->lo = LOW_U16_U64(addr);
	e->sel = selector;
	e->ist = 0;
	e->zero = 0;
	e->type = GATE_INTERRUPT;
	e->dpl = 0;
	e->p = 1;
	e->mid = MID_U16_U64(addr);
}

static inline void put_entry(uintptr_t base, unsigned n, struct kidt_entry64 *entry)
{
	memcpy(idt_entry(base, n), entry, sizeof(*entry));
}

static inline void __set_intr_gate(unsigned n, u16 selector, uintptr_t base, uintptr_t addr)
{
	struct kidt_entry64 entry;
	pack_entry(&entry, selector, addr);
	put_entry(base, n, &entry);
}

static inline void set_intr_gate(unsigned n, u16 selector, uintptr_t base, void *addr)
{
	NT_ASSERT(n <= 0xFF);
	return __set_intr_gate(n, selector, base, (uintptr_t)addr);
}

typedef union {
	u64 all;
	struct {
		u64 limit_low : 16;
		u64 base_low : 16;
		u64 base_mid : 8;
		u64 type : 4;
		u64 system : 1;
		u64 dpl : 2;
		u64 present : 1;
		u64 limit_high : 4;
		u64 avl : 1;
		u64 l : 1;
		u64 db : 1;
		u64 gran : 1;
		u64 base_high : 8;
	};
} segmentdesc_t;

typedef struct {
	segmentdesc_t d32;
	u32 base_upper32;
	u32 reserved;
} segmentdesc64_t;

static inline segmentdesc_t *segment_desc(uintptr_t gdt, u16 sel)
{
	return (segmentdesc_t *)(gdt + (sel & ~3));
}

static uintptr_t segment_desc_base(segmentdesc_t *desc)
{
	uintptr_t base = (desc->base_high << 24 | desc->base_mid << 16 | desc->base_low) & MAXULONG;
	if (!desc->system)
		base |= (uintptr_t)(((segmentdesc64_t *)desc)->base_upper32) << 32;

	return base;
}

static uintptr_t __segmentbase(uintptr_t gdt, u16 sel)
{
	if (!sel)
		return 0;

	/* If it's an LDT segment, load the LDT, we deal with GDT mostly here,
	 * it's very unlikely that this will branch...  See calls down below in setup_vmcs().
 	 * in vcpu.c  (Hence parameter name "gdt")  */
	if (sel & 4) {
		segmentdesc_t *ldt = segment_desc(gdt, __sldt());
		uintptr_t ldt_base = segment_desc_base(ldt);
		return segment_desc_base(segment_desc(ldt_base, sel));
	}

	return segment_desc_base(segment_desc(gdt, sel));
}

static inline struct tss *get_tss(u16 sel)
{
	struct gdtr gdt;
	__sgdt(&gdt);

	return (struct tss *)__segmentbase(gdt.base, sel);
}

static inline struct tss *current_tss(void)
{
	return get_tss(__str());
}

#endif
