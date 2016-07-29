#ifndef __ASM_H
#define __ASM_H

#if !defined(_AMD64_) && !defined(__x86_64) && !defined(_M_AMD64) && !defined(__M_X64)
#error only 64-bit is supported
#endif

#include "types.h"

#define __cli()		_disable()
#define __sti()		_enable()

typedef struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
} invvpid_t;

typedef struct {
	u64 ptr;
	u64 gpa;
} invept_t;

extern void __invvpid(u32 type, invvpid_t *i);
extern void __invept(u32 type, invept_t *i);
extern void __ept_violation(void);

static inline void __invept_all(void)
{
	__invept(VMX_EPT_EXTENT_GLOBAL, &(invept_t) { 0, 0 });
}

static inline void __invept_gpa(u64 ptr, u64 gpa)
{
	__invept(VMX_EPT_EXTENT_CONTEXT, &(invept_t) {
		.ptr = ptr,
		.gpa = gpa,
	});
}

static inline void __invvpid_all(void)
{
	__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, &(invvpid_t) { 0, 0, 0 });
}

static inline void __invvpid_vpid(u16 vpid, u64 gva)
{
	invvpid_t i;
	i.vpid = vpid;
	i.rsvd = 0;
	i.gva = gva;

	__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = gva
	});
}

static inline bool test_bit(u64 bits, u64 bs)
{
	return (bits & bs) == bs;
}

extern bool __vmx_vminit(void *, void *);
extern void __vmx_entrypoint(void);

extern u8 __vmx_vmcall(uintptr_t, void *);
extern u8 __vmx_vmfunc(u32, u32);

extern void __lgdt(const void *);
extern void __sgdt(void *);

extern void __lldt(u16);
extern u16 __sldt(void);

extern void __ltr(u16);
extern u16 __str(void);

extern void __writees(u16);
extern u16 __reades(void);

extern void __writecs(u16);
extern u16 __readcs(void);

extern void __writess(u16);
extern u16 __readss(void);

extern void __writeds(u16);
extern u16 __readds(void);

extern void __writefs(u16);
extern u16 __readfs(void);

extern void __writegs(u16);
extern u16 __readgs(void);

extern uintptr_t __lar(uintptr_t);
extern void __writecr2(uintptr_t);
extern void __invd(void);

#endif
