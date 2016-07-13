#ifndef __ASM_H
#define __ASM_H

#ifndef _AMD64_
#error only 64-bit is supported
#endif

#include "types.h"

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
	invept_t i = { 0, 0 };
	__invept(VMX_EPT_EXTENT_GLOBAL, &i);
}

static inline void __invept_gpa(u64 ptr, u64 gpa)
{
	invept_t i;
	i.ptr = ptr;
	i.gpa = gpa;


	__invept(VMX_EPT_EXTENT_CONTEXT, &i);
}

static inline void __invvpid_all(void)
{
	invvpid_t i = { 0, 0, 0 };
	__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, &i);
}

static inline void __invvpid_vpid(u16 vpid, u64 gva)
{
	invvpid_t i;
	i.vpid = vpid;
	i.rsvd = 0;
	i.gva = gva;

	__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &i);
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

// Microsoft
extern u64 RtlGetEnabledExtendedFeatures(u64 FeatureMask);
extern void *RtlPcToFileHeader(void *pc, void **base);

#endif
