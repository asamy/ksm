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
#ifndef __ASM_H
#define __ASM_H

#if !defined(_AMD64_) && !defined(__x86_64) && !defined(_M_AMD64) && !defined(__M_X64)
#error only 64-bit is supported
#endif

#include "types.h"

#define __cli()			_disable()
#define __sti()			_enable()
#ifdef MINGW
#define __return_addr()		__builtin_return_address(0)
#else
#define __return_addr()		_ReturnAddress()
#endif

#ifdef MINGW
#define __writedr(dr, val)					\
	__asm __volatile("movq	%[Val], %%dr" #dr		\
			 : : [Val] "a" ((val)))

#define __readdr(dr) __extension__ ({			\
	unsigned long long val;				\
	__asm __volatile("movq	%%dr" #dr ", %[Val]"	\
			 : [Val] "=r" (val));		\
	(val);						\
})

static inline void _xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	__asm __volatile(".byte 0x0f,0x01,0xd1"
			 :: "a" (eax), "d" (edx), "c" (index));
}

static inline void __cpuidex(int *ret, int func, int subf)
{
	u32 eax, ebx, ecx, edx;
	__asm __volatile("cpuid"
			 : "=a" (eax), "=D" (ebx), "=c" (ecx), "=d" (edx)
			 : "a" (func), "c" (subf));
	ret[0] = eax;
	ret[1] = ebx;
	ret[2] = ecx;
	ret[3] = edx;
}

static inline u64 __lar(u64 sel)
{
	u64 ar;
	__asm __volatile("lar %0, %[sel]"
			 : "=r" (ar)
			 : [sel] "r" (sel));
	return ar;
}

#define __wbinvd()	__asm __volatile("wbinvd")
#define __invd()	__asm __volatile("invd")
#define __halt()	__asm __volatile("hlt")
#define __invlpg(addr)	__asm __volatile("invlpg (%0)" :: "r" (addr) : "memory")
#define __readeflags()	({							\
	u64 rflags;								\
	__asm __volatile("pushfq\n\tpopq %[rf]" : [rf] "=r" (rflags));		\
	rflags;									\
})

#define DEFINE_SEL_READER(name, instr)				\
	static inline u16 name(void)				\
	{							\
		u16 tmp;					\
		__asm __volatile(instr : "=m" (tmp));		\
		return tmp;					\
	}

DEFINE_SEL_READER(__sldt, "sldt %0")
DEFINE_SEL_READER(__str, "str %0")
DEFINE_SEL_READER(__readcs, "movw %%cs, %0")
DEFINE_SEL_READER(__readds, "movw %%ds, %0")
DEFINE_SEL_READER(__reades, "movw %%es, %0")
DEFINE_SEL_READER(__readfs, "movw %%fs, %0")
DEFINE_SEL_READER(__readgs, "movw %%gs, %0")
DEFINE_SEL_READER(__readss, "movw %%ss, %0")

#else
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

static inline bool test_bit(u64 bits, u64 bs)
{
	return (bits & bs) == bs;
}

/* avoid declared inside parameter list  */
struct vcpu;

extern bool __vmx_vminit(struct vcpu *);
extern void __vmx_entrypoint(void);
extern void __ept_violation(void);

#endif
