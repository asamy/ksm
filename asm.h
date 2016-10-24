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

extern u8 __invvpid(u32 type, invvpid_t *i);
extern u8 __invept(u32 type, invept_t *i);
extern void __ept_violation(void);

static inline u8 __invept_all(void)
{
	return __invept(VMX_EPT_EXTENT_GLOBAL, &(invept_t) { 0, 0 });
}

static inline u8 __invept_gpa(u64 ptr, u64 gpa)
{
	return __invept(VMX_EPT_EXTENT_CONTEXT, &(invept_t) {
		.ptr = ptr,
		.gpa = gpa,
	});
}

static inline u8 __invvpid_all(void)
{
	return __invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, &(invvpid_t) { 0, 0, 0 });
}

static inline u8 __invvpid_single(u16 vpid)
{
	return __invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = 0,
	});
}

static inline u8 __invvpid_no_global(u16 vpid)
{
	return __invvpid(VMX_VPID_EXTEND_ALL_GLOBAL, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = 0
	});
}

static inline u8 __invvpid_addr(u16 vpid, u64 gva)
{
	return __invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = gva
	});
}

static inline bool test_bit(u64 bits, u64 bs)
{
	return (bits & bs) == bs;
}

static inline u64 vmcs_read(u64 what)
{
	u64 x;
	__vmx_vmread(what, &x);

	return x;
}

static inline u32 vmcs_read32(u64 what)
{
	return (u32)vmcs_read(what);
}

static inline u16 vmcs_read16(u64 what)
{
	return (u16)vmcs_read32(what);
}

extern bool __vmx_vminit(struct vcpu *);
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
