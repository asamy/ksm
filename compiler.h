/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Public domain.
*/
#ifndef __COMPILER_H
#define __COMPILER_H

#ifdef DBG
#ifdef __linux__
#define dbgbreak()	(void)0		//__asm __volatile("int $3")
#else
#define dbgbreak() do {		\
	if (KD_DEBUGGER_ENABLED && !KD_DEBUGGER_NOT_PRESENT)	\
		__debugbreak();		\
} while (0)
#endif
#else
#define dbgbreak()	(void)0
#endif

#define break_if(cond)	do {	\
	if (!!(cond))		\
		dbgbreak();	\
} while (0)

#ifndef __linux__
/* Windows definitions  */
#define BUG_ON(cond)	do {	\
	if (!!(cond))		\
		__ud2();	\
} while (0)

/* Don't expose this to the assembler, it won't understand it.  */
#ifndef __ASSEMBLY__
/* Long names  */
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long int uint32_t;
typedef unsigned long long uint64_t;

typedef signed char sint8_t;
typedef signed short sint16_t;
typedef signed long int sint32_t;
typedef signed long long sint64_t;

/* Short names  */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef sint8_t s8;
typedef sint16_t s16;
typedef sint32_t s32;
typedef sint64_t s64;

#ifndef _UINTPTR_T_DEFINED
typedef unsigned long long uintptr_t;
#define _UINTPTR_T_DEFINED
#endif

#ifndef _INTPTR_T_DEFINED
typedef signed long long intptr_t;
#define _INTPTR_T_DEFINED
#endif

#ifndef _bool_true_false_are_defined
#define bool	_Bool
#define true	1
#define false	0
#define _bool_true_false_are_defined
#endif

/* Avoid NT retardism  */
#define container_of(address, type, field)	CONTAINING_RECORD(address, type, field)
/* OTOH - MSVC does not have typeof.  Hack it.  */
#define container_off_var(var, member)			\
	((const char *)&(var)->member - (const char *)(var))

#ifndef UM
#include "list.h"

#define spinlock_t		KSPIN_LOCK
#define spin_lock_init		KeInitializeSpinLock
#define spin_lock(s) \
	KLOCK_QUEUE_HANDLE q;	\
	KeAcquireInStackQueuedSpinLock((s), &q)
#define spin_unlock(s)	\
	KeReleaseInStackQueuedSpinLock(&(q))
#define spin_lock_irqsave(s,f)		spin_lock((s));		(void)f
#define spin_unlock_irqrestore(s,f)	spin_unlock((s));	(void)f

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(PEPROCESS process);
#endif
#endif

#ifdef _MSC_VER
/* MSVC specific definitions  */
/* Disable annoying warnings  */
#pragma warning(disable:4115)		/* 'type' : named type definition in parentheses  */
#pragma warning(disable:4242)		/* 'identifier' : conversion from 'type1' to 'type2', possible loss of data*/
#pragma warning(disable:4244)		/* 'conversion' conversion from 'type1' to 'type2', possible loss of data  */
#pragma warning(disable:4201)		/* nonstandard extension used : nameless struct/union  */
#pragma warning(disable:4311)		/* 'variable' : pointer truncation from 'type' to 'type'  */
#pragma warning(disable:4214)		/* nonstandard extension used : bit field types other than int  */
#pragma warning(disable:4133)		/* 'type' : incompatible types - from 'type1' to 'type2'  */
#pragma warning(disable:4146)		/* unary minus operator applied to unsigned type, result still unsigned  */
#pragma warning(disable:4366)		/* The result of the unary 'operator' operator may be unaligned  */
#pragma warning(disable:4702)		/* unreachable code  */
#pragma warning(disable:4100)		/* 'identifier' : unreferenced formal parameter  */
#pragma warning(disable:4200)		/* nonstandard extension used : zero-sized array in struct/union  */
#pragma warning(disable:4098)		/* 'function' : void function returning a value  */
#pragma warning(disable:4152)		/* non standard extension, function/data ptr conversion in expression  */
#pragma warning(disable:4204)		/* nonstandard extension used : non-constant aggregate initializer  */
#pragma warning(disable:4189)		/* 'identifier' : local variable is initialized but not referenced  */
#pragma warning(disable:4706)		/* assignment within conditional expression  */
#pragma warning(disable:4221)		/* nonstandard extension used : 'identifier' : cannot be initialized using address of automatic variable  */
#pragma warning(disable:4054)		/*  'conversion' : from function pointer 'type1' to data pointer 'type2'  */
#pragma warning(disable:4057)		/* 'function' : 'unsigned int *' differs in indirection to slightly different base types from 'u32 *'  */
#pragma warning(disable:4245)		/* 'initializing': conversion from 'int' to 'u8', signed/unsigned mismatch  */

#define __align(alignment)	__declspec(align(alignment))
#define __packed
#else
/* GCC (Windows) specific definitions  */
#define _In_
#define _In_opt_
#define __align(alignment)	__attribute__((__aligned__(alignment)))
#ifndef __forceinline
#define __forceinline		__attribute__((always_inline)) inline
#endif
#define __packed		__attribute__((__packed__))
#include <ntstatus.h>

#define STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR	0xC035003C
#define STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE	0xC0350071
#define STATUS_HV_FEATURE_UNAVAILABLE			0xC035001E
#define STATUS_HV_ACCESS_DENIED				0xC0350006
#define STATUS_HV_NOT_PRESENT				0xC0351000
#endif

#if defined(ENABLE_DBGPRINT) || defined(ENABLE_FILEPRINT)
#define ENABLE_PRINT
#endif
#define ERR_NOTH 		STATUS_HV_NOT_PRESENT
#define ERR_CPUID		STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR
#define ERR_BUSY		STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE
#define ERR_FEAT		STATUS_HV_FEATURE_UNAVAILABLE
#define ERR_UNSUP		STATUS_NOT_SUPPORTED
#define ERR_DENIED		STATUS_HV_ACCESS_DENIED
#define ERR_NOMEM		STATUS_NO_MEMORY
#define ERR_EXCEPT		GetExceptionCode()
#define ERR_RANGE		STATUS_BUFFER_OVERFLOW
#else
/* Linux definitions  */
#ifndef __ASSEMBLY__
#include <stdbool.h>
#endif
#include <asm-generic/errno-base.h>

#define list_node		list_head

#define __align(alignment)	__attribute__((__aligned__(alignment)))
#define KERNEL_STACK_SIZE	(6 << PAGE_SHIFT)

#define ERR_NOTH 		-ENOENT
#define ERR_CPUID		-EOPNOTSUPP
#define ERR_BUSY		-EBUSY
#define ERR_FEAT		-ENOENT
#define ERR_UNSUP		-EOPNOTSUPP
#define ERR_DENIED		-EACCES
#define ERR_NOMEM		-ENOMEM
#define ERR_EXCEPT		-EINVAL
#define ERR_RANGE		-ERANGE
#endif

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#endif
