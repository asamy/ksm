#ifndef __TYPES_H
#define __TYPES_H

#pragma warning(disable:4115)
#pragma warning(disable:4242)
#pragma warning(disable:4244)
#pragma warning(disable:4201)
#pragma warning(disable:4311)
#pragma warning(disable:4214)
#pragma warning(disable:4133)
#pragma warning(disable:4146)
#pragma warning(disable:4366)
#pragma warning(disable:4702)
#pragma warning(disable:4100)
#pragma warning(disable:4200)
#pragma warning(disable:4098)
#pragma warning(disable:4152)
#pragma warning(disable:4204)
#pragma warning(disable:4189)
#pragma warning(disable:4706)
#pragma warning(disable:4221)
#pragma warning(disable:4054)

/* Long names  */
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef signed char sint8_t;
typedef signed short sint16_t;
typedef signed int sint32_t;
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

#ifndef _bool_true_false_defined
#define bool	_Bool
#define true	1
#define false	0
#define _bool_true_false_defined
#endif

#ifndef _UINTPTR_T_DEFINED
typedef unsigned long long uintptr_t;
#define _UINTPTR_T_DEFINED
#endif

#ifndef _INTPTR_T_DEFINED
typedef signed long long intptr_t;
#define _INTPTR_T_DEFINED
#endif

#define PRIu16	"h"
#define PRIu32	"l"
#define PRIu64	"ll"

#define PRIh16	"hx"
#define PRIH16	"04hx"
#define PRIh32	"lx"
#define PRIH32	"08lx"
#define PRIh64	"llx"
#define PRIH64	"016llx"

#endif
