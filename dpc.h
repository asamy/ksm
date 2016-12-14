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
#ifndef __KERNEL_DPC_H
#define __KERNEL_DPC_H

NTKERNELAPI
#ifndef __GNUC__
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
#endif
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

NTKERNELAPI
#ifndef __GNUC__
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
#endif
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

NTKERNELAPI
#ifndef __GNUC__
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
#endif
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

static NTSTATUS __g_dpc_logical_rval = 0;
#define STATIC_DEFINE_DPC(name, call, ...)	\
	static VOID __percpu_##name(PRKDPC dpc, void *ctx, void *sys0, void *sys1)	\
	{	\
		UNREFERENCED_PARAMETER(dpc);	\
		__g_dpc_logical_rval |= (call) (__VA_ARGS__);	\
		KeSignalCallDpcSynchronize(sys1);	\
		KeSignalCallDpcDone(sys0);	\
	}	\

#define STATIC_CALL_DPC(name, ...) do {	\
	__g_dpc_logical_rval = 0;	\
	KeGenericCallDpc(__percpu_##name, __VA_ARGS__);	\
} while (0)
#define STATIC_DPC_RET() 	__g_dpc_logical_rval

#endif
