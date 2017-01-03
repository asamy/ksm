/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * DPC is a shortcut for Deferred Procedure Call.
 *
 * Per-processor macros
 * Public domain.
*/
#ifndef __PERCPU_H
#define __PERCPU_H

static int __g_dpc_logical_rval = 0;

#ifndef __linux__
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

#define DEFINE_DPC(name, call, ...)	\
	VOID __percpu_##name(PRKDPC dpc, void *ctx, void *sys0, void *sys1)	\
	{	\
		UNREFERENCED_PARAMETER(dpc);	\
		__g_dpc_logical_rval |= (call) (__VA_ARGS__);	\
		KeSignalCallDpcSynchronize(sys1);	\
		KeSignalCallDpcDone(sys0);	\
	}

#define CALL_DPC(name, ...) do {	\
	__g_dpc_logical_rval = 0;	\
	KeGenericCallDpc(__percpu_##name, __VA_ARGS__);	\
} while (0)
#else
#define DEFINE_DPC(name, call, ...)	\
	void __percpu_##name(void *ctx)	\
	{	\
		__g_dpc_logical_rval |= (call) (__VA_ARGS__);	\
	}
#define CALL_DPC(name, ...) do {		\
	int cpu;	\
	__g_dpc_logical_rval = 0;	\
	for_each_online_cpu(cpu)	\
		smp_call_function_single(cpu, __percpu_##name, __VA_ARGS__, 1);	\
} while (0)
#endif
#define DPC_RET() 	__g_dpc_logical_rval
#endif
