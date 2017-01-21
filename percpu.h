/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * DPC is short for Deferred Procedure Call.
 *
 * Per-processor macros
 * Public domain.
 *
 * This file handles per-processor callbacks, on Linux it uses SMP API
 * to send a call-function IPI to the specified processor(s), on
 * Windows, this uses the DPC API.
 *
 * The following macros are defined here:
 *	DEFINE_DPC(name, call, args...)
 *	Example:
 *		static DEFINE_DPC(do_something,
 *				  __vmx_vmcall,
 *				  ctx);
 *	ctx is an optional parameter that is passed to the function
 *	when called by the IPI, it does not have to be used.
 *
 * To call the DPC:
 *	CALL_DPC(name, args...)
 *	Example:
 *		CALL_DPC(do_something, &my_context);
 *	Which will call it on all online processors.
 *
 * To call the DPC on one CPU only:
 *	CALL_DPC_ON_CPU(cpu, name, fail, args...)
 *	Example:
 *		CALL_DPC_ON_CPU(cpu, do_something, goto out, ctx);
 *		out:
 *			... handle fail here ...
 *
 * To get the return value:
 *	DPC_RET():
 *		This macro returns a logical OR'd variable, basically the return
 *		value of the callback(s) OR'd.
 *	Note: the variable returned by this macro is per-file (a static variable), so
 *	      you might want to account for that also.
*/
#ifndef __PERCPU_H
#define __PERCPU_H

static int __g_dpc_logical_rval = 0;

#ifndef __linux__
NTKERNELAPI VOID KeGenericCallDpc(PKDEFERRED_ROUTINE Routine,
				  PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID SystemArgument2);

#define DEFINE_DPC(name, call, ...)	\
	VOID __percpu_##name(PRKDPC dpc, void *ctx, void *sys0, void *sys1)	\
	{									\
		UNREFERENCED_PARAMETER(dpc);					\
		__g_dpc_logical_rval |= (call) (__VA_ARGS__);			\
		KeSignalCallDpcSynchronize(sys1);				\
		KeSignalCallDpcDone(sys0);					\
	}

#define CALL_DPC(name, ...) do {						\
	__g_dpc_logical_rval = 0;						\
	KeGenericCallDpc(__percpu_##name, __VA_ARGS__);				\
} while (0)

#define CALL_DPC_ON_CPU(cpu, name, fail, ...) do {				\
	__g_dpc_logical_rval = 0;						\
	PROCESSOR_NUMBER proc_nr;						\
	KeGetProcessorNumberFromIndex((cpu), &proc_nr);				\
	PKDPC dpc = mm_alloc_pool(sizeof(*dpc));				\
	if (!dpc)								\
		fail;								\
	KeInitializeDpc(dpc, __percpu_##name, __VA_ARGS__);			\
	KeSetImportanceDpc(dpc, HighImportance);				\
	KeSetTargetProcessorDpcEx(dpc, &proc_nr);				\
	KeInsertQueueDpc(dpc, NULL, NULL);					\
} while (0)
#else
#define DEFINE_DPC(name, call, ...)						\
	void __percpu_##name(void *ctx)						\
	{									\
		__g_dpc_logical_rval |= (call) (__VA_ARGS__);			\
	}

#define CALL_DPC(name, ...) do {						\
	int cpu;								\
	__g_dpc_logical_rval = 0;						\
	for_each_online_cpu(cpu)						\
		smp_call_function_single(cpu, __percpu_##name, __VA_ARGS__, 1);	\
} while (0)

#define CALL_DPC_ON_CPU(cpu, name, fail, ...) do {				\
	__g_dpc_logical_rval = 0;						\
	smp_call_function_single(cpu, __percpu_##name, __VA_ARGS__, 1);		\
} while (0)
#endif

#define DPC_RET() 	__g_dpc_logical_rval
#endif
