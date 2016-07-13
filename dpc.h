#ifndef __KERNEL_DPC_H
#define __KERNEL_DPC_H

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
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
#define STATIC_DPC_RET()	__g_dpc_logical_rval

#endif
