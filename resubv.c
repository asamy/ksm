/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * Public domain
*/
#ifdef ENABLE_RESUBV
#ifdef __linux__
#include <linux/syscore_ops.h>
#else
#include <ntddk.h>
#endif

#include "ksm.h"
#include "compiler.h"

#ifdef __linux__
static void ksm_resume(void)
{
	KSM_DEBUG("in resume: %d\n", ksm_subvert(ksm));
}

static int ksm_suspend(void)
{
	KSM_DEBUG("in suspend: %d\n", ksm_unsubvert(ksm));
	return 0;
}

static struct syscore_ops syscore_ops = {
	.resume = ksm_resume,
	.suspend = ksm_suspend,
};

int register_power_callback(void)
{
	register_syscore_ops(&syscore_ops);
	return 0;
}

void unregister_power_callback(void)
{
	unregister_syscore_ops(&syscore_ops);
}
#else
typedef struct _DEV_EXT {
	void *CbRegistration;
	void *CbObject;
} DEV_EXT, *PDEV_EXT;
static DEV_EXT g_dev_ext;

static void power_callback(PDEV_EXT ctx, void *arg0, void *arg1)
{
	if (arg0 != (void *)PO_CB_SYSTEM_STATE_LOCK)
		return;

	if (arg1 == (void *)0)
		ksm_unsubvert(ksm);
	else if (arg0 == (void *)1)
		ksm_subvert(ksm);
}

int register_power_callback(void)
{
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING name;
	NTSTATUS status;
	PDEV_EXT ext = &g_dev_ext;

	RtlInitUnicodeString(&name, L"\\Callback\\PowerState");
	InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ExCreateCallback(&ext->CbObject, &obj, FALSE, TRUE);
	if (!NT_SUCCESS(status))
		return status;

	ext->CbRegistration = ExRegisterCallback(ext->CbObject,
						 (PCALLBACK_FUNCTION)power_callback,
						 ext);
	if (!ext->CbRegistration) {
		ObDereferenceObject(ext->CbObject);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

void unregister_power_callback(void)
{
	PDEV_EXT ext = &g_dev_ext;
	if (ext->CbRegistration)
		ExUnregisterCallback(ext->CbRegistration);

	if (ext->CbObject)
		ObDereferenceObject(ext->CbObject);
}
#endif
#endif
