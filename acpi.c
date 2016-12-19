/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * Public domain
*/
#ifdef ENABLE_ACPI
#include "ksm.h"

static void power_callback(PDEV_EXT ctx, void *arg0, void *arg1)
{
	if (arg0 != (void *)PO_CB_SYSTEM_STATE_LOCK)
		return;

	if (!arg1)
		ksm_unsubvert();
	else
		ksm_subvert();
}

NTSTATUS register_power_callback(PDEV_EXT ext)
{
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING name;
	NTSTATUS status;

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

void deregister_power_callback(PDEV_EXT ext)
{
	if (ext->CbRegistration)
		ExUnregisterCallback(ext->CbRegistration);

	if (ext->CbObject)
		ObDereferenceObject(ext->CbObject);
}
#endif
