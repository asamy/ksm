#include "vcpu.h"
#include "acpi.h"

static void power_callback(void *ctx, void *arg0, void *arg1)
{
	if (arg0 != (void *)PO_CB_SYSTEM_STATE_LOCK)
		return;

	VCPU_DEBUG("power: %d\n", arg1);
	if (arg1 == (void *)0)
		ksm_exit();
	else
		ksm_init();
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

	ext->CbRegistration = ExRegisterCallback(ext->CbObject, power_callback, ext);
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
