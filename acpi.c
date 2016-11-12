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
#ifdef ENABLE_ACPI
#include "ksm.h"

static void power_callback(PDEV_EXT ctx, void *arg0, void *arg1)
{
	if (arg0 != (void *)PO_CB_SYSTEM_STATE_LOCK)
		return;

	if (!arg1)
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
