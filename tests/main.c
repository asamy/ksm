#include <ntddk.h>

#include "../compiler.h"
#include "export.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	int ret = 0;
	DbgPrint("Running tests\n");

	ret |= run_allgood();
	ret |= run_fail_entry();
	ret |= run_go_vmx();
	ret |= run_ept();

	/* Just return failure anyway  */
	DbgPrint("Done running all tests: %d\n", ret);
	return STATUS_UNSUCCESSFUL;
}
