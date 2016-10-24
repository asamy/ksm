# ksm

A really simple and lightweight x64 hypervisor written in C for Intel processors.

## Features

- IDT Shadowing
- EPT violation #VE (if not available natively, it will keep using VM-Exit instead)
- EPTP switching VMFUNC (if not available natively, it will be emulated using a VMCALL)

## Requirements

- An Intel processor
- Microsoft compiler (CL).  VS 2015 prefered, Others are not currently supported.

## Unsupported features (hardware, etc.)

- UEFI
- Intel TXT
- VT-x nesting (i.e. having a vm running inside it and not the other way around!)

## Debugging and/or testing

Since #VE and VMFUNC are now optional and will not be enabled unless the CPU support it, you can now test under VMs with
emulation for VMFUNC.

## Supported Kernels

All x64 NT kernels starting from the Windows 7 NT kernel.  It was mostly tested under Windows 8/8.1/10, but no reason not to support 7.

## Porting to other kernels (e.g. Linux or similar) guidelines

- Port `Makefile` and/or provide some project (e.g. `KDevelop` or similar).  Makefile is prefered
- Port `mm.h` functions (`mm_alloc_pool, mm_free_pool, __mm_free_pool`).  You'll need `__get_free_page` instead of `ExAllocatePool`.
- Port `acpi.c` (not really needed) for re-virtualization on S1-3 or S4 state (commenting it out is OK).
- Port `main.c` for some internal windows stuff, e.g. `DriverEntry`, etc.  Perhaps even rename to something like main_windows.c or similar.
- Port `page.c` for the hooking example (not required, but it's essential to demonstrate usage).
- Port `x64.asm` to inline assembly perhaps or some other GAS file, shouldn't be too difficult (MASM -> GAS/NASM, GAS prefered).
- Port intrinsic functions, should be easy, `__vmx_vmwrite, __vmx_vmread`, etc.  Just defining them should be OK (e.g.
														  in
														  vmx.h
														  or in
														  pure
														  assembly).

Hopefully didn't miss something important, but these are definitely the mains.

## Contributions

Contributions are really appreciated and can be submitted by one of the following:

- Patches (e-mail)
- Github pull requests
- git request-pull

It'd be appreciated if you use a separate branch for your submissions (other than master, that is).

## TODO / In consideration

- APIC virtualization (if nesting)
- MMIO (if nesting)
- UEFI support
- Intel TXT support
- Nesting support (shouldn't be too difficult, not mandatory.)
- Interrupt queueing (currently if an injection fails, it will just ignore it, should be simple).
- Cross-compiling Makefile
- Native-compiling Makefile
- GCC / CLang support (you can discard SEH aka `__try` and `__except` if required)

## Known bugs

1. BSOD on exit due to `ept_free_prealloc`, moreover, the reason is `BAD_POOL_CALLER`...  Only happens when:
	- An executable page is hooked
	- A hooked page gets called at least once.
2. BSOD on initial startup (rare) due to win32k, reason: `PAGE_FAULT_IN_NON_PAGED_AREA` (Windows 8.1/10 bug)

## Technical information

Note: If the processor does not support VMFUNC or #VE, they will be disabled and instead, emulated via VM-exit.

### IDT shadowing

- By enabling the descriptor table exiting bit in processor secondary control, we can easily establish this
- On initial startup, we allocate a completely new IDT base and copy the current one in use to it (also save the old
												   one)
- When a VM-exit occurs with an `EXIT_REASON_GDT_IDT_ACCESS`, we simply just give them the cached one (on sidt) or (on
														  lidt),
	we copy the new one's contents, discarding the hooked entries we know about, thus not letting them know about
	our stuff.

### #VE setup and handling

We use 3 EPT pointers, one for executable pages, one for readwrite pages, and last one for normal usage.  (see next
													   section)

- `vcpu.c`: in `setup_vmcs()` where we initially setup the VMCS fields, we then set the relevant fields (`VE_INFO_ADDRESS`,
													`EPTP_LIST_ADDRESS`,
													`VM_FUNCTION_CTL`) and enable
relevant bits VE and VMFUNC in secondary processor control.

- `x64.asm`: which contains the #VE handler (`__ept_violation`) then does the usual interrupt handling and then calls
	`__ept_handle_violation` (ept.c) where it actually does what it needs to do.
- `ept.c`: in `__ept_handle_violation` (#VE handler not VM-exit), usually the processor will do the #VE handler instead of
	the VM-exit route, but sometimes it won't do so if it's delivering another exception.  This is very rare.
- `ept.c`: while handling the violation via #VE, we switch vmfunc only when we detect that the faulting address is one of
	our interest (e.g. a hooked page), then we determine which EPTP we want and execute `VMFUNC` with that EPTP index.

### Hooking executable pages

#### Execute-only EPT for executable page hooking, RW for read or write access

	(... to avoid a lot of violations, we just mark the page as execute only and replace the _final_ page frame
	 number so that it just goes straight ahead to our trampoline)
Since we use 3 EPT pointers, and since the page needs to be read and written to sometimes (e.g. patchguard
											   verification),
      we also need to catch RW access to the page and then switch the EPTP appropriately according to
      the access.  In that case we switch over to `EPTP_RWHOOK` to allow RW access only!
	The third pointer is used for when we need to call the original function.

## Reporting bugs (or similar)

You can report bugs by using Github issues, please provide the following:

- System information (version including build number, CPU information perhaps codename too)
- The git tree hash
- Anything else you feel is relevant

If it's a crash, please provide the following:

- A minidump (C:\windows\minidump) or a memory dump (C:\windows\memory.dmp).  Former prefered.
- The compiled .sys and the .pdb file
- The Kernel executable if possible, e.g. ntoskrnl.exe from C:\Windows\System32

## Thanks to...

- Linux kernel (KVM)
- HyperPlatform

## License

GPL v2 firm, see LICENSE file.
