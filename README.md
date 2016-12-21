# ksm [![Build Status](https://travis-ci.org/asamy/ksm.svg?branch=master)](https://travis-ci.org/asamy/ksm) [![Build Status](https://ci.appveyor.com/api/projects/status/nb7u22qxjabauex5?svg=true)](https://ci.appveyor.com/project/asamy/ksm)

A really simple and lightweight x64 hypervisor written in C for Intel processors.

KSM does not stand for anything, it's a random name, it was first named kum,
but the name wasn't appropriate, and in fact, a discussion was on
[HackerNews](https://news.ycombinator.com/item?id=12089356) and they wouldn't
let me free until I renamed it.

KSM aims to be fully feature fledged and as general purpose as possible,
although there are absolutely no barriers, even extending it to be a
multi-purpose thing is perfeclty fine, e.g. a sandbox, etc.

Currently, KSM supports Windows and Linux kernels natively, and aims to support
macOS by 2017, if you want to port KSM see porting guidelines down below.

## Features

- IDT Shadowing
- EPT violation #VE (if not available natively, it will keep using VM-Exit instead)
- EPTP switching VMFUNC (if not available natively, it will be emulated using a VMCALL)
- APIC virtualization
- VMX Nesting

## Why not other hypervisors?

You may have already guessed from the `Features` part, if not, here are some reasons:

- Do not implement the new processor features KSM implements (VMFUNC, #VE, etc.)
- Are not simple enough to work with or understand
- Simply, just have messy code base or try too hard to implement endless C++ features that just make code ugly.
- Too big code base and do not have the same purpose (e.g. research or similar)

Such features for such purpose is really crucial, for my purpose, I wanted a quicker physical memory virtualization
technique that I can relay on.

![img](http://i.imgur.com/l3RhUIu.png)

## Requirements

- An Intel processor (with VT-x and EPT support)
- A working C compiler (GCC or CLang or Microsoft compiler (CL)).

## Unsupported features (hardware, etc.)

- UEFI
- Intel TXT (available on Linux only)

## Debugging and/or testing

Since #VE and VMFUNC are now optional and will not be enabled unless the CPU support it, you can now test under VMs with
emulation for VMFUNC.

### Live debugging under Windows

You may want to disable `SECONDARY_EXEC_DESC_TABLE_EXITING` in vcpu.c in secondary controls,otherwise it makes WinDBG go *maniac*.  I have not investigated the root cause, but it keeps loading GDT and LDT all the time, which is _insane_.

## Supported Kernels

- All x64 NT kernels starting from the Windows 7 NT kernel.  It was mostly tested under Windows 7/8/8.1/10.
- Linux kernel (tested under 3.16, 4.8.13 and mainline)

## Porting to other kernels guidelines

- Port `mm.h` functions (`mm_alloc_page`, `__mm_free_page`, `mm_alloc_pool`,
			 etc.)
- Port `acpi.c` (not really needed) for re-virtualization on S1-3 or S4 state (commenting it out is OK).
- Write module for initialization
- Port `print.c` for printing interface (Some kernels may not require it)
- Port `vmx.S` for the assembly based stuff, please use macros for calling conventions, etc.

Hopefully didn't miss something important, but these are definitely the mains.

## KSM needs your help to survive!

Contributions are really appreciated and can be submitted by one of the following:

- Patches (e-mail)
- Github pull requests
- git request-pull

It'd be appreciated if you use a separate branch for your submissions (other than master, that is).

The github issues is a great place to start, although implementing new features
is perfectly fine and very welcome, feel free to do whatever your little heart
wants.

## TODO / In development

- APIC virtualization (Partially implemented, needs testing)
- UEFI support
- Intel TXT support
- Nesting support (Some fixes needed and support for minor features)
- More documentation

## Building

### Building for Linux

Simply `make`.

### Building for Windows

#### Compiling under MinGW

Simply `make -f Makefile.windows C=1` (if cross compiling under Linux) or `mingw32-make -f Makefile.windows` (under native).  
Note: If you're compiling under native, you may need to adjust some paths
(specially DDK paths) in `Makefile.windows`

##### Makefile variables:

1. `C=1` - Prepare for cross-compiling.
2. `V=1` - Verbose output (the default, pass 0 for quiet.)

#### Compiling under MSVC

The solution under `ksm/` directory is a VS 2015 solution, you can use it to build, you'll
also need the Windows Driver Development Kit.

## Loading the driver

### On Linux
Loading:
- `sudo make load`  

Unloading:
- `sudo make unload`

Output:
- `sudo dmesg -wH`

### On Windows
In commandline as administrator:

1. `sc create ksm type= kernel binPath= C:\path\to\your\ksm.sys`
2. `sc start ksm`

Unloading:
- `sc stop ksm`

You can also use [kload](https://github.com/asamy/kload)  
Output can be seen via DebugView or WinDBG if live debugging.

## Some technical information

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

- `vmx.asm` (or `vmx.S` for GCC): which contains the `#VE` handler (`__ept_violation`) then does the usual interrupt handling and then calls
	`__ept_handle_violation` (`vcpu.c`) where it actually does what it needs to do.
- `vcpu.c`: in `__ept_handle_violation` (`#VE` handler *not* `VM-exit`), usually the processor will do the `#VE` handler instead of
	the VM-exit route, but sometimes it won't do so if it's delivering another exception.  This is very rare.
- `vcpu.c`: while handling the violation via `#VE`, we call `vmfunc` only when we detect that the faulting address is one of
	our interest (e.g. a hooked page), then we determine which `EPTP` we want and execute `VMFUNC` with that EPTP index.

### Hooking executable pages

#### Execute-only EPT for executable page hooking, RW for read or write access

	(... to avoid a lot of violations, we just mark the page as execute only and replace the _final_ page frame
	 number so that it just goes straight ahead to our trampoline)
Since we use 3 EPT pointers, and since the page needs to be read and written to sometimes (e.g. patchguard
											   verification),
      we also need to catch RW access to the page and then switch the EPTP appropriately according to
      the access.  In that case we switch over to `EPTP_RWHOOK` to allow RW access only!
	The third pointer is used for when we need to call the original function.  The third pointer
	has execute only access rights to the page with the sane page frame number.

## Enabling certain features / tests

You can define one or more of the following:

- `EPAGE_HOOK` - Enables executable page shadow hook
- `ENABLE_PML` - Enables Page Modification Log if supported.
- `EMULATE_VMFUNC` - Forces emulation of VMFUNC even if CPU supports it.
- `EPT_SUPPRESS_VE` - Force suppress VE bit in EPT.
- `ENABLE_ACPI` - Enable S1-3-S4 power state monitoring for re-virtualization
- `NESTED_VMX` - Enable experimental VT-x nesting
- `ENABLE_FILEPRINT` - Available only when `DBG` is defined.  Enables loggin to
disk (Windows only)
- `ENABLE_DBGPRINT` - Available only when `DBG` is defined.  Enables `DbgPrint`
log.  (Windows only)

## Reporting bugs (or similar)

You can report bugs using Github issues, please provide the following:

- System information (version including build number, CPU information perhaps codename too)
- The git tree hash
- Anything else you feel is relevant

If it's a crash, please provide the following:

### For Windows

- A minidump (C:\windows\minidump) or a memory dump (C:\windows\memory.dmp).  Former prefered.
- The compiled .sys and the .pdb/.dbg file
- The Kernel executable if possible, e.g. ntoskrnl.exe from C:\Windows\System32

### For Linux

- `ksmlinux.ko` and `ksmlinux.o`
- Stack dump from dmesg or kernel panic

## Thanks to...

- Linux kernel (KVM)
- HyperPlatform
- XEN

## License

GPL v2 firm, see LICENSE file.
