# ksm v1.4 [![BountySource](https://www.bountysource.com/badge/team?team_id=189129&style=raised)](https://www.bountysource.com/teams/ksm?utm_source=ksm&utm_medium=shield&utm_campaign=raised) [![Build Status](https://travis-ci.org/asamy/ksm.svg?branch=master)](https://travis-ci.org/asamy/ksm) [![Build Status](https://ci.appveyor.com/api/projects/status/nb7u22qxjabauex5?svg=true)](https://ci.appveyor.com/project/asamy/ksm)

A really simple and lightweight x64 hypervisor written in C for Intel processors.

KSM aims to be fully feature fledged and as general purpose as possible,
although there are absolutely no barriers, even extending it to be a
multi-purpose thing is perfeclty fine, e.g. a sandbox, etc.

Currently, KSM runs on Windows and Linux kernels natively, and aims to support
macOS by 2017, if you want to port KSM see porting guidelines down below.  Note
that the `master` branch may be unstable (bugs, unfinished features, etc.), so
you might want to stick with the releases for a captured stable state.

Unlike other hypervisors (e.g. KVM, XEN, etc.), KSM's purpose is not to run
other Operating Systems, instead, KSM can be used as an extra layer of
protection to the existing running OS.  This type of virtualization is usually
seen in Anti-viruses, or sandboxers or even Viruses.  KSM also supports
nesting, that means it can emulate other hardware-assisted virtualization tools
(VT-x) such as KVM or itself, or so, it's however an experimental feature and
is not recommended.

## Features

- IDT Shadowing
- EPT violation #VE (if not available natively, VM-exit path is taken)
- EPTP switching VMFUNC (if not available natively, it will be emulated using a VMCALL)
- APIC virtualization (Experimental, do not use)
- VMX Nesting (Experimental, do not use)

## Why not other hypervisors?

You may have already guessed from the `Features` part, if not, here are some reasons:

- Do not implement the new processor features KSM implements (VMFUNC, #VE, etc.)
- Are not simple enough to work with or understand
- Simply, just have messy code base or try too hard to implement endless C++ features that just make code ugly.
- Too big code base and do not have the same purpose (e.g. research or similar)

Such features for such purpose is really crucial, for my purpose, I wanted a quicker physical memory virtualization
technique that I can relay on.

## Requirements

- An Intel processor (with VT-x and EPT support)
- A working C compiler (GCC or Microsoft compiler aka CL are supported)

## Supported Kernels

- All x64 NT kernels starting from the Windows 7 NT kernel.  It was mostly tested under Windows 7/8/8.1/10.
- Linux kernel (tested under 3.16, 4.8.13 and mainline)

## TODO / In development

- APIC virtualization (Partially implemented, needs testing & fixes)
- TSC virtualization
- UEFI support
- Intel TXT support
- AMD-V with NPT support
- Nesting support (Some fixes needed and support for minor features)
- More documentation
- Finish writing tests
- Failsafe state (e.g. when an unexpected thing happens, turn off and restore
                  state to a valid one.)

See also Github issues.  Some of these features are unfortunately not
(fully) implemented due to lack of hardware (support) or similar.

## Some technical information

If any of them is confusing, please open an issue and I'll happily explain and
perhaps improve this inline-manual...

### Debugging and/or testing

Since #VE and VMFUNC are now optional and will not be enabled unless the CPU support it,
you can now test under VMs with emulation for VMFUNC.

#### Live debugging under Windows

You may want to disable `SECONDARY_EXEC_DESC_TABLE_EXITING` in vcpu.c in secondary controls,
otherwise it makes WinDBG go **maniac**.  I have not investigated the root cause, but it keeps
loading GDT and LDT all the time, which is _insane_.

### Initialization

The main initialization code is in `ksm.c` which manages all-cpus
{,de}initialization, however, `vcpu.c` is to handle per-cpu initialization and
is called from `ksm.c` on a high-level understanding, then `exit.c` handles
events from the guest kernel.

**Note**: there are more things that happen during this transition, but to simplify
things, only a few stuff is explained.

**Note**: Most `ksm` prefixed functions are either defined in `ksm.c` or `ksm.h`
or `main_KERNELNAME.c`, all of `vcpu` prefixed functions are defined in
`vcpu.c` and `exit.c`, `vmx` prefixed functions are mostly inline assembly
(vmx.h in that case) or compiler-intrinsics or defined in assembler.

This is the flow:

```
	driver entry (any process context) -> ksm_init()
	(later on or in another context):
		ksm_subvert() ->
			for each cpu call __ksm_init_cpu:
		__ksm_init_cpu:
			set feature control MSR appropriately
			set CR4.VMXE bit

			vcpu_create(vcpu) -> __vmx_vminit(vcpu) ->
				save guest state
				vcpu_run()

				vcpu_run(vcpu, stack_ptr, guest_start_point) ->
					...
					/* write important fields to VM Control
					   structure:  */
					vmcs_write()
					vmcs_write()
					....
					if not vmlaunch():
						print error
					else
						/* CPU already jumped to start
						   point  */
					endif
			guest_start_point:
				restore guest state (registers incl rflags, etc.)
				return to __ksm_init_cpu

		__ksm_init_cpu (contd.):
			if __vmx_vminit failed:
				throw error
				remove CR4.VMXE bit
				return error
			else
				return 0 /* succeeded  */
			endif
		ksm_subvert() (contd.):
			return whatever___ksm_init_cpu_returned
	...
```

During a guest event (e.g. CPUID execution, etc.), this is what happens:

```
	CPU:
		save guest state
		load host state (rsp, fs, gs, ...)
		jump to host RIP (__vmx_entrypoint)

	KSM:
		__vmx_entrypoint:
			/* Note: The guest registers are still untouched at
			   this point!  so we can save them and write to them
			   if needed.  */
			push guest registers
			if not vcpu_handle_exit(regs) then
				jump do_vmx_off
			else
				pop guest registers
				vmresume
				if fail:
					jump handle_fail
				endif
			endif

		do_vmx_off:
			pop guest registers
			vmxoff
			if fail:
				jump handle_fail
			endif

			/* Now we're off VMX root mode and preparing to return
			   to normal mode, aka no guest-host barrier.  */
			restore guest stack pointer
			set guest rflags	/* important to do this after
						   restoring the stack pointer
						   and not before, because this
						   may cause interrupts to be
						   re-enabled...  */
			jump to guest defined RIP	/* last guest RIP +
							   last instruction
							   length.  */

		handle_fail:
			push guest registers
			push guest flags
			vcpu_handle_fail()	/* should not return  */
		do_hlt:		/* incase vcpu_handle_fail() somehow
				   returned...  */
			hlt
			jump do_hlt

	CPU:
	/* Note: We assume all these came from us (the host, or root mode), in
	   the other case where these instructions are not executed in root
	   mode, the CPU will either:
		1) VM exit to root mode if it's inside non-root mode (i.e.
		virtualized)
		2) throw exception if non-root mode.
	*/
		if did_vmresume:	/* if vmresume was executed  */
			if not check_host_state_fields or
			   not check_guest_state_fields:
				set_eflags_to_indicate_failure
				advance_instruction_pointer
				return to caller
			endif

			/* check if some stuff need to be done on vm-entry
			   (e.g. MSR load or exceptions):  */
			if msr_entry_fields:
				load msrs
			endif
		
			save_host_state_fields (very unlikely to be updated...)
			load guest_state_fields 
			set instruction_pointer to guest_start /* defined by us
							  in that case
							  */
			if exception_queued:
				throw exception
			else:
				jump to guest_start
			endif
		elif did_vmxoff:	/* if vmxoff was executed  */
			if not do_sanity_checks:
				set_eflags_to_indicate_failure
				advance instruction_pointer
				return to caller
			endif

			turn off root mode (i.e. set VMXON pointer to none)
			set vmcs pointer to 0
			set_eflags_to_indicate_success
			advance instruction_pointer
			return to caller
		endif
```

### Controling processor events

You can probably tell from that that the execution is now split into 2 things and
that we pretty much "kicked" the kernel (Linux or Windows) out of the physical
CPU, and took over, and each time they execute something that we want to
monitor, the physical processor does the so-called "VM exit" which makes it
enter a "supervision" mode then we can decide what to do with that event, there
are some events that are forced to do a VM-exit ("unconditional vm-exit") such
as execution of CPUID, VMX instructions, etc, which we don't have control over,
so when the CPU encounters such instructions, it will exit to us and then we
can emulate the instruction.

To control which events do a VM-exit, the processor offers 3 main "VM control
structure" fields, which are (see vmx.h for a full list of controls):

1. Primary processor control (stuff like enabling MSR/IO controls, cr3-load-exiting,
   cr3-store-exiting, etc.)
2. Secondary processor control (which must be activated by setting a bit inside
   primary, and offers stuff like enabling Extended Page Tables, Virtual Processor ID (for cache control),
   and even descriptor table-exiting like when they load/store GDT/IDT/TR/LDT, etc.)
3. Pin based control (External interrupts, posted interrupts, preemption timer,
   virtual non-maskable interrupt).  This basically controls interrupt
delivery, the "External interrupts" bit means that the processor will exit each
time it's delivering an external interrupt (e.g. Mouse, keyboard, etc.  Things
					    that are attached to the Local
					    APIC basically, ...)

	Note: Those are the "main" controls, there are also other fields that
	can conditionally cause vm-exits.

Since there is no bits that controls cr0/cr4 stores/loads in those "main"
controls, the processor offers 4 fields that control access to those:

1. `CR0_READ_SHADOW` (If a bit is not set in this variable, then the guest kernel
   won't see it visible.)
2. `CR4_READ_SHADOW` (Same as CR0, we shadow the VMXE bit, so that they can't
   easily know that we have VMX mode on, and so that we can emulate VMX mode
   for them if needed.)
3. `CR0_GUEST_HOST_MASK` (If a bit is set in this variable, the processor causes
   a VM-exit when they try to set that specific bit in their CR0)
4. `CR4_GUEST_HOST_MASK` (Same as CR0, we set the VMXE bit here, so that we can
   know when they tried to set it and emulate VMX if needed.)

The following control fields are also useful:

1. `EXCEPTION_BITMAP` - The bit index is the exception vector in the IDT (say page
								 faults, if bit
								 14 is set,
								 then each time
								 there is a
								 page fault,
								 the processor
								 gets kicked
								 out of guest
								 mode and gives
								 us control.)
2. `MSR_BITMAP` - This is described in more detail in `ksm.c`, see
   `init_msr_bitmap`.  Controls when the processor does VM exits for an MSR
   read/write.
3. `IO_BITMAP_A` - I/O ports (low part from 0 up to 7FFF), controls when an
   in/out instruction for a specific port will cause a VM exit.
4. `IO_BITMAP_B` - I/O ports (high part from 8000 to FFFF), ^^^^.

There are also other control fields, but these are mainly not used.  The rest
of the fields are mostly guest and host setup (e.g. setting where the
					       guest/host entry point is,
					       etc.).
It's rather better if you look at `vcpu_run()` in vcpu.c, that way you can get
a "realistic" view of things.

### How we work with EPT

EPT (Extended Page Tables) also called SLAT (Second Level Address Translation)
is used to control guest address translation but on the physical level.

Without EPT, the processor normally goes through translating a virtual address
to its backing physical address, with EPT, the processor adds another level of
translation, which translates the physical address (now called "guest physical address"
					    or GPA) to "host physical address"
(HPA).

Normally, the base PML4 table is stored in CR3, which the processor uses to
translate a virtual address to it's backing physical address, EPT is very
similar, with a configured EPT pointer (EPTP) which also contains the PML4
table, the processor uses this table to translate the GPA to HPA.

Here's an example of what happens during both phases:

```c
#define MAX_PHYS	36				/* physical addr width
							   */
#define PAGE_SHIFT	12				/* bits 0:11 are the
							   offset.  */
#define PA_MASK		((1 << MAX_PHYS) - 1)
#define PAGE_PA_MASK	(PA_MASK << PAGE_SHIFT);	/* bits 12:47 of an
							   entry is the Page
							   physical address.
							 */
#define ENTRY_COUNT	512				/* per table  */
#define ENTRY_MASK	(ENTRY_COUNT - 1)
#define pdpt_index(a)	(a >> 39) & ENTRY_MASK		/* bits 38:30  */
#define pdt_index(a)	(a >> 30) & ENTRY_MASK		/* bits 29:21  */
#define pt_index(a)	(a >> 21) & ENTRY_MASK		/* bits 20:12  */
#define page_index(a)	(a >> 12) & ENTRY_MASK		/* bits 11:0  */

	/* First level:  Translate GVA to GPA:  */
	GVA = some_arbitrary_value;
	PML4 = VA_OF(CR3 & PAGE_PA_MASK);
	PDPT = VA_OF(PML4[pdpt_index(GVA)] & PAGE_PA_MASK);
	PDT = VA_OF(PDPT[pdt_index(GVA)] & PAGE_PA_MASK);
	PT = VA_OF(PDT[pt_index(GVA)] & PAGE_PA_MASK);
	PAGE = PT[page_index(GVA)];
	GPA = PAGE & PAGE_PA_MASK;

	/* We now have GPA, and we know it's valid!  (assume so)  */
	/* Second level: Translate GPA to HPA */
	EPTP = read_eptp_from_current_vmcs;
	PML4 = VA_OF(EPTP & PAGE_PA_MASK);
	PDPT = VA_OF(PML4[pdpt_index(GPA)] & PAGE_PA_MASK);
	PDT = VA_OF(PDPT[pdt_index(GPA)] & PAGE_PA_MASK);
	PT = VA_OF(PDT[pt_index(GPA)] & PAGE_PA_MASK);
	PAGE = PT[page_index(GPA)];
	HPA = PAGE & PAGE_PA_MASK;
```

Pretty much repeating ourselves, but this is basically what happens.  An
example for this kind of use is executable page hooking which is described in
more detail in `page.c` (also below).

Just like page faults, EPT has "EPT violation" and "EPT misconfig", in the
latter case, it can happen when an unsupported bit is set (e.g. a reserved bit
							   is set somewhere),
in the former case, it can happen when for example an access bit is not there
(e.g. trying to execute but there is no execute access given.)

The traditional EPT violation handling is via the VM exit path, but modern
processors (starting off Intel Broadwell) supports a new IDT exception
called "Virtualization Exceptions" and that is defined at vector 20 in the IDT.
When set and the relevant bits in VMCS are also set, the processor will
throw exceptions to that vector instead of causing a VM exit, but under certain
conditions it will take the vm-exit path instead, see notes below.

### Some notes

To simplify things, the following terms are used as an abbreviation:

1. Host - refers to the VMM (Virtual Machine Monitor) aka VMX root mode
2. Guest or Kernel - refers to the running guest kernel (i.e. Windows or Linux)

Some things need to be used with extra care especially inside Host as
this is a sensitive mode and things may go unexpected if used improperly.

- The timestamp counter does not _pause_ during entry to Host, so
things like APIC timer can fire on next guest entry (`vmresume`).
- Interrupts are disabled.  On entry to `__vmx_entrypoint`, the CPU had already
disabled interrupts.  So, addresses referenced inside root mode should be
physically contiguous, otherwise if you enable interrupts by yourself, you
might cause havoc if a preemption happens.
- Calling a Kernel function inside the Host can be dangerous, especially
because the Host stack is different, so any kind of stack probing
functions will most likely fail.
- Single stepping `vmresume` or `vmlaunch` is invaluable, the debugger will
never give you back control, for obvious reasons.  If you want that behavior,
      then rather set a breakpoint on whatever `vcpu->ip` is set to.
- Virtualization Exceptions (#VE) will not occur if:
	1. The processor is delivering another exception
	2. The `except_mask` inside `ve_except_info` is set to non-zero value.
- If the processor does not support Virtualization Exceptions, the VM exit path
will be taken instead (Note that the VM exit path is _always_ handled).
- If the processor does not support VMFUNC, it's emulated via VMCALL instead.

Some notes on Guest:

- VMFUNC does **not** have CPL checks, that means a user-space program can
execute it.
- The virtual processor ID (VPID) cannot be 0 since the Host already uses that
one, so we use the current processor number is + 1.  VPIDs are used to control
processor cache.

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

## Porting to other kernels guidelines

- Port `mm.h` functions (`mm_alloc_page`, `__mm_free_page`, `mm_alloc_pool`,
			 etc.)
- Port `resubv.c` (not really needed) for re-virtualization on S1-3 or S4 state (commenting it out is OK).
- Write module for initialization
- Port `print.c` for printing interface (Some kernels may not require it)
- Port `vmx.S` for the assembly based stuff, please use macros for calling conventions, etc.

Hopefully didn't miss something important, but these are definitely the mains.

## Porting to other x86 processors

Since some code is split oddly, and needs to be organized to fit logically
together, these files should be renamed/merged:

- exit.c and vcpu.c should be merged to make vmx.c

## KSM needs your help to survive!

Contributions are really appreciated and can be submitted by one of the following:

- Patches (e-mail)
- Github pull requests
- git request-pull

	The github issues is a great place to start, although implementing new features
	is perfectly fine and very welcome, feel free to do whatever your little heart
	wants.

	See also (TODO / In development) seciton in this README.

The following is _not_ required, but **prefered**:

1. Put your copyright on top of the file(s) you edit along with a tiny description
with your changes.  Something like:

```c
/*
   ...
   Copyright (C) 2016 Your Name <your_email@domain.com>
	- Added support for XXX
	- Fixed bug with YYY
   ...
 */
```

2. Format your git commit messages properly (A signed-off-by is good but
   **not** required, note: you can use `git commit --signoff` instead of writing
   manually.  See also Linux kernel contribution guidelines for more perks):
```
vmx: fix issue with arg

Write as much as you would like as needed or point to some issue, although
writing is prefered, or even comments in the code itself is much better.

Optional:
Signed-off-by: Your Name <your_email@domain.com>
```

### Setting up your git tree

For the sake of simplicity, we're going to use some names placeholders (which
									in
									reality
									you
									should
									replace
									with
									your
									own):

1. `LOCAL_BRANCH` - is your local branch you're going to be committing to (e.g.
   `my-changes`).
2. `REMOTE_BRANCH` - is the branch name you have in your remote repository (e.g.
   `pull-me`, can be the same as `LOCAL_BRANCH`).
3. `REMOTE_URL` - Your remote repository URL (e.g. https://github.com/XXX/ksm).

	Note: you do not have to have a remote repository, you can commit to
	your local copy, then just use patches, see below.
4. `USER_NAME` - Your github username

Clone the repository locally:

`git clone https://github.com/USER_NAME/ksm`

**Note**: replace USER_NAME with mine (asamy) if you're not going to use
pull-requests.

Switch to a new branch (**Optional but preferred**):

`git checkout -b LOCAL_BRANCH`

Setup remote (**Optional**: skip if you want to use the full URL each time):

`git remote add upstream https://github.com/asamy/ksm`

If there are changes in my tree that you want to get, then:

`git pull --rebase upstream master`

This will rebase my changes on top of your local tree.

	**Note**: If you skipped remote setup, then replace `upstream` with the
	URL.

	**Note**: You might want to switch to the master branch first to pull
	my changes there, then switch back to your branch, then merge them
	together later using `git merge --ff master` (`ff` is fast-forward,
						      which means it will not
						      generate a merge commit,
						      you can skip it).


If you have local changes, `--rebase` will stop and ask you to commit, you can
do this without comitting:

`git stash && git pull --rebase upstream master && git stash pop`

What this does is 1) stashes your changes, 2) pulls my changes and prepares to
rebase your stashed changes on top of mine, 3) pops the stashed changes on
top, if there any conflicts, then it will let you know and you should fix them.

Then commit your changes:

```
git add ...
git add ...
git commit --signoff -m "commit message"
```

#### Submitting your changes

If you're going to use patches, then simply:

`git format-patch HEAD~X`

Where X is the number of commits to create patches from, can be ommitted to
take HEAD (i.e. most recent) commit only, e.g.:

`git format-patch HEAD~`

(You can use commit hashes instead, too.)

You can then use the patch file(s) as an attachment and e-mail them manually, or
you can use `git send-email` to do it for you.

##### Using pull requests

You have 2 options (if using 1st, then skip the rest):

1. If you're using github fork, you can just use the github pull request
   interface.
2. If you're going to use git request-pull follow.

##### Using git-request-pull

(Skip this if you're using Github pull requests.)

Usage:

`git request-pull START_COMMIT REPOSITORY_URL END_COMMIT`

First publish your changes:

`git push origin REMOTE_BRANCH`

To summarize a branch changes:

`git request-pull abcd https://github.com/USER_NAME/ksm HEAD`

Which will summarize changes from commit `abcd` to `HEAD` of which you can then
e-mail me that summary.

You can also use:

`git request-pull master https://github.com/USER_NAME/ksm
LOCAL_BRANCH:REMOTE_BRANCH`

Which will summarize changes from the local master branch (Which should contain
							   my changes, i.e. my
							   tree) to your
changes.

`REMOTE_BRANCH` can be omitted if same as `LOCAL_BRANCH`.
You can also specify a tag of your choice, in that case, use tag names instead
of commit hashes/branch names.

## Enabling certain features / tests

You can define one or more of the following:

- `EPAGE_HOOK` - Enables executable page shadow hook
- `ENABLE_PML` - Enables Page Modification Log if supported.
- `EMULATE_VMFUNC` - Forces emulation of VMFUNC even if CPU supports it.
- `EPT_SUPPRESS_VE` - Force suppress VE bit in EPT.
- `ENABLE_RESUBV` - Enable S1-3-S4 power state monitoring for re-virtualization
- `NESTED_VMX` - Enable experimental VT-x nesting
- `ENABLE_FILEPRINT` - Available on Windows only.  Enables loggin to
disk
- `ENABLE_DBGPRINT` - Available on Windows only.  Enables `DbgPrint`
log.
- `VCPU_TRACER_LOG` - Outputs a useless message on some VM-Exit handlers, this
can be replaced with something more useful such as performance measurements,
    etc.  See `ksm.h` for more information.

## Building

### Building for Linux

Install kernel headers:

- Debian/Ubuntu: `[sudo] apt-get install linux-headers-$(uname -r)`
- ArchLinux: `[sudo] pacman -S linux-headers`
- Fedora: `[sudo] yum install kernel-devel kernel-headers`

Then `make`.

### Building for Windows

#### Compiling under MinGW

**Warning**: The MinGW build is known to be unstable under Windows 10, so it's
not recommended, rather use the VS project to compile for Windows.

##### Makefile variables:

You can pass one or more of the following variables to your `make` command:

- `WINVER=0x0602` - Explicility specify windows version to build for.
- `C=1` - Prepare for cross-compiling.
- `V=1` - Verbose output (the default, pass 0 for quiet.)
- `BIN_DIR=arg` - Generate binary and symbols to this directory
- `OBJ_DIR=arg` - Generate object files to this directory
- `DEP_DIR=arg` - Generate dependency files to this directory
- `CROSS_INC=arg` - Path to include directory if they reside in a special place
- `CROSS_LIB=arg` - Path to library directory if they reside in a special place
- `CROSS_BUILD=arg` - Prefix to toolchain binaries (e.g.
						    `x86-_64-w64-mingw32-XXX`)
- `PREPEND=arg` - Prepend something to the compiler/linker executable (e.g. if
								       this is
								       "c" and
								       compiler
								       is "gcc"
								       then
								       full
								       command
								       is going
								       to be
								       "cgcc")
- `CEXTRA=arg` - Print something out after compiling a C file.
- `AEXTRA=arg` - Print something out after compiling an Assembler file.
- `LEXTRA=arg` - Print something out after linking

You may need to adjust the windows version you're compiling for, in that case
adjust `WINVER` inside the Makefile manually or pass it through commandline:

	make -f Makefile.windows C=1 WINVER=0x0602

##### Cross under Linux

Install the following packages:

- Debian/Ubuntu: `[sudo] apt-get install gcc-mingw-w64-x86-64
binutils-mingw-w64-x86-64`
- ArchLinux: `[sudo] pacman -S mingw-w64-gcc`
- Fedora: `[sudo] yum install mingw64-gcc`

Then `make -f Makefile.windows C=1`

##### Under Native

Natively, you'll want to adjust (or pass in command line) DDK paths, e.g.:

`mingw32-make -f Makefile.windows CROSS_INC=/path/to/include/ddk`

Or, simply just edit Makefile.windows manually.  Also make sure to adjust your
environment variables (PATH) to point to the right `bin/` directory where the
compiler, etc lie.

#### Compiling under MSVC

The solution under `ksm/` directory is a VS 2015 solution, you can use it to build, you'll
also need the Windows Driver Development Kit.

**NOTE**:  You need to adjust the Windows version you are targetting via the
project properities, go to Driver Settings -> General -> Target OS Version.

To build from VS command line, simply cd to where `ksm` is and:

`msbuild ksm\ksm.sln`

Or:

`msbuild ksm\ksm\ksm.vcxproj`

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
Output can be seen via DebugView or WinDBG if live debugging (You might want to
							      execute `ed
							      Kd_DEFAULT_Mask
							      8`).

**Note for Windows 10**: DebugView seems to be having problems starting a 2nd
time there, to workaround this, rename it's driver
C:\windows\system32\drivers\Dbgv.sys to something else, then start it again.

## Reporting bugs (or similar)

You can report bugs using Github issues, there is an Issue Template to help you
fill things as needed.

## References

- Linux kernel (KVM)
- HyperPlatform
- XEN

## License

GPL v2 firm, see LICENSE file.  Note that some code is thirdparty, respective
licenses and/or copyright should be there, if you think it's not, please let me
know.  Most of the code is GPL'd, though...

