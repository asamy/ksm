Technical Documentation and Specification
=========================================

	This simple manual explains some parts of KSM, and also describes how we use 
	multiple EPT pointers and Virtualization Exception (#VE) handling.

Debugging and/or testing
------------------------

	Since #VE and VMFUNC are now optional and will not be enabled unless the CPU support it,
	you can now test under VMs with emulation for VMFUNC.

Live debugging under Windows
----------------------------

	You may want to disable `SECONDARY_EXEC_DESC_TABLE_EXITING` in vcpu.c in secondary controls,
	otherwise it makes WinDBG go **maniac**.  I have not investigated the root cause, but it keeps
	loading GDT and LDT all the time, which is _insane_.

Initialization
--------------

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

.. code-block::

	driver entry (any process context) -> ksm_init()
	(later on or in another context):

	ksm_subvert() ->
		for each cpu:
			call __ksm_init_cpu

	__ksm_init_cpu():
		set feature control MSR appropriately
		call vcpu_init(current cpu ptr)

		vcpu_init(vcpu) ->
			allocate needed stuff
			return

	__ksm_init_cpu (contd.):
		call __vmx_vminit(current cpu ptr)

		__vmx_vminit(vcpu) ->
			save guest state
			call vcpu_run(vcpu, rsp, guest_start_pointer)

			vcpu_run(vcpu, stack_ptr, guest_start_point) ->
				enter vmx root mode (load vmxon pointer)
				load vmcs
				clear vmcs launch state
				set cr0 fixed bits
				set cr4 fixed bits (VMXE)
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

		__vmx_vminit(vcpu) (contd.)
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


	During a guest event (e.g. CPUID execution, etc.), this is what happens:


.. code-block::

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
			call vcpu_handle_fail()	/* should not return  */
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

Controling processor events
---------------------------

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
	   virtual non-maskable interrupt).  This basically controls interrupt delivery, the "External interrupts" bit means that the processor will exit each time it's delivering an external interrupt (e.g. Mouse, keyboard, etc.  Things that are attached to the Local APIC basically, ...)

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

	1. `EXCEPTION_BITMAP` - The bit index is the exception vector in the IDT
	2. `MSR_BITMAP` - This is described in more detail in `ksm.c`, see
	   `init_msr_bitmap`.  Controls when the processor does VM exits for an MSR
	   read/write.
	3. `IO_BITMAP_A` - I/O ports (low part from 0 up to 7FFF), controls when an
	   in/out instruction for a specific port will cause a VM exit.
	4. `IO_BITMAP_B` - I/O ports (high part from 8000 to FFFF), ^^^^.

	There are also other control fields, but these are mainly not used.  The rest
	of the fields are mostly guest and host setup.
	It's rather better if you look at `vcpu_run()` in vcpu.c, that way you can get
	a "realistic" view of things.

How we work with EPT
--------------------

	EPT (Extended Page Tables) also called SLAT (Second Level Address Translation)
	is used to control guest address translation but on the physical level.

	Without EPT, the processor normally goes through translating a virtual address
	to its backing physical address, with EPT, the processor adds another level of
	translation, which translates the physical address (now called "guest physical address" or GPA) to "host physical address" (HPA).

	Normally, the base PML4 table is stored in CR3, which the processor uses to
	translate a virtual address to it's backing physical address, EPT is very
	similar, with a configured EPT pointer (EPTP) which also contains the PML4
	table, the processor uses this table to translate the GPA to HPA.

	Here's an example of what happens during both phases:

	.. code-block::

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
		gva = some_arbitrary_value;
		pml4 = VA_OF(CR3 & PAGE_PA_MASK);
		pdpt = VA_OF(pml4[pdpt_index(gva)] & PAGE_PA_MASK);
		pdt = VA_OF(pdpt[pdt_index(gva)] & PAGE_PA_MASK);
		pt = VA_OF(pdt[pt_index(gva)] & PAGE_PA_MASK);
		page = pt[page_index(gva)];
		gpa = page & PAGE_PA_MASK;

		/* We now have GPA, and we know it's valid!  (assume so)  */
		/* Second level: Translate GPA to HPA */
		eptp = read_eptp_from_current_vmcs;
		pml4 = VA_OF(eptp & PAGE_PA_MASK);
		pdpt = VA_OF(pml4[pdpt_index(gpa)] & PAGE_PA_MASK);
		pdt = VA_OF(pdpt[pdt_index(gpa)] & PAGE_PA_MASK);
		pt = VA_OF(pdt[pt_index(gpa)] & PAGE_PA_MASK);
		page = pt[page_index(gpa)];
		hpa = page & PAGE_PA_MASK;

	Pretty much repeating ourselves, but this is basically what happens.  An
	example for this kind of use is executable page hooking which is described in
	more detail in `page.c` (also below).

	Just like page faults, EPT has "EPT violation" and "EPT misconfig", in the
	latter case, it can happen when an unsupported bit is set (e.g. a reserved bit is set somewhere),
	in the former case, it can happen when for example an access bit is not there
	(e.g. trying to execute but there is no execute access given.)

	The traditional EPT violation handling is via the VM exit path, but modern
	processors (starting off Intel Broadwell) supports a new IDT exception
	called "Virtualization Exceptions" and that is defined at vector 20 in the IDT.
	When set and the relevant bits in VMCS are also set, the processor will
	throw exceptions to that vector instead of causing a VM exit, but under certain
	conditions it will take the vm-exit path instead, see notes below.

Some notes
----------

	To simplify things, the following terms are used as an abbreviation:

	1. Host - refers to the VMM (Virtual Machine Monitor) aka VMX root mode
	2. Guest or Kernel - refers to the running guest kernel (i.e. Windows or Linux)

	Some things need to be used with extra care especially inside Host as
	this is a sensitive mode and things may go unexpected if used improperly.

	- The timestamp counter does not _pause_ during entry to Host, so things like APIC timer can fire on next guest entry (`vmresume`).
	- Interrupts are disabled.  On entry to `__vmx_entrypoint`, the CPU had already disabled interrupts ("host eflags").  So, addresses referenced inside root mode should be physically contiguous, otherwise if you enable interrupts by yourself, you might cause havoc if a preemption happens.
	- Calling a Kernel function inside the Host can be dangerous, especially because the Host stack is different, so any kind of stack probing functions will most likely fail.
	- Single stepping `vmresume` or `vmlaunch` is invaluable, the debugger will never give you back control, for obvious reasons.  If you want that behavior, then rather set a breakpoint on whatever `vcpu->ip` is set to.
	- If the processor does not support Virtualization Exceptions, the VM exit path will be taken instead (Note that the VM exit path is _always_ handled).
	- If the processor does not support VMFUNC, it's emulated via VMCALL instead.
	- Virtualization Exceptions (#VE) will not occur if:
		1. The processor is delivering another exception
		2. The `except_mask` inside `ve_except_info` is set to non-zero value.

	Some notes on Guest:

	- VMFUNC does **not** have CPL checks, that means a user-space program can execute it.
	- The virtual processor ID (VPID) cannot be 0 since the Host already uses that one, so we use the current processor number is + 1.  VPIDs are used to control processor cache.

IDT shadowing
-------------

	- By enabling the descriptor table exiting bit in processor secondary control, we can easily establish this
	- On initial startup, we allocate a completely new IDT base and copy the current one in use to it (also save the old one)
	- When a VM-exit occurs with an `EXIT_REASON_GDT_IDT_ACCESS`, we simply just give them the cached one (on sidt) (or on lidt), we copy the new one's contents, discarding the hooked entries we know about, thus not letting them know about our stuff.

#VE setup and handling
----------------------

	- `vcpu.c`: in `setup_vmcs()` where we initially setup the VMCS fields, we then set the relevant fields (`VE_INFO_ADDRESS`, `EPTP_LIST_ADDRESS`, `VM_FUNCTION_CTL`) and enable relevant bits VE and VMFUNC in secondary processor control.
	- `vmx.asm` (or `vmx.S` for GCC): which contains the `#VE` handler (`__ept_violation`) then does the usual interrupt handling and then calls the C handler `__ept_handle_violation` (`vcpu.c`).
	- `vcpu.c`: in `__ept_handle_violation` (`#VE` handler *not* `VM-exit`), usually the processor will do the `#VE` handler instead of the VM-exit route, but sometimes it won't do so if it's delivering another exception.  This is very rare.
	- `vcpu.c`: while handling the violation via `#VE`, we call `vmfunc` only when we detect that the faulting address is one of
		our interest (e.g. a hooked page), then we determine which `EPTP` we want and execute `VMFUNC` with that EPTP index.

Hooking executable pages
-------------------------

Execute-only EPT for executable page hooking, RW for read or write access
-------------------------------------------------------------------------

	To avoid a lot of violations, we just mark the page as execute only and
	replace the _final_ page frame number so that it just goes straight ahead to our trampoline
	Since we use 3 EPT pointers, and since the page needs to be read and written to sometimes
	(e.g. patchguard verification), we also need to catch RW access to the page and then switch
	the EPTP appropriately according to the access.  In that case we switch over to `EPTP_RWHOOK`
	to allow RW access only! The third pointer is used for when we need to call the original function.
	The third pointer has execute only access rights to the page with the sane page frame number.

Porting to other kernels guidelines
-----------------------------------

	- Port `mm.h` functions (`mm_alloc_page`, `__mm_free_page`, `mm_alloc_pool`, etc.)
	- Port `resubv.c` (not really needed) for re-virtualization on S1-3 or S4 state (commenting it out is OK).
	- Port `hotplug.c` for cpu hotplug callbacks
	- Write module for initialization
	- Port `print.c` for printing interface (Some kernels may not require it)
	- Port `vmx.S` for the assembly based stuff, please use macros for calling conventions, etc.

	Hopefully didn't miss something important, but these are definitely the mains.
