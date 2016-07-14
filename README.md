# ksm

A really simple and lightweight x64 hypervisor written in C for Windows for Intel processors.

## Features

- IDT Shadowing
- EPT violation handling via #VE
- EPTP switching VMFUNC and a small hooking example included

## Brief descriptions of the flow

#### IDT shadowing

- By enabling the descriptor table exiting bit in processor secondary control, we can easily establish this
- On initial startup, we allocate a completely new IDT base and copy the current one in use to it (also save the old
												   one)
- When a VM-exit occurs with an EXIT_REASON_GDT_IDT_ACCESS, we simply just give them the cached one (on sidt) or (on
														  lidt),
	we copy the new one's contents, discarding the hooked entries we know about, thus not letting them know about
	our stuff.


#### #VE handling and hook idea

We use 3 EPT pointers, one for executable pages, one for readwrite pages, and last one for normal usage.  (see next
													   section)

- vcpu.c: in setup_vmcs() where we initially setup the VMCS fields, we then set the relevant fields (VE_INFO_ADDRESS,
													EPTP_LIST_ADDRESS,
													...) and enable
relevant bits (VE, VMFUNC, and EPTP Switching CTL in VM_FUNCTION_CTL).

- x64.asm: which contains the #VE handler (__ept_violation) then does the usual interrupt handling and then calls
	__ept_handle_violation (ept.c) where it actually does what it needs to do.
- ept.c: in __ept_handle_violation (#VE handler not VM-exit), usually the processor will do the #VE handler instead of
	the VM-exit way, but sometimes it won't do so if it's delivering another exception.  This is very rare.
- ept.c: while handling the violation via #VE, we switch vmfunc only when we detect that the faulting address is one of
	our interest (e.g. a hooked page), then we determine which EPTP we want and do vmfunc with that EPTP index.

##### Execute-only EPT for executable page hooking, RW for read or write access

	(... to avoid a lot of violations, we just mark the page as execute only and replace the _final_ page frame
	 number so that it just goes straight ahead to our trampoline)
Since we use 3 EPT pointers, and since the page needs to be read and written to sometimes (e.g. patchguard
											   verification),
      we also need to catch RW access to the page and then switch the EPTP appropriately according to
      the access, if it's a read access, then we need to give it the original page pfn, otherwise
      give it the normal one as no harm will be done anyway.  Do also note that we always mark the page
      as "RW" because the processor does not support the write-only bit.


## Thanks to...

- Linux kernel (KVM)
- HyperPlatform

If you think I hacked some of your code and I missed you, please send me an e-mail.

## License

MIT (The MIT License)
