; Copyright (c) 2015-2016, tandasat. All rights reserved.  Original initialization code
; Copyright (C) 2015-2016, asamy, improvements and added support for IDT #VE handling, and optimized some operations
EXTERN vcpu_init : PROC
EXTERN vcpu_handle_exit : PROC
EXTERN vcpu_handle_fail : PROC
EXTERN vcpu_dump_regs : PROC
EXTERN __ept_handle_violation : PROC

KFRAME_RPL  = -56h
KFRAME_CSR  = -54h
KFRAME_RAX  = -50h
KFRAME_RCX  = -48h
KFRAME_RDX  = -40h
KFRAME_R8   = -38h
KFRAME_R9   = -30h
KFRAME_R10  = -28h
KFRAME_R11  = -20h
KFRAME_XMM0 = -10h
KFRAME_XMM1 = +0h
KFRAME_XMM2 = +10h
KFRAME_XMM3 = +20h
KFRAME_XMM4 = +30h
KFRAME_XMM5 = +40h
KFRAME_SS   = +108h
KFRAME_RSP  = +100h
KFRAME_FLGS = +0F8h
KFRAME_CS   = +0F0h
KFRAME_EC   = +0E0h
KFRAME_IP   = +0E8h

.CONST

; Saves all general purpose registers to the stack
PUSHAQ MACRO
	push	r15
	push	r14
	push	r13
	push	r12
	push	r11
	push	r10
	push	r9
	push	r8
	push	rdi
	push	rsi
	push	rbp
	push	-1
	push	rbx
	push	rdx
	push	rcx
	push	rax
ENDM

POPAQ MACRO
	pop	rax
	pop	rcx
	pop	rdx
	pop	rbx
	add	rsp, 8
	pop	rbp
	pop	rsi
	pop	rdi
	pop	r8
	pop	r9
	pop	r10
	pop	r11
	pop	r12
	pop	r13
	pop	r14
	pop	r15
ENDM

ASM_DUMP_REGISTERS MACRO
	pushfq
	PUSHAQ                      ; -8 * 16

    
	POPAQ
	popfq
ENDM

; General IDT trap handler (entry)
;	assumes:
;		1) There is an error code on the stack
;		2) NO_SWAP_LABEL is provided in case the trap is a kernel mode trap.
; Note: This does not save XMM registers, you need to do that with TRAP_SAVE_XMM.
;
; Saves non-volatile registers on the frame pointer and jumps to NO_SWAP_LABEL if no
; GS swapping required (MSR_IA32_KERNEL_GS_BASE <-> MSR_IA32_GS_BASE), otherwise does
; swapgs and that's it.
TRAP_ENTER MACRO	NO_SWAP_LABEL
	; stack:
	;		ss (+40)
	;		rsp (+32)
	;		rflags (+24)
	;		cs (+16)
	;		ip (+8)	
	;		ec (+0)			<-- rsp

	push	rbp			; save rbp
	sub	rsp, 158h		; squeeze it to make shit fit
	lea	rbp, [rsp + 80h]

	; stack:
	;		ss	(+188h)
	;		rsp	(+180h)
	;		rflags  (+178h)
	;		cs	(+170h)
	;		ip	(+168h)
	;		ec	(+160h)
	;		rbp	(+158h)			<- original rbp saved
	;		frame	(+080h)			<- actual rbp pointing here
	;		data	(+000h)			<- rsp
	mov	[rbp + KFRAME_RAX], rax
	mov	[rbp + KFRAME_RCX], rcx 
	mov	[rbp + KFRAME_RDX], rdx
	mov	[rbp + KFRAME_R8], r8
	mov	[rbp + KFRAME_R9], r9
	mov	[rbp + KFRAME_R10], r10
	mov	[rbp + KFRAME_R11], r11

	mov	ax, word ptr [rbp + KFRAME_CS]
	and	al, 1
	mov	[rbp + KFRAME_RPL], al
	jz	NO_SWAP_LABEL
	swapgs
ENDM

; cleans up stack from TRAP_ENTER.
TRAP_EXIT MACRO
	mov	r11, [rbp + KFRAME_R11]
	mov	r10, [rbp + KFRAME_R10]
	mov	r9,  [rbp + KFRAME_R9]
	mov	r8,  [rbp + KFRAME_R8]
	mov	rdx, [rbp + KFRAME_RDX]
	mov	rcx, [rbp + KFRAME_RCX] 
	mov	rax, [rbp + KFRAME_RAX]

	mov	rsp, rbp
	mov	rbp, qword ptr [rbp + 0D8h]
	add	rsp, 0E8h
ENDM

; cleans up XMM registers and CSR
TRAP_REST_XMM MACRO
	ldmxcsr	dword ptr[rbp + KFRAME_CSR]
	movaps	xmm0, xmmword ptr[rbp + KFRAME_XMM0]
	movaps	xmm1, xmmword ptr[rbp + KFRAME_XMM1]
	movaps	xmm2, xmmword ptr[rbp + KFRAME_XMM2]
	movaps	xmm3, xmmword ptr[rbp + KFRAME_XMM3]
	movaps	xmm4, xmmword ptr[rbp + KFRAME_XMM4]
	movaps	xmm5, xmmword ptr[rbp + KFRAME_XMM5]
ENDM

; save XMM registers and CSR
TRAP_SAVE_XMM MACRO
	stmxcsr	dword ptr [rbp + KFRAME_CSR]
	ldmxcsr	dword ptr gs:[180h]
	movaps	[rbp + KFRAME_XMM0], xmm0
	movaps	[rbp + KFRAME_XMM1], xmm1
	movaps	[rbp + KFRAME_XMM2], xmm2
	movaps	[rbp + KFRAME_XMM3], xmm3
	movaps	[rbp + KFRAME_XMM4], xmm4
	movaps	[rbp + KFRAME_XMM5], xmm5
ENDM

.CODE

__vmx_vminit PROC
	pushfq
	PUSHAQ			; -8 * 16

	; rcx contains vcpu
	mov	rdx, rsp	; SP
	mov	r8, do_resume	; IP after success

	sub	rsp, 20h
	call	vcpu_init
	add	rsp, 20h

	; if we get here, we failed
	POPAQ
	popfq
	xor	al, al
	ret

do_resume:
	mov	rcx, rsp
	mov	rdx, rsp
	add	rdx, 8*17
    
	sub	rsp, 28h
	call	vcpu_dump_regs
	add	rsp, 28h

	POPAQ
	popfq
	mov	al, 1
	ret
__vmx_vminit ENDP

__vmx_entrypoint PROC
	; This is the VM entry point, aka root mode.
	; This saves guest registers (as they are untouched for now)
	; and restores control to guest if all good, otherwise, fail.
	;
	; All interrupts are disabled at this point.
	PUSHAQ
	mov	rcx, rsp
    
	sub	rsp, 48h
	call	vcpu_handle_exit
	add	rsp, 48h

	test	al, al
	jz	exit

	POPAQ
	vmresume		; give them control
	jmp	error		; something went wrong.

exit:
	; at this point:
	;	rax = eflags
	;	rdx = rsp
	;	rcx = return address	(aka RIP prior to this call plus instruction length)
	POPAQ
	vmxoff
	ja	2f

	push	rax
	popfq			; eflags to indicate success

	mov	rsp, rdx	; stack pointer
	push	rcx		; return address (rip + instr len)
	ret

error:
	; otherwise, we are rip.
	pushfq
	PUSHAQ
	mov	rcx, rsp
    
	sub	rsp, 28h
	call	vcpu_handle_fail
	add	rsp, 28h

do_hlt:
	hlt						; not reached
	jmp	do_hlt
__vmx_entrypoint ENDP

__vmx_vmcall PROC
	; assumes:
	;	rcx = hypercall
	;	rdx = data
	vmcall
	setna 	al
	ret
__vmx_vmcall ENDP

; it's unsafe to call this function directly, so unless
; you're 100% sure the CPU supports it, use vcpu_vmfunc instead.
__vmx_vmfunc PROC
	; assumes:
	;	ecx = EPTP index
	;	edx = function
	mov	eax, edx
	db	0fh, 01h, 0d4h
	setna 	al
	ret
__vmx_vmfunc ENDP

__lgdt PROC
	lgdt	fword ptr [rcx]
	ret
__lgdt ENDP

__sgdt PROC
	sgdt	[rcx]
	ret
__sgdt ENDP

__lldt PROC
	lldt	cx
	ret
__lldt ENDP

__sldt PROC
	sldt	ax
	ret
__sldt ENDP

__ltr PROC
	ltr	cx
	ret
__ltr ENDP

__str PROC
	str	ax
	ret
__str ENDP

__writees PROC
	mov	es, cx
	ret
__writees ENDP

__reades PROC
	mov	ax, es
	ret
__reades ENDP

__writecs PROC
	mov	cs, cx
	ret
__writecs ENDP

__readcs PROC
	mov	ax, cs
	ret
__readcs ENDP

__writess PROC
	mov	ss, cx
	ret
__writess ENDP

__readss PROC
	mov	ax, ss
	ret
__readss ENDP

__writeds PROC
	mov	ds, cx
	ret
__writeds ENDP

__readds PROC
	mov	ax, ds
	ret
__readds ENDP

__writefs PROC
	mov	fs, cx
	ret
__writefs ENDP

__readfs PROC
	mov	ax, fs
	ret
__readfs ENDP

__writegs PROC
	mov	gs, cx
	ret
__writegs ENDP

__readgs PROC
	mov	ax, gs
	ret
__readgs ENDP

__lar PROC
	lar	rax, rcx
	ret
__lar ENDP

__writecr2 PROC
	mov	cr2, rcx
	ret
__writecr2 ENDP

__invd PROC
	invd
	ret
__invd ENDP

__invept PROC
	invept	ecx, oword ptr [rdx]
	setna 	al
	ret
__invept ENDP

__invvpid PROC
	invvpid	ecx, oword ptr [rdx]
	setna 	al
	ret
__invvpid ENDP

__ept_violation PROC
	; #VE handler, standard interrupt handling then
	; calls C handler aka __ept_handle_violation, see ept.c
	sub	rsp, 8
	TRAP_ENTER(ept_no_swap)

ept_no_swap:
	cld
	TRAP_SAVE_XMM

	mov	rcx, [rbp + KFRAME_CS]
	mov	rdx, [rbp + KFRAME_IP]
	sub	rsp, 48h
	call	__ept_handle_violation
	add	rsp, 48h

	test	byte ptr [rbp + KFRAME_RPL], 1
	jz	ept_ret_noswap

	TRAP_REST_XMM
	TRAP_EXIT
	swapgs
	iretq

ept_ret_noswap:
	TRAP_REST_XMM
	TRAP_EXIT
	iretq
__ept_violation ENDP

PURGE PUSHAQ
PURGE POPAQ
PURGE ASM_DUMP_REGISTERS
END
