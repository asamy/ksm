; Copyright (c) 2015, 2016 tandasat. All rights reserved.
;	Original initialization code
; Copyright (C) 2016, 2017 asamy
;	improvements and added support for IDT #VE handling,
;	and optimized some operations
;
; This file is specific to Windows, it only compiles with MASM and thus should
; only be used with the VS project.
;
; For GCC (or general AT&T aka GAS) assembly, you should look at vmx.S and various
; inlined assembly in x86.h/vmx.h
EXTERN vcpu_run : PROC
EXTERN vcpu_handle_exit : PROC
EXTERN vcpu_handle_fail : PROC
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
; RSP is read from VMCS.
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
	sub	rsp, 8	; placeholder
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

TRAP_SAVE_GPR MACRO
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
ENDM

; cleans up stack from TRAP_SAVE_GP.
TRAP_REST_GPR MACRO
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

; General IDT trap handler (entry)
;	assumes:
;		1) There is an error code on the stack
;		2) NO_SWAP_LABEL is provided in case the trap is a kernel mode trap.
; Note: This does not save XMM registers, you need to do that with TRAP_SAVE_GP_XMM.
;
; Saves non-volatile registers on the frame pointer and jumps to NO_SWAP_LABEL if no
; GS swapping required (MSR_IA32_KERNEL_GS_BASE <-> MSR_IA32_GS_BASE), otherwise does
; swapgs and that's it.
;
; See __ept_violation below on how this is used.
TRAP_ENTER MACRO	NO_SWAP_LABEL, NO_ERROR_CODE
	IFNB <NO_ERROR_CODE>
		sub	rsp, 8
	ENDIF

	; align stack then save general purpose registers.
	TRAP_SAVE_GPR

	; see if we're coming from usermode, if so, swap gs.
	mov	ax, word ptr [rbp + KFRAME_CS]
	and	al, 1
	mov	[rbp + KFRAME_RPL], al
	jz	&NO_SWAP_LABEL&

	; ok we're coming from usermode, swap to kernel gs.
	swapgs

&NO_SWAP_LABEL&:
	; clear direction flag
	cld

	; save XMM
	TRAP_SAVE_XMM
ENDM

TRAP_EXIT MACRO		NO_SWAP_LABEL
	; see if we're coming from usermode, if so, swap back gs
	test	byte ptr [rbp + KFRAME_RPL], 1
	jz	&NO_SWAP_LABEL&

	; ok we're coming from usermode
	TRAP_REST_XMM
	TRAP_REST_GPR
	swapgs
	iretq

&NO_SWAP_LABEL&:
	TRAP_REST_XMM
	TRAP_REST_GPR
	iretq
ENDM

.CODE

; Returns 0 on success, -1 on failure
__vmx_vminit PROC
	pushfq
	PUSHAQ			; -8 * 16

	; rcx contains vcpu
	mov	rdx, rsp	; SP
	mov	r8, do_resume	; IP after success

	sub	rsp, 20h
	call	vcpu_run
	add	rsp, 20h

	; if we get here, we failed
	POPAQ
	popfq

	mov	eax, -1
	ret

do_resume:
	POPAQ
	popfq

	xor	eax, eax
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
    
	sub	rsp, 20h
	call	vcpu_handle_exit
	add	rsp, 20h

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
	jna	error

	; Give them their stack pointer
	mov	rsp, rdx

	push	rax
	popfq			; eflags to indicate success

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

__reades PROC
	mov	ax, es
	ret
__reades ENDP

__readcs PROC
	mov	ax, cs
	ret
__readcs ENDP

__readss PROC
	mov	ax, ss
	ret
__readss ENDP

__readds PROC
	mov	ax, ds
	ret
__readds ENDP

__readfs PROC
	mov	ax, fs
	ret
__readfs ENDP

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
	invept	rcx, oword ptr [rdx]
	setna 	al
	ret
__invept ENDP

__invvpid PROC
	invvpid	rcx, oword ptr [rdx]
	setna 	al
	ret
__invvpid ENDP

__ept_violation PROC
	; #VE handler, standard interrupt handling then
	; calls C handler aka __ept_handle_violation, see ept.c
	TRAP_ENTER ept_no_swap, 1

	mov	rcx, [rbp + KFRAME_CS]
	mov	rdx, [rbp + KFRAME_IP]

	sub	rsp, 20h
	call	__ept_handle_violation
	add	rsp, 20h

	TRAP_EXIT	ept_ret_no_swap
__ept_violation ENDP

PURGE PUSHAQ
PURGE POPAQ
PURGE TRAP_ENTER
PURGE TRAP_EXIT
PURGE TRAP_SAVE_GPR
PURGE TRAP_REST_GPR
PURGE TRAP_SAVE_XMM
PURGE TRAP_REST_XMM
END
