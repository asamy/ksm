EXTERN init_vcpu:PROC
EXTERN handle_exit:PROC
EXTERN handle_fail:PROC

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

.CODE

vmx_init PROC
	pushfq
	PUSHAQ			; -8 * 16

	; rcx contains vcpu
	mov	rdx, rsp	; SP
	mov	r8, do_resume	; IP after success

	sub	rsp, 20h
	call	init_vcpu
	add	rsp, 20h

	; if we get here, we failed
	POPAQ
	popfq
	xor	al, al
	ret

do_resume:
	POPAQ
	popfq
	mov	al, 1
	ret
vmx_init ENDP

vmx_ep PROC
	; This is the VM entry point, aka root mode.
	; This saves guest registers (as they are untouched for now)
	; and restores control to guest if all good, otherwise, fail.
	;
	; All interrupts are disabled at this point.
	PUSHAQ
	mov	rcx, rsp
    
	sub	rsp, 48h
	call	handle_exit
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
	jna	error

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
	call	handle_fail
	add	rsp, 28h

do_hlt:
	hlt						; not reached
	jmp	do_hlt
vmx_ep ENDP

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
	invept	ecx, oword ptr [rdx]
	setna 	al
	ret
__invept ENDP

__invvpid PROC
	invvpid	ecx, oword ptr [rdx]
	setna 	al
	ret
__invvpid ENDP

PURGE PUSHAQ
PURGE POPAQ
END
