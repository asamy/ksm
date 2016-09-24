; Copyright (c) 2015-2016, tandasat. All rights reserved .  Original initialization code
; Copyright (C) 2015-2016, asamy, improvements and added support for IDT #VE handling, and optimized some operations
EXTERN vcpu_handle_exit : PROC
EXTERN vcpu_handle_fail : PROC
EXTERN vcpu_dump_regs : PROC
EXTERN __ept_handle_violation : PROC

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
	mov	rcx, rsp
	mov	rdx, rsp
	add	rdx, 8*17
    
	sub	rsp, 28h
	call	vcpu_dump_regs
	add	rsp, 28h
    
	POPAQ
	popfq
ENDM

.CODE

__vmx_vminit PROC
	pushfq
	PUSHAQ			; -8 * 16
	
	mov	rax, rcx	; vcpu_init pointer
	mov	rcx, rdx	; vcpu
	mov	rdx, rsp	; SP
	mov	r8, do_resume	; IP after success

	sub	rsp, 20h
	call	rax		; func(rsp, do_resume, param)
	add	rsp, 20h

	; if we get here, we failed
	POPAQ
	popfq
	xor	rax, rax
	ret

do_resume:
	POPAQ
	popfq

	sub	rsp, 8
	ASM_DUMP_REGISTERS
	add	rsp, 8

	mov	rax, 1
	ret
__vmx_vminit ENDP

__vmx_entrypoint PROC
	PUSHAQ
	mov	rcx, rsp
    
	sub	rsp, 20h
	call	vcpu_handle_exit
	add	rsp, 20h

	test	al, al
	jz	exit

	POPAQ
	vmresume
	jmp	error

exit:
	POPAQ
	vmxoff
	jz	error
	jc	error
	push	rax
	popfq
	mov	rsp, rdx
	push	rcx
	ret

error:
	pushfq
	PUSHAQ
	mov	rcx, rsp
    
	sub	rsp, 28h
	call	vcpu_handle_fail
	add	rsp, 28h
	ret						; not reached
__vmx_entrypoint ENDP

__vmx_vmcall PROC
	vmcall
	setz	al
	setc	al
	ret
__vmx_vmcall ENDP

__vmx_vmfunc PROC
	mov	eax, ecx
	mov	ecx, edx
	dd	90d4010fh	; vmfunc nop
	setz	al
	setc	al
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
	setz	al
	setc	al
	ret
__invept ENDP

__invvpid PROC
	invvpid	ecx, oword ptr [rdx]
	setz	al
	setc	al
	ret
__invvpid ENDP

__ept_violation PROC
	; stack:
	;		ss (+40)
	;		rsp (+32)
	;		rflags (+16)
	;		cs (+8)	
	;		ip (+0)			<-- rsp

	sub	rsp, 8			; dummy error code (See struct ve_except_info of vcpu)
	push	rbp			; save rbp
	sub	rsp, 158h		; squeeze it to make shit fit
	lea	rbp, [rsp + 80h]

	; stack:
	;		cs	(+170h)
	;		ip	(+168h)
	;		ec	(+160h)
	;		rbp	(+158h)			<- original rbp saved
	;		frame	(+080h)			<- actual rbp pointing here
	;		data	(+000h)			<- rsp

	; rbp frame:
	;		-58h = RPL
	;		-54h = mxcsr
	;		-50h = rax
	;		-48h = rcx
	;		-40h = rdx
	;		-38h = r8
	;		-30h = r9
	;		-28h = r10
	;		-20h = r11
	;		-10h = xmm0
	;		+ 0 = xmm1
	;		+10h = xmm2
	;		+20h = xmm3
	;		+30h = xmm4
	;		+40h = xmm5

	mov	[rbp - 50h], rax
	mov	[rbp - 48h], rcx 
	mov	[rbp - 40h], rdx
	mov	[rbp - 38h], r8
	mov	[rbp - 30h], r9
	mov	[rbp - 28h], r10
	mov	[rbp - 20h], r11

	; save RPL and check if it's coming from user mode...
	mov	ax, word ptr[rbp + 0F0h]
	and	al, 1
	mov	[rbp - 58h], al
	jz	no_swap
	swapgs

no_swap:
	cld
	stmxcsr	dword ptr [rbp - 54h]
	ldmxcsr	dword ptr gs:[180h]
	movaps	[rbp - 10h], xmm0
	movaps	[rbp + 0h], xmm1
	movaps	[rbp + 10h], xmm2
	movaps	[rbp + 20h], xmm3
	movaps	[rbp + 30h], xmm4
	movaps	[rbp + 40h], xmm5

	mov	rcx, [rbp + 0F0h]			; cs
	mov	rdx, [rbp + 0E8h]			; rip
	call	__ept_handle_violation

	test	byte ptr [rbp - 58h], 1
	jz	intr_ret_noswap

	ldmxcsr	dword ptr[rbp - 54h]
	movaps	xmm0, xmmword ptr[rbp - 10h]
	movaps	xmm1, xmmword ptr[rbp + 0h]
	movaps	xmm2, xmmword ptr[rbp + 10h]
	movaps	xmm3, xmmword ptr[rbp + 20h]
	movaps	xmm4, xmmword ptr[rbp + 30h]
	movaps	xmm5, xmmword ptr[rbp + 40h]
	mov	r11, [rbp - 20h]
	mov	r10, [rbp - 28h]
	mov	r9,  [rbp - 30h]
	mov	r8,  [rbp - 38h]
	mov	rdx, [rbp - 40h]
	mov	rcx, [rbp - 48h] 
	mov	rax, [rbp - 50h]
	mov	rsp, rbp
	mov	rbp, [rbp + 0D8h]
	add	rsp, 0E8h
	swapgs
	iretq

intr_ret_noswap:
	ldmxcsr	dword ptr[rbp - 54h]
	movaps	xmm0, xmmword ptr[rbp - 10h]
	movaps	xmm1, xmmword ptr[rbp + 0h]
	movaps	xmm2, xmmword ptr[rbp + 10h]
	movaps	xmm3, xmmword ptr[rbp + 20h]
	movaps	xmm4, xmmword ptr[rbp + 30h]
	movaps	xmm5, xmmword ptr[rbp + 40h]
	mov	r11, [rbp - 20h]
	mov	r10, [rbp - 28h]
	mov	r9,  [rbp - 30h]
	mov	r8,  [rbp - 38h]
	mov	rdx, [rbp - 40h]
	mov	rcx, [rbp - 48h] 
	mov	rax, [rbp - 50h]
	mov	rsp, rbp
	mov	rbp, [rbp + 0D8h]
	add	rsp, 0E8h
	iretq
__ept_violation ENDP

PURGE PUSHAQ
PURGE POPAQ
PURGE ASM_DUMP_REGISTERS
END
