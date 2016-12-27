/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * Assembly stuff for GCC (AT&T aka GAS) only.  See vmx.asm for MASM.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifdef __linux__
/* Arguments  */
#define REG_A1		%rdi
#define REG_A2		%rsi
#define REG_A3		%rdx
#define REG_A4		%rcx
/* Volatile registers (caller-saved)  */
#define REG_V1		%rdx
#define REG_V2		%rcx
#define REG_V3		%rax
#define REG_V4		%r8
#define REG_V5		%r9
#define REG_V6		%r10
#define REG_V7		%r11
#define REG_V8		%rdi
#define REG_V9		%rsi
#else
/* Arguments  */
#define REG_A1		%rcx
#define REG_A2		%rdx
#define REG_A3		%r8
#define REG_A4		%r9
/* Volatile registers (caller-saved)  */
#define REG_V1		%rax
#define REG_V2		%rcx
#define REG_V3		%rdx
#define REG_V4		%r8
#define REG_V5		%r9
#define REG_V6		%r10
#define REG_V7		%r11
#endif

.macro PUSH_REGS
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%r11
	pushq	%r10
	pushq	%r9
	pushq	%r8
	pushq	%rdi
	pushq	%rsi
	pushq	%rbp
	pushq	$-1
	pushq	%rbx
	pushq	%rdx
	pushq	%rcx
	pushq	%rax
.endm

.macro POP_REGS
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rbx
	addq	$8, %rsp
	popq	%rbp
	popq	%rsi
	popq	%rdi
	popq	%r8
	popq	%r9
	popq	%r10
	popq	%r11
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
.endm

#define KFRAME_RPL	-0x66
#define KFRAME_CSR	-0x64
#define KFRAME_V1	-0x60
#define KFRAME_V2	-0x58
#define KFRAME_V3	-0x50
#define KFRAME_V4	-0x48
#define KFRAME_V5	-0x40
#define KFRAME_V6	-0x38
#define KFRAME_V7	-0x30
#define KFRAME_V8	-0x28
#define KFRAME_V9	-0x20
#define KFRAME_XMM0	-0x10
#define KFRAME_XMM1	0x00
#define KFRAME_XMM2	0x10
#define KFRAME_XMM3	0x20
#define KFRAME_XMM4	0x30
#define KFRAME_XMM5	0x40
#define KFRAME_SS	0x108
#define KFRAME_RSP	0x100
#define KFRAME_FLGS	0x0F8
#define KFRAME_CS	0x0F0
#define KFRAME_EC	0x0E0
#define KFRAME_IP	0x0E8

.macro TRAP_ENTER no_swap
	pushq	%rbp
	subq	$0x158, %rsp
	leaq	0x80(%rsp), %rbp
	movq	REG_V1, KFRAME_V1(%rbp)
	movq	REG_V2, KFRAME_V2(%rbp)
	movq	REG_V3, KFRAME_V3(%rbp)
	movq	REG_V4, KFRAME_V4(%rbp)
	movq	REG_V5, KFRAME_V5(%rbp)
	movq	REG_V6, KFRAME_V6(%rbp)
	movq	REG_V7, KFRAME_V7(%rbp)
#ifdef REG_V8
	movq	REG_V8, KFRAME_V8(%rbp)
#endif
#ifdef REG_V9
	movq	REG_V9, KFRAME_V9(%rbp)
#endif
	movw	KFRAME_CS(%rbp), %ax
	andb	$1, %al
	movb	%al, KFRAME_RPL(%rbp)
	jz	\no_swap
	swapgs
.endm

.macro TRAP_EXIT
#ifdef REG_V9
	movq	KFRAME_V9(%rbp), REG_V9
#endif
#ifdef REG_V8
	movq	KFRAME_V8(%rbp), REG_V8
#endif
	movq	KFRAME_V7(%rbp), REG_V7
	movq	KFRAME_V6(%rbp), REG_V6
	movq	KFRAME_V5(%rbp), REG_V5
	movq	KFRAME_V4(%rbp), REG_V4
	movq	KFRAME_V3(%rbp), REG_V3
	movq	KFRAME_V2(%rbp), REG_V2
	movq	KFRAME_V1(%rbp), REG_V1
	movq	%rbp, %rsp
	movq	0xD8(%rbp), %rbp
	addq	$0xE8, %rsp
.endm

#ifndef __linux__
/*
 * Fix this if XMM (floating point) really is needed inside C code, for now
 * this is commented out on just Linux, because it's not tested.
 */
.macro TRAP_REST_XMM
	ldmxcsr KFRAME_CSR(%rbp)
	movaps KFRAME_XMM0(%rbp), %xmm0
	movaps KFRAME_XMM1(%rbp), %xmm1
	movaps KFRAME_XMM2(%rbp), %xmm2
	movaps KFRAME_XMM3(%rbp), %xmm3
	movaps KFRAME_XMM4(%rbp), %xmm4
	movaps KFRAME_XMM5(%rbp), %xmm5
.endm

.macro TRAP_SAVE_XMM
	stmxcsr KFRAME_CSR(%rbp)
	ldmxcsr %gs:0x180
	movaps	%xmm0, KFRAME_XMM0(%rbp)
	movaps	%xmm1, KFRAME_XMM1(%rbp)
	movaps	%xmm2, KFRAME_XMM2(%rbp)
	movaps	%xmm3, KFRAME_XMM3(%rbp)
	movaps	%xmm4, KFRAME_XMM4(%rbp)
	movaps	%xmm5, KFRAME_XMM5(%rbp)
.endm
#endif

.macro irq_entry symbol:req handler:req no_error_code:req
.globl \symbol
\symbol:
	.if \no_error_code
		subq	$8, %rsp
	.endif
	TRAP_ENTER(1f)

1:
	cld
#ifndef __linux__
	TRAP_SAVE_XMM
#endif

	movq	KFRAME_CS(%rbp), REG_A1
	movq	KFRAME_IP(%rbp), REG_A2
	call	\handler

	testb	$1, KFRAME_RPL(%rbp)
	jz	2f

#ifndef __linux__
	TRAP_REST_XMM
#endif
	TRAP_EXIT
	swapgs
	iretq

2:
#ifndef __linux__
	TRAP_REST_XMM
#endif
	TRAP_EXIT
	iretq
.endm

	.text

/* EPT violations  */
irq_entry __ept_violation	__ept_handle_violation	1

.globl __vmx_vminit
__vmx_vminit:
	pushfq
	PUSH_REGS

 	/* parameter one is pass-through (vcpu).  */
	movq	%rsp, REG_A2
	movabs	$do_resume, REG_A3
	call	vcpu_run

	/* If we get here, we failed  */
	POP_REGS
	popfq

	movb	$1, %al
	ret

do_resume:
	/* Succeeded  */
	POP_REGS
	popfq

	xorb	%al, %al
	ret

.globl __vmx_entrypoint
__vmx_entrypoint:
	/*
	 * Host entry point (aka VMX root mode).
	 * Note: all interrupts are disabled at this point.
	 */
	PUSH_REGS
	movq	%rsp, REG_A1
	call	vcpu_handle_exit

	testb	%al, %al
	jz	1f

	POP_REGS
	vmresume
	jmp	2f

1:
	POP_REGS
	vmxoff
	jna	2f

	/* Give them their stack pointer  */
	movq	%rdx, %rsp

	pushq	%rax
	popfq

	/*
	 * rcx contains return address, which is guest's rip + instr_len (aka
	 * VMCALL length)
	 */
	pushq	%rcx
	ret

2:
	pushfq
	PUSH_REGS
	movq	%rsp, REG_A1
	call	vcpu_handle_fail

3:	/* not reached  */
	hlt
	jmp 3b

