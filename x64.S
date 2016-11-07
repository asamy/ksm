/* Assembly for GCC(GAS) only.  See x64.asm for MSVC  */

#define PUSH_REGS	\
	pushq	%r15;	\
	pushq	%r14;	\
	pushq	%r13;	\
	pushq	%r12;	\
	pushq	%r11;	\
	pushq	%r10;	\
	pushq	%r9;	\
	pushq	%r8;	\
	pushq	%rdi;	\
	pushq	%rsi;	\
	pushq	%rbp;	\
	pushq	$-1;	\
	pushq	%rbx;	\
	pushq	%rdx;	\
	pushq	%rcx;	\
	pushq	%rax

#define POP_REGS		\
	popq	%rax;	\
	popq	%rcx;	\
	popq	%rdx;	\
	popq	%rbx;	\
	addq	$8, %rsp;\
	popq	%rbp;	\
	popq	%rsi;	\
	popq	%rdi;	\
	popq	%r8;	\
	popq	%r9;	\
	popq	%r10;	\
	popq	%r11;	\
	popq	%r12;	\
	popq	%r13;	\
	popq	%r14;	\
	popq	%r15;

#define KFRAME_RPL	-0x56
#define KFRAME_CSR	-0x54
#define KFRAME_RAX	-0x50
#define KFRAME_RCX	-0x48
#define KFRAME_RDX	-0x40
#define KFRAME_R8	-0x38
#define KFRAME_R9	-0x30
#define KFRAME_R10	-0x28
#define KFRAME_R11	-0x20
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

#define TRAP_ENTER(no_swap)			\
	pushq	%rbp;				\
	subq	$0x158, %rsp;			\
	leaq	0x80(%rsp), %rbp;		\
	movq	%rax, KFRAME_RAX(%rbp);		\
	movq	%rcx, KFRAME_RCX(%rbp);		\
	movq	%rdx, KFRAME_RDX(%rbp);		\
	movq	%r8, KFRAME_R8(%rbp);		\
	movq	%r9, KFRAME_R9(%rbp);		\
	movq	%r10, KFRAME_R10(%rbp);		\
	movq	%r11, KFRAME_R11(%rbp);		\
	movw	KFRAME_CS(%rbp), %ax;		\
	andb	$1, %al;			\
	movb	%al, KFRAME_RPL(%rbp);		\
	jz	no_swap;			\
	swapgs;

#define TRAP_EXIT				\
	movq	KFRAME_R11(%rbp), %r11;		\
	movq	KFRAME_R10(%rbp), %r10;		\
	movq	KFRAME_R9(%rbp), %r9;		\
	movq	KFRAME_R8(%rbp), %r8;		\
	movq	KFRAME_RDX(%rbp), %rdx;		\
	movq	KFRAME_RCX(%rbp), %rcx;		\
	movq	KFRAME_RAX(%rbp), %rax;		\
	movq	%rbp, %rsp;			\
	movq	0xD8(%rbp), %rbp;		\
	addq	$0xE8, %rsp;

#define TRAP_REST_XMM				\
	ldmxcsr KFRAME_CSR(%rbp);		\
	movaps KFRAME_XMM0(%rbp), %xmm0;	\
	movaps KFRAME_XMM1(%rbp), %xmm1;	\
	movaps KFRAME_XMM2(%rbp), %xmm2;	\
	movaps KFRAME_XMM3(%rbp), %xmm3;	\
	movaps KFRAME_XMM4(%rbp), %xmm4;	\
	movaps KFRAME_XMM5(%rbp), %xmm5;

#define TRAP_SAVE_XMM				\
	stmxcsr KFRAME_CSR(%rbp);		\
	ldmxcsr %gs:0x180;			\
	movaps	%xmm0, KFRAME_XMM0(%rbp);	\
	movaps	%xmm1, KFRAME_XMM1(%rbp);	\
	movaps	%xmm2, KFRAME_XMM2(%rbp);	\
	movaps	%xmm3, KFRAME_XMM3(%rbp);	\
	movaps	%xmm4, KFRAME_XMM4(%rbp);	\
	movaps	%xmm5, KFRAME_XMM5(%rbp);

	.text
.globl __vmx_vminit
__vmx_vminit:
	pushfq
	PUSH_REGS

	movq	%rsp, %rdx
	movq	$do_resume, %r8

	subq	$0x20, %rsp
	call	vcpu_init
	addq	$0x20, %rsp

	/* If we get here, we failed  */
	POP_REGS
	popfq
	xorb	%al, %al
	ret

do_resume:
	/* Succeeded  */
	POP_REGS
	popfq

	movb	$1, %al
	ret

.globl __vmx_entrypoint
__vmx_entrypoint:
	PUSH_REGS
	movq	%rsp, %rcx

	subq	$0x48, %rsp
	call	vcpu_handle_exit
	addq	$0x48, %rsp

	testb	%al, %al
	jz	exit

	POP_REGS
	vmresume
	jmp	error

exit:
	POP_REGS
	vmxoff
	jz	error
	jc	error
	pushq	%rax
	popfq
	movq	%rdx, %rsp
	pushq	%rcx
	ret

error:
	pushfq
	movq	%rsp, %rcx

	subq	$0x28, %rsp
	call	vcpu_handle_fail
	addq	$0x28, %rsp
	ret

.globl __ept_violation
__ept_violation:
	subq	$8, %rsp
	TRAP_ENTER(ept_no_swap)

ept_no_swap:
	cld
	TRAP_SAVE_XMM

	movq	KFRAME_CS(%rbp), %rcx
	movq	KFRAME_IP(%rbp), %rdx

	subq	$0x48, %rsp
	call	__ept_handle_violation
	addq	$0x48, %rsp

	testb	$1, KFRAME_RPL(%rbp)
	jz	ept_ret_noswap

	TRAP_REST_XMM
	TRAP_EXIT
	swapgs
	iretq

ept_ret_noswap:
	TRAP_REST_XMM
	TRAP_EXIT
	iretq

.globl __segmentlimit
__segmentlimit:
	lsl	%rax, %rcx
	ret

