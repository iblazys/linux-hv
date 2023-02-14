#ifndef __ASSEMBLY__
#error __ASSEMBLY__ is not defined...
#endif

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
	subq	$8, %rsp	/* placeholder  */
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

	.text

.globl __vmx_vminit
__vmx_vminit:
	pushfq
	PUSH_REGS

	/* 
	rdi = virtual_cpu struct
	rsi (REG_A2) = contains the stack pointer for the guest
	rdx = the address to jump to after launch
	rcx = the original flags for the guest
	*/

	/* parameter one is pass-through (vcpu).  */

	movq	%rsp, REG_A2 /* put rsp into argument 2 */
	movabs	$do_resume, REG_A3 /* put do_resume's address in argument 3 */

	subq	$0x20, %rsp
	call	vmm_virtualize_single_cpu
	addq	$0x20, %rsp

	/* If we get here, we failed  */
	POP_REGS
	popfq

	ret

/* guest resumes here on successful vmlaunch */
do_resume:
	POP_REGS
	popfq

	xorl 	%eax, %eax
	ret

/* ----------------------------------------------------- */

.globl __vmx_entrypoint
__vmx_entrypoint:
	/*
	 * Host entry point (aka VMX root mode).
	 * Note: all interrupts are disabled at this point.
	 *
	 * Save all guest general purpose registers, then let the C handler do
	 * the rest.
	 *
	 *	This is how the stack looks like after PUSH_REGS:
	 *		+0   = %rax
	 *		+8   = %rcx
	 *		+16  = %rdx
	 *		+24  = %rbx
	 *		+32  = %rsp	(garbage, overwritten with real value in
	 *				 vcpu_handle_exit())
	 *		+40  = %rbp
	 *		+48  = %rsi
	 *		+56  = %rdi
	 *		+64  = %r8
	 *		+72  = %r9
	 *		+80  = %r10
	 *		+88  = %r11
	 *		+96  = %r12
	 *		+104 = %r13
	 *		+112 = %r14
	 *		+120 = %r15
	 *		+128 = vcpu (set in vcpu_create())
	 *
	 * Note: we pass vcpu->stack -8 to HOST_RSP, this is because
	 * at this specific area, it's set to the vcpu pointer.  So basically,
	 * a pop here (before PUSH_REGS) will pop vcpu pointer, but the
	 * registers in this specific context are guest registers, we need
	 * their values as-is untouched, we may also modify them later on
	 * depending on the event (e.g. cpuid, etc.)
	 */
	PUSH_REGS
	movq	%rsp, REG_A1

	subq	$0x20, %rsp
	call	exit_handle_vmexit
	addq	$0x20, %rsp

	testb	%al, %al
	jz	1f

	POP_REGS
	vmresume

	/* Something went wrong during re-entry to guest...  */
	jmp	2f

1:
	/* See exit.c (vcpu_do_exit)  */
	POP_REGS
	vmxoff
	jna	2f

	/* Give them their stack pointer  */
	movq	%rdx, %rsp

	/* and their rflags (adjusted to indicate successful vmcall)  */
	pushq	%rax
	popfq

	/*
	 * rcx contains return address, which is guest's rip + instr_len (aka
	 * VMCALL length)
	 */
	pushq	%rcx
	ret

2:
	/* Either vmresume or vmxoff failure...  */
	nop
	pushfq
	PUSH_REGS
	movq	%rsp, REG_A1
	subq	$0x20, %rsp
	call	exit_handle_fail
	addq	$0x20, %rsp


3:	/* shouldn't come here, but incase it does, hlt forever:  */
	hlt
	jmp 3b