#ifndef __ASSEMBLY__
#error __ASSEMBLY__ is not defined...
#endif

.globl __vmx_vminit
__vmx_vminit:
	pushfq
	PUSH_REGS

	/* parameter one is pass-through (vcpu).  */
	movq	%rsp, REG_A2
	movabs	$do_resume, REG_A3

	subq	$0x20, %rsp
	call	vcpu_run
	addq	$0x20, %rsp

	/* If we get here, we failed  */
	POP_REGS
	popfq

	movl	ERR_DENIED, %eax
	ret

do_resume:
	/* Succeeded  */
	POP_REGS
	popfq

	xorl 	%eax, %eax
	ret