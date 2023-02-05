#include <linux/linkage.h>
#include <asm/export.h>

.extern VmmVirtualizeSingleCpu
.extern ExitVmExitHandler

// https://github.com/birb007/sauron/blob/3b2188963ec07a53af421ddc6130e423fee3e6dd/src/vmxasm.S

.macro store_cpu_state
	pushq %rbp
	subq $8, %rsp
	pushq %rax
	pushq %rbx
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
.endm

.macro restore_cpu_state
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	addq $8, %rsp
	popq %rbp
.endm

.text

// Per-CPU hypervisor initialisation entry point
SYM_FUNC_START(InitSingleCpuEntry)
	pushfq
	store_cpu_state
	movabs $.vmx_guest_resume, %rsi
	movq %rsp, %rdx
	movq 0x80(%rsp), %rcx
	// %rdi contains the VMM context structure (struct vmm_ctx).
	// %rsi contains the address to jump to after VMLAUNCH.
	// %rdx contains the original sp for VMX guest.
	// %rcx contains the original flags for VMX guest.
	subq $0x20, %rsp
	call VmmVirtualizeSingleCpu
	addq $0x20, %rsp
	jmp .vmx_guest_resume
.vmx_guest_resume:
	// If VMLAUNCH fails to execute, InitSingleCpuEntry returns with an
	// error indication with ((struct cpu_ctx*)cpu)->failed. Otherwise,
	// the failed indicator is not set.
	restore_cpu_state
	popfq
	ret
SYM_FUNC_END(InitSingleCpuEntry)
EXPORT_SYMBOL(InitSingleCpuEntry)

// VM-exit entry point
SYM_FUNC_START(EntryToVmExit)
	store_cpu_state
	movq 0x80(%rsp), %rdi
	movq %rsp, %rsi
	// %rdi contains the cpu_ctx pointer at the top of the stack
	// which store_cpu_state moves by 0x80 bytes.
	// %rsi contains a pointer to a hv_exit_state instance.
	subq $0x20, %rsp
	call ExitVmExitHandler
	addq $0x20, %rsp

	test %al, %al
	jnz .failure

	restore_cpu_state
	VMRESUME
	// If VMRESUME does not succeed then attempt to handle error.
	jmp .failure
.failure:
	// TODO implement VMRESUME error handler
	jmp .critical_failure
.critical_failure:
	hlt
	jmp .critical_failure
SYM_FUNC_END(EntryToVmExit)
EXPORT_SYMBOL(EntryToVmExit)