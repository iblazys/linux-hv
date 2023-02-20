#ifndef __LINUXHV_EXIT_H
#define __LINUXHV_EXIT_H

#include "x86.h"
#include "vmm.h"

#define STACK_REG_AX			0
#define STACK_REG_CX			1
#define STACK_REG_DX			2
#define STACK_REG_BX			3
#define STACK_REG_SP			4
#define STACK_REG_BP			5
#define STACK_REG_SI			6
#define STACK_REG_DI			7
#define STACK_REG_R8			8
#define STACK_REG_R9			9
#define STACK_REG_R10			10
#define STACK_REG_R11			11
#define STACK_REG_R12			12
#define STACK_REG_R13			13
#define STACK_REG_R14			14
#define STACK_REG_R15			15
#define STACK_EFL_VCPU			16
#define STACK_VCPU              17

// test
struct hypercall_request {
    union {
        struct {
            uint16_t call_code : 16;
            uint8_t fast : 1;
            uint16_t variable_header_size : 10;
            uint8_t rsvdZ1 : 4;
            uint8_t is_nested : 1;
            uint32_t rep_count : 12;
            uint8_t rsvdZ2 : 4;
            uint16_t rep_start_index : 12;
            uint8_t rsvdZ3 : 4;
        };
        uint64_t data;
    };
};

bool exit_handle_vmexit(uintptr_t *stack);
void exit_handle_fail(uintptr_t *stack);

bool exit_handle_invalid_guest_state(struct virtual_cpu* vcpu);

bool exit_handle_write_msr(struct virtual_cpu* vcpu);

/* should be called by a vmcall */
static inline void exit_handle_vcpu_exit(struct virtual_cpu* vcpu)
{
	/* Fix GDT  
	struct gdtr gdt = {
		.limit = (u16)vmcs_read32(GUEST_GDTR_LIMIT),
		.base = vmcs_read(GUEST_GDTR_BASE),
	};
	__lgdt(&gdt);
	*/

	/* Fix IDT (restore whatever guest last loaded...) 
	__lidt(&vcpu->g_idt);
	*/

	uintptr_t ret = vcpu->rip + vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);

	// set rflags to indicate successful vmcall - todo: function
	rflags rflags;
	rflags.AsUInt = vcpu->rflags;

	vcpu->rflags &= ~(rflags.carry_flag | rflags.parity_flag | rflags.auxiliary_carry_flag |
			rflags.zero_flag | rflags.sign_flag | rflags.overflow_flag);

	uintptr_t cr3 = vmread(VMCS_GUEST_CR3);
	write_cr3(cr3); // todo: wrapper __writec

	/* See __vmx_entrypoint in assembly on how this is used.  */
	*(uintptr_t *)&vcpu->host_sp[STACK_REG_CX] = ret;
	*(uintptr_t *)&vcpu->host_sp[STACK_REG_DX] = vcpu->host_sp[STACK_REG_SP];
	*(uintptr_t *)&vcpu->host_sp[STACK_REG_AX] = vcpu->rflags;

    /*
	ksm_write_reg(vcpu, STACK_REG_CX, ret);
	ksm_write_reg(vcpu, STACK_REG_DX, ksm_read_reg(vcpu, STACK_REG_SP));
	ksm_write_reg(vcpu, STACK_REG_AX, vcpu->eflags);
    */
}

// move these functions and the struct to a dedicated vcpu.h/c ?

static inline void vcpu_advance_rip(struct virtual_cpu *vcpu)
{
	uint32_t instruction_len = (uint32_t)vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
	__vmx_vmwrite(VMCS_GUEST_RIP, vcpu->rip + instruction_len);
}

static inline uint32_t vcpu_read_reg32(struct virtual_cpu *vcpu, int reg)
{
	return (uint32_t)vcpu->host_sp[reg];
}

static inline uint64_t vcpu_combine_reg64(struct virtual_cpu *vcpu, int lo, int hi)
{
	return (uint64_t)vcpu_read_reg32(vcpu, lo) | (u64)vcpu_read_reg32(vcpu, hi) << 32;
}

#endif