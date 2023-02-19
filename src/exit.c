#include "exit.h"
#include "validate.h"

bool exit_handle_vmexit(uintptr_t *stack)
{
    size_t exit_reason;
    exit_reason = 0;

    struct virtual_cpu* vcpu = (struct virtual_cpu *)stack[STACK_EFL_VCPU];

    vcpu->host_sp = stack;
	vcpu->host_sp[STACK_REG_SP] = vmread(VMCS_GUEST_RSP);
	vcpu->rflags = vmread(VMCS_GUEST_RFLAGS);
	vcpu->rip = vmread(VMCS_GUEST_RIP);

    __vmx_vmread(VMCS_EXIT_REASON, &exit_reason);
    
    exit_reason &= 0xFFFF;

    pr_info("linux-hv: vmexit on cpu %d with exit reason 0x%zx", vcpu->processor_id, exit_reason);

    switch (exit_reason)
    {
        case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
        case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
        case VMX_EXIT_REASON_EXECUTE_VMPTRST:
        case VMX_EXIT_REASON_EXECUTE_VMREAD:
        case VMX_EXIT_REASON_EXECUTE_VMRESUME:
        case VMX_EXIT_REASON_EXECUTE_VMWRITE:
        case VMX_EXIT_REASON_EXECUTE_VMXOFF:
        case VMX_EXIT_REASON_EXECUTE_VMXON:
        case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
        {
            pr_info("VMEXIT: VMXINSTRUCTION");
            break;
        }

        case VMX_EXIT_REASON_EXECUTE_CPUID:
        {
            pr_info("VMEXIT: CPUID");
            //exit_handle_cpuid();
            break;
        }

        case VMX_EXIT_REASON_ERROR_INVALID_GUEST_STATE:
        {
            return exit_handle_invalid_guest_state(vcpu);

            break;
        }
    }

    // returning false = vmxoff
    // use a VMCALL to turn it off
    return true;
}

void exit_handle_fail(uintptr_t *stack)
{
    pr_info("exit failed");
}

bool exit_handle_invalid_guest_state(struct virtual_cpu* vcpu)
{
    pr_info("linux-hv: vmexit with invalid guest state!");

    // todo: dump state

    // This will check the guest state and trigger an assert
    // if any of the checks fail.
    validate_guest_entry_state();

    // Incase the above checks do not find anything (thanks intel)
    // then turn off vmx and let the vmm know we have called vmxoff
    // for this virtual cpu already
    
    // This is only temporary, until I can find the fucking cause of the invalid guest state.
    // Eventually you would want this to trigger a kernel panic.
    exit_handle_vcpu_exit(vcpu);

    vcpu->is_virtualized = false;

    return false;
}
