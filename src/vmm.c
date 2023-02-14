#include "vmm.h"
#include "cpu.h"
#include "vmx.h"
#include "vmx_asm.h"
#include "vmcs.h"

struct vmm_state* vmm_init(void)
{
    struct vmm_state* vmm;
    unsigned int processorCount;

    // Check vmx support
    if(!cpu_supports_vmx())
    {
        // Handled
        return NULL;
    }

    processorCount = num_online_cpus();

    if(!(vmm = vmm_allocate_vmm_state()))
    {
        pr_err("Failed to allocate vmm state");
        return NULL;
    }

    if(!(vmm->guest_cpus = vmm_allocate_virtual_cpus(processorCount)))
    {
        pr_err("Failed to allocate guest cpus");
        vmm_free_vmm_state(vmm);
        return NULL;
    }

    // Set state
    vmm->number_of_cpus = processorCount;

    /* 
    Setup and launch each cpu, __vmx_vminit is located in vmx_asm.S
    which ends up calling vmm_virtualize_single_cpu
    */

    on_each_cpu((void*)__vmx_vminit, vmm, true);

    // TODO: Error handling below
    vmm->init_status = true;

    return vmm;
}

//
struct vmm_state* vmm_allocate_vmm_state(void)
{   
    struct vmm_state* vmm;

    vmm = kzalloc(sizeof(struct vmm_state), GFP_KERNEL);

    return vmm;
}

//
struct virtual_cpu* vmm_allocate_virtual_cpus(uint32_t num_of_cpus)
{
    struct virtual_cpu* guest_cpu;

    guest_cpu = kzalloc(sizeof(struct virtual_cpu) * num_of_cpus, GFP_KERNEL);

    return guest_cpu;
}

int vmm_allocate_saved_state(struct virtual_cpu* vcpu)
{
    vcpu->saved_state = kzalloc(sizeof(struct cpu_saved_state), GFP_KERNEL);

    if(!vcpu->saved_state)
    {   
        pr_err("Failed to allocate vcpu saved state");
        return 0;
    }

    return 1;
}

//
// called from __vmx_vminit in vmx_asm.S
// Initializes a single processor and launches the vm
//
void vmm_virtualize_single_cpu(void* info, uintptr_t gsp, uintptr_t gip)
{    
    unsigned int processor_id = smp_processor_id();

    struct vmm_state* vmm = info;
    struct virtual_cpu* vcpu = &vmm->guest_cpus[processor_id];
    vcpu->processor_id = processor_id;

    pr_info("virtualizing processor %d", vcpu->processor_id);

    // enable vmx operation in cr4
    cpu_enable_vmx_operation();

    // adjust control register fixed bits
    // todo: save original registers
    vmx_adjust_control_registers();

    if(!vmm_allocate_saved_state(vcpu))
    {
        vcpu->launch_failed = true;
        return;
    }

    if(!vmx_allocate_vmxon_region(vcpu))
    {
        vcpu->launch_failed = true;
        return;
    }

    if(!vmcs_allocate_vmcs_region(vcpu))
    {
        vmx_free_vmxon_region(vcpu);
        vcpu->launch_failed = true;
        return;
    }

    // vmxon, vmclear, vmptrld
    if(!vmx_prepare_to_launch(vcpu))
    {
        vmx_free_vmxon_region(vcpu);
        vmcs_free_vmcs_region(vcpu);

        vcpu->launch_failed = true;

        return;
    }

    // set vcpu rsp, rip, and eflags
    vcpu->rsp = gsp;
    vcpu->rip = gip;
    vcpu->rflags = __readrflags();
    
    // put our virtual cpu at the top of the stack
    *(struct virtual_cpu **)((uintptr_t)vcpu->stack + HOST_STACK_SIZE - 8) = vcpu;

    // setup vmcs
    vmcs_setup_vmcs(vcpu);

    pr_info("ready to launch vm on cpu %d", vcpu->processor_id);

    // call vmlaunch
    __vmx_vmlaunch();

    pr_info("WE FAILED!!");
}

//
void vmm_free_vmm_state(struct vmm_state* vmm)
{
    kfree(vmm);
}

//
void vmm_free_virtual_cpus(struct vmm_state* vmm)
{
    kfree(vmm->guest_cpus);
}

// dont call this directly, use vmm_shutdown
void vmm_shutdown_cpu(struct vmm_state* vmm)
{
    struct virtual_cpu* vcpu = &vmm->guest_cpus[smp_processor_id()];

    pr_info("shutting down vm on cpu: %d", vcpu->processor_id);

    if(vcpu->launch_failed)
    {
        /*  
        The virtual cpu freed and shutdown if the launch fails
        see vmm_virtual_single_cpu and vmx_prepare_to_launch
        */
        return;
    }
    
    // Turn vmx off
    __vmx_off();

    // Disable vmx in cr4

    // Reset fixed bits
    
    // Free vm regions
    vmx_free_vmxon_region(vcpu);
    vmcs_free_vmcs_region(vcpu);

    //vmm_free_saved_state(vcpu); -- TODO
}

//
void vmm_shutdown(struct vmm_state* vmm)
{
    // Shutdown each virtualized cpu
    on_each_cpu((void*)vmm_shutdown_cpu, vmm, true);

    // Free vcpus and vmm state
    vmm_free_virtual_cpus(vmm);
    vmm_free_vmm_state(vmm);
}
