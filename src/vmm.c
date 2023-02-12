#include "vmm.h"
#include "cpu.h"
#include "vmx.h"
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

    // Initialize each cpu
    on_each_cpu(vmm_virtualize_single_cpu, vmm, true);

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

void vmm_virtualize_single_cpu(void* info)
{
    unsigned int processor_id = smp_processor_id();

    struct vmm_state* vmm = info;
    struct virtual_cpu* vcpu = &vmm->guest_cpus[processor_id];
    vcpu->processor_id = processor_id;

    pr_info("virtualizing processor %d", vcpu->processor_id);

    cpu_enable_vmx_operation();

    vmx_adjust_control_registers();

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

    if(!vmx_vmxon((void*)vcpu->vmxon_region_phys))
    {
        vmx_free_vmxon_region(vcpu);
        vmcs_free_vmcs_region(vcpu);

        vcpu->launch_failed = true;

        return;
    }

    pr_info("vmx enabled on cpu %d", vcpu->processor_id);
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

void vmm_shutdown_cpu_shim(struct vmm_state* vmm)
{
    struct virtual_cpu* vcpu = &vmm->guest_cpus[smp_processor_id()];

    pr_info("shutting down vm on cpu: %d", vcpu->processor_id);

    if(vcpu->launch_failed)
    {
        // vcpu already freed if launch failed
        // see vmm_virtualize_single_cpu...
        return;
    }
    
    // todo: turn vmx off etc

    vmx_free_vmxon_region(vcpu);
    vmcs_free_vmcs_region(vcpu);
}

//
void vmm_shutdown(struct vmm_state* vmm)
{
    on_each_cpu((void*)vmm_shutdown_cpu_shim, vmm, true);

    // free guest state
    // free vmm
}
