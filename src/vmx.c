#include "vmx.h"
#include "ia32.h"

int vmx_allocate_vmxon_region(struct virtual_cpu* vcpu)
{
    void* vmxon_region = kzalloc(__PAGE_SIZE, GFP_KERNEL);
    //pr_info("vmxon region: %p", vmxon_region);

   	if(vmxon_region == NULL)
    {
        pr_err("failed to allocate vmxon region");
        return ENOMEM;
   	}

    long vmxon_phy_region = __pa(vmxon_region);
    uint32_t revisionId = __readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmxon_region = revisionId; 

    vcpu->vmxon_region_phys = vmxon_phy_region;
    vcpu->vmxon_region_virt = (uint64_t)vmxon_region;

    return 1;
}

void vmx_free_vmxon_region(struct virtual_cpu* vcpu)
{
    kfree((void*)vcpu->vmxon_region_virt);
}

int vmx_vmxon(void *vmxon_phys_addr)
{
    int status;
    
    status = __vmx_on(vmxon_phys_addr);

    if(status)
    {
        pr_err("VMXON failed with status %d\n", status);
        return 0;
    }

    return 1;
}

void vmx_adjust_control_registers(void)
{
    cr4 cr4 = { 0 };
    cr0 cr0 = { 0 };
    cr_fixed cr_fixed = { 0 };

    cr0.AsUInt = __readcr0();
    cr4.AsUInt = __readcr4();

    // save original registers
    // vcpu->saved_state->cr0 = cr0;

    // fix cr0
    cr_fixed.as_uint = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.AsUInt |= cr_fixed.fields.low;
    cr_fixed.as_uint = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.AsUInt &= cr_fixed.fields.low;
    
    // fix cr4
    cr_fixed.as_uint = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.AsUInt |= cr_fixed.fields.low;
    cr_fixed.as_uint = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.AsUInt &= cr_fixed.fields.low;

    // write em both
    __writecr0(cr0.AsUInt);
    __writecr4(cr4.AsUInt);
}

