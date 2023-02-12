#include "vmcs.h"
#include "ia32.h"

int vmcs_allocate_vmcs_region(struct virtual_cpu* vcpu)
{
    void* vmcs_region = kzalloc(PAGE_SIZE, GFP_KERNEL);

   	if(vmcs_region == NULL)
    {
        pr_err("failed to allocate vmcs region");
        return 0;
   	}

    long vmxcs_phy_region = __pa(vmcs_region);
    uint32_t revisionId = __readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmcs_region = revisionId; 

    vcpu->vmcs_region_phys = vmxcs_phy_region;
    vcpu->vmcs_region_virt = (uint64_t)vmcs_region;

    return 1;
}

void vmcs_free_vmcs_region(struct virtual_cpu* vcpu)
{
    kfree((void*)vcpu->vmcs_region_virt);
}
