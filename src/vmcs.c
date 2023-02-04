#include "vmcs.h"
#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags

#include "../ia32-doc/out/ia32.h"
#include "asmdefs.h"

bool AllocVmcsRegion(GUEST_CPU_STATE *vcpu)
{
    void* vmcs_region = kzalloc(PAGE_SIZE, GFP_KERNEL);

   	if(vmcs_region == NULL)
    {
        pr_err("failed to allocate vmcs region");
        return false;
   	}

    long vmxcs_phy_region = __pa(vmcs_region);
    uint32_t revisionId = _readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmcs_region = revisionId; 

    vcpu->VmcsRegionPhysicalAddress = vmxcs_phy_region;
    vcpu->VmcsRegionVirtualAddress = vmcs_region;

    return true;
}