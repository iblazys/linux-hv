#include "vmx.h"
#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags

#include "../ia32-doc/out/ia32.h"
#include "asmdefs.h"

bool VmxOnInitRegion(GUEST_CPU_STATE* vcpu) 
{
    void* vmxon_region = kzalloc(PAGE_SIZE, GFP_KERNEL);
    //pr_info("vmxon region: %p", vmxon_region);

   	if(vmxon_region == NULL)
    {
        pr_err("failed to allocate vmxon region");
        return false;
   	}

    long vmxon_phy_region = __pa(vmxon_region);
    uint32_t revisionId = _readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmxon_region = revisionId; 

    vcpu->VmxonRegionPhysicalAddress = vmxon_phy_region;
    vcpu->VmxonRegionVirtualAddress = (uint64_t)vmxon_region;

    return true;
}

bool VmxOn(void *vmxon_phys)
{
    int status;
    
    status = _vmxon(vmxon_phys);

    if(status) 
    {
        pr_err("VMXON failed with status %d\n", status);
        return false;
    }

    return true;
}

void VmxOff()
{   
    _vmxoff(); // maybe move error handling to this function
}

// Free region

// 