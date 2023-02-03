/* 
 * vmm.c - our virtual machine manager
 */ 

#include <linux/kernel.h>
#include <linux/slab.h> // memory alloc
#include <linux/gfp.h> // memory alloc flags

#include <cpuid.h> // cpuid intrinsic
#include <asm/msr.h> // msr instrinsic

#include "../ia32-doc/out/ia32.h"
//#include "asm_operations.h"
#include "vmm.h"

bool InitVMM(void)
{        
    if(!CheckCPUFeatures()) 
    {
        // Handled by above function. 
        return false;
    }

    pr_info("VMX support detected");

    int32_t processorCount = num_online_cpus();

    // Allocate guest state (virtual cpu state) array
    // TODO: Create guest state struct
    VIRTUAL_CPU_STATE *guestState = kzalloc(sizeof(VIRTUAL_CPU_STATE) * processorCount, GFP_NOWAIT);

    pr_info("Allocated guest state for %d processors", processorCount);

    kfree(guestState);

    pr_info("Freed guest state");

    return true;
}

/// @brief Check if the cpu supports the features required by this hypervisor.
bool CheckCPUFeatures(void)
{
    CPUID_EAX_01 cpu = { 0 };

    // Run the cpuid instruction
    __get_cpuid(1, &cpu.CpuidVersionInformation.AsUInt,
        &cpu.CpuidAdditionalInformation.AsUInt,
        &cpu.CpuidFeatureInformationEcx.AsUInt,
        &cpu.CpuidFeatureInformationEdx.AsUInt);

    // bit 31 of ecx = hypervisor present bit
    
    if (cpu.CpuidFeatureInformationEcx.VirtualMachineExtensions == 0) 
    {
        pr_info("VMX is not supported on your processor.");
        return false;
    }
    
    return true;
}