/* 
 * vmm.c - our virtual machine manager
 */
#include "vmm.h"

#include <linux/kernel.h>
#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags
#include <linux/vmalloc.h> // vmalloc
#include <linux/smp.h>     // get_cpu(), put_cpu()

#include <asm/msr.h> // rdmsr testing
#include <cpuid.h> // cpuid intrinsic

#include "arch.h"
#include "../ia32-doc/out/ia32.h" //
#include "asmdefs.h"
#include "vmx.h"
#include "vmcs.h"

// this doesnt need to be global anymore
//GUEST_CPU_STATE* g_VMMContext;

VMM_STATE* VmmInit(void)
{   
    VMM_STATE* VmmState;

    if(!CpuHasVmxSupport()) 
    {
        // Handled by above function. 
        return -1;
    }

    pr_info("vMX support detected");

    // Allocate state memory - move to an InitVmmState function or something
    int32_t processorCount = num_online_cpus();

    VmmState = kzalloc(sizeof(VMM_STATE), GFP_KERNEL);
    pr_info("vmm state allocated");

    VmmState->GuestCPUs = kzalloc(sizeof(GUEST_CPU_STATE) * processorCount, GFP_KERNEL);
    pr_info("zero allocated memory for %d guest cpus", processorCount);

    on_each_cpu(InitSingleCpuEntry, VmmState, true);
    // Guest will resume here only if it fails.


    // Allocate vmx on and vmcs regions on all cpu's
    //on_each_cpu((void*)AllocateVMRegionOnAllCPU, g_VMMState, true);

    // messing around

    // Is this safe in root mode, I guess I'll find out
    // on_each_cpu((void*)testFunc, NULL, true);

    return VmmState;
}

bool VmmShutdown(void* info)
{
    uint32_t cpuid = smp_processor_id();
    VMM_STATE* vmm = info;
    GUEST_CPU_STATE* current_vcpu = &((VMM_STATE*)info)->GuestCPUs[cpuid];

    //pr_info("vcpu[%d] shutting down vm", cpuid);

    // Execute vmxoff on all CPU's
    VmxOff();
    pr_info("vcpu[%d] vmxoff", cpuid);

    // Disable VMX operation on all CPU's
    CpuDisableVmxOperation();
    pr_info("vmx operation disabled on cpuid %d", cpuid);

    // Free vmxon region
    kfree(current_vcpu->VmxonRegionVirtualAddress);

    // Free vmcs region
    kfree(current_vcpu->VmcsRegionVirtualAddress);

    return true;
}

void VmmDestroy(VMM_STATE* vmmState)
{
    // Only call this function after the VMM has shutdown.

    kfree(vmmState->GuestCPUs);
    kfree(vmmState);
}

//
// Called from asm, ran on every cpu
// Allocates the memory, enables vmxe in cr4, and sets up the vmcs
//
void InitSingleCPU(void* info, u64 ip, u64 sp, u64 flags)
{
    uint32_t cpuid = smp_processor_id();
    GUEST_CPU_STATE* current_vcpu = &((VMM_STATE*)info)->GuestCPUs[cpuid];

    if(current_vcpu < 0)
    {
        pr_info("failed to get vcpu[%d]", cpuid);
    }

    //pr_info("guest will resume to %p with rsp=%llx on fail\n", (void*)ip, sp);

    CpuEnableVmxOperation();

    // Adjust control register bits
    AdjustCR4AndCr0Bits();

    // Allocate memory
    if(!VmxOnInitRegion(current_vcpu)) 
    {
        // Handled
        goto error;
    }

    pr_info("vcpu[%d] vmxon_region virt: %llx, phys: %llx",
        cpuid, current_vcpu->VmxonRegionVirtualAddress, current_vcpu->VmxonRegionPhysicalAddress);

    
    if(!VmcsInitRegion(current_vcpu))
    {
        // Handled
        goto error;
    }

    pr_info("vcpu[%d] vmcs_region virt: %llx, phys: %llx",
        cpuid, current_vcpu->VmcsRegionVirtualAddress, current_vcpu->VmcsRegionPhysicalAddress);

    // execute vmx on for current processor
    if(!VmxOn(current_vcpu->VmxonRegionPhysicalAddress)) 
    {
        goto error;
    }
    
    pr_info("vcpu[%d] vmxon", cpuid);
    
    // Setup VMCS
    //VmcsSetupControls();
    //VmcsSetupGuest();
    //VmcsSetupHost();
    
    /*
    if (_vmxon(vmxon_phy_region)) 
    {
        pr_info("vmxon for processor %d", current_cpu);
    }
    else
    {
        //return false;
    }
    */
error:
    return;
}

void AdjustCR4AndCr0Bits(void)
{
    CR_FIXED CrFixed = { 0 };
    CR4      Cr4 = { 0 };
    CR0      Cr0 = { 0 };

    //
    // Fix Cr0
    //
    CrFixed.Flags = _readmsr(IA32_VMX_CR0_FIXED0);
    Cr0.AsUInt = _readcr0();
    Cr0.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = _readmsr(IA32_VMX_CR0_FIXED1);
    Cr0.AsUInt &= CrFixed.Fields.Low;

    _writecr0(Cr0.AsUInt);

    //
    // Fix Cr4
    //
    CrFixed.Flags = _readmsr(IA32_VMX_CR4_FIXED0);
    Cr4.AsUInt = _readcr4();
    Cr4.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = _readmsr(IA32_VMX_CR4_FIXED1);
    Cr4.AsUInt &= CrFixed.Fields.Low;

    _writecr4(Cr4.AsUInt);
}
