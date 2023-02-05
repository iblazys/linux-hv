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
        return NULL;
    }

    // Allocate state memory - move to an InitVmmState function or something
    int32_t processorCount = num_online_cpus();

    if(!(VmmState = kzalloc(sizeof(VMM_STATE), GFP_KERNEL)))
    {
        pr_err("failed to allocate vmm state");
        return NULL;
    }

    if(!(VmmState->GuestCPUs = kzalloc(sizeof(VIRTUAL_CPU) * processorCount, GFP_KERNEL)))
    {
        pr_err("failed to allocate guest cpu states");
        kfree(VmmState);
        return NULL;
    }

    on_each_cpu(InitSingleCpuEntry, VmmState, true);

    // todo: add number of launched cpus to a vmm state member

    return VmmState;
}

bool VmmShutdown(void* info)
{
    uint32_t cpuid = smp_processor_id();
    VMM_STATE* vmm = info;
    VIRTUAL_CPU* current_vcpu = &((VMM_STATE*)info)->GuestCPUs[cpuid];

    //pr_info("vcpu[%d] shutting down vm", cpuid);

    // Execute vmxoff on all CPU's
    VmxOff();

    // Disable VMX operation on all CPU's
    CpuDisableVmxOperation();
    //pr_info("vmx operation disabled on cpuid %d", cpuid);

    // Free vmxon region
    kfree(current_vcpu->VmxonRegionVirtualAddress);

    // Free vmcs region
    kfree(current_vcpu->VmcsRegionVirtualAddress);

    pr_info("vcpu[%d] vmm shutdown", cpuid);

    return true;
}

/// @brief 
/// @param vmmState 
void VmmDestroy(VMM_STATE* vmmState)
{
    // Only call this function after the VMM has shutdown.
    //if(vmmState->IsRunning)
    // error

    kfree(vmmState->GuestCPUs);
    kfree(vmmState);
}

//
// Allocates the memory, enables vmxe in cr4 
// sets up the vmcs and calls vmlaunch on 
// every cpu, called from `InitSingleCpuEntry` in asmdefs.S
//
void VmmVirtualizeSingleCpu(void* info, u64 ip, u64 sp, u64 flags)
{
    uint32_t cpuid = smp_processor_id();
    VMM_STATE* vmmState = info;
    VIRTUAL_CPU* currentvCpu = &((VMM_STATE*)info)->GuestCPUs[cpuid];

    currentvCpu->RIP = ip;
    currentvCpu->RSP = sp;
    currentvCpu->RFlags = flags;

    currentvCpu->ProcessorId = cpuid;
    currentvCpu->VmmStatePtr = vmmState;

    //pr_info("guest will resume to %p with rsp=%llx on fail\n", (void*)ip, sp);

    CpuEnableVmxOperation();

    // Adjust control register bits
    AdjustCR4AndCr0Bits();

    // Get rid of gotos? meh

    // Allocate memory
    if(!VmxOnInitRegion(currentvCpu)) 
    {
        goto error;
    }

    if(!VmcsInitRegion(currentvCpu))
    {
        goto error;
    }

    // execute vmx on the vmcs physical address
    if(!VmxOn(currentvCpu->VmxonRegionPhysicalAddress)) 
    {
        goto error;
    }

    // Clear VMCS - execute vmclear on the vmcs physical address
    if(!VmcsClear(currentvCpu->VmcsRegionPhysicalAddress))
    {
        goto vmclearFail;
    }

    // Load VMCS - execute vmptrld on the vmcs physical address
    if(!VmcsLoad(currentvCpu->VmcsRegionPhysicalAddress))
    {
        goto vmloadFail;
    }

    // Setup VMCS
    VmcsSetup(currentvCpu); // pass current cpu to this and save gdt idt etc


    currentvCpu->VmExitHandler = &EntryToVmExit;
    currentvCpu->LaunchFailed = false;

    // VMLAUNCH
    pr_info("Ready to launch vm");




vmloadFail:
vmclearFail:
    currentvCpu->LaunchFailed = true;
    // turn off vmx for failed processor
    // have to change ShutdownVMM to detect failed processors before we can do that
    // see below comment
error:
    currentvCpu->LaunchFailed = true; 
    // todo: check failed launched in InitVmm and ShutdownVMM
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
    CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    Cr0.AsUInt = __readcr0();
    Cr0.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    Cr0.AsUInt &= CrFixed.Fields.Low;

    _writecr0(Cr0.AsUInt);

    //
    // Fix Cr4
    //
    CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    Cr4.AsUInt = __readcr4();
    Cr4.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    Cr4.AsUInt &= CrFixed.Fields.Low;

    _writecr4(Cr4.AsUInt);
}
