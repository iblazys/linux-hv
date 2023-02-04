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

// this doesnt need to be global anymore
VMM_STATE* g_VMMState;
//GUEST_CPU_STATE* g_VMMContext;

bool InitVMM(void)
{   
    VMM_STATE* VmmState;

    if(!CpuHasVmxSupport()) 
    {
        // Handled by above function. 
        return false;
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

    return true;
}

bool ShutdownVMM(void)
{
    uint32_t cpu;
    cpu = get_cpu();
    put_cpu();

    // Disable VMX operation on all CPU's
    on_each_cpu((void*)CpuDisableVmxOperation, NULL, true);

    pr_info("vmx operation disabled on cpuid %d", cpu);

    // Free guest cpu memory
    kfree(g_VMMState->GuestCPUs);

    // Free vmm state
    kfree(g_VMMState);

    return true;
}

void testFunc(void)
{
    unsigned int cpu;
    
    cpu = get_cpu();

    //pr_info("Running on CPU: %u\n", cpu);

    //pr_info("GuestState[%d] address: 0x%llx", cpu, g_GuestState);

    //VIRTUAL_CPU_STATE* currentCpu = &g_VMMContext[cpu];

    //pr_info("GuestState[%d] address: 0x%llx", cpu, currentCpu);

    //currentCpu->VmcsRegionPhysicalAddress = 0xFFFFFFFF;

    //put_cpu(); // Don't forget this!
}

//
// Called from asm, ran on every cpu
//
void InitSingleCPU(void* info, u64 ip, u64 sp, u64 flags)
{
    uint32_t current_cpu = smp_processor_id();
    GUEST_CPU_STATE* vcpu = &((VMM_STATE*)info)->GuestCPUs[current_cpu];

    //pr_info("guest will resume to %p with rsp=%llx on fail\n", (void*)ip, sp);

    CpuEnableVmxOperation();

    //pr_info("vmx operation enabled on cpuid %d", current_cpu);

    // Adjust control register bits
    AdjustCR4AndCr0Bits();

    // Allocate vm regions
    void* vmxon_region = kzalloc(4096, GFP_KERNEL);

   	if(vmxon_region == NULL)
    {
		printk(KERN_INFO "Error allocating vmxon region\n");
        // vmm_state->last_error = 0;
        return;
   	}

    long vmxon_phy_region = __pa(vmxon_region);
    uint32_t revisionId = _readmsr(IA32_VMX_BASIC);

    *(uint32_t *)vmxon_region = revisionId; // set revision id

    // set vm regions
    vcpu->VmxonRegionPhysicalAddress = vmxon_phy_region;
    vcpu->VmxonRegionVirtualAddress = vmxon_region;

    pr_info("vcpu[%d] vmxon_region virt: %llx, phys: %llx",
        current_cpu, vmxon_region, vmxon_phy_region);

    // allocate vmcs regions
    
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

    

    //return true;
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

bool AllocateVMRegion(void)
{
    uint32_t RegionSize = 2 * 4096; // TODO: define vmxonsize

    void* region = vzalloc(RegionSize + 4096); // TODO: define alignment page size

    pr_info("vmxonregion at address: 0x%p", region);

    vfree(region);
    return true;
}
