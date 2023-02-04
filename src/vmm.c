/* 
 * vmm.c - our virtual machine manager
 */ 

#include <linux/kernel.h>
#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags
#include <linux/vmalloc.h> // vmalloc
#include <linux/smp.h>     // get_cpu(), put_cpu()

#include <cpuid.h> // cpuid intrinsic

#include "../ia32-doc/out/ia32.h"
#include "vmm.h"
#include "asmdefs.h"

VIRTUAL_CPU_STATE* g_GuestState;

bool InitVMM(void)
{        
    if(!CheckCPUFeatures()) 
    {
        // Handled by above function. 
        return false;
    }

    pr_info("VMX support detected");

    int32_t processorCount = num_online_cpus();

    // Zero allocate guest state (virtual cpu state) array
    g_GuestState = kzalloc(sizeof(VIRTUAL_CPU_STATE) * processorCount, GFP_NOWAIT);

    pr_info("Allocated guest state memory for %d processors", processorCount);
    pr_info("g_GuestState address: 0x%llx", g_GuestState);

    // free guest state
    kfree(g_GuestState);
    pr_info("freed guest state");

    // Allocate vmx on and vmcs regions on all cpu's
    on_each_cpu((void*)AllocateVMRegionOnAllCPU, NULL, true);

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

    // disable vmx in cr4
    CR4 cr4;
    cr4.AsUInt = _readcr4();
    cr4.VmxEnable = false;
    _writecr4(cr4.AsUInt);

    pr_info("vmx operation disabled on cpuid %d", cpu);

    return true;
}

void testFunc(void)
{
    unsigned int cpu;
    
    cpu = get_cpu();

    //pr_info("Running on CPU: %u\n", cpu);

    //pr_info("GuestState[%d] address: 0x%llx", cpu, g_GuestState);

    VIRTUAL_CPU_STATE* currentCpu = &g_GuestState[cpu];

    pr_info("GuestState[%d] address: 0x%llx", cpu, currentCpu);

    currentCpu->VmcsRegionPhysicalAddress = 0xFFFFFFFF;

    put_cpu(); // Don't forget this!
}

//
/// @brief Check if the cpu supports the features required by this hypervisor.
//
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

    // Load feature control register
    IA32_FEATURE_CONTROL_REGISTER Control = { 0 };
    Control.AsUInt = _readmsr(IA32_FEATURE_CONTROL);

    pr_info("Lock Bit: %d", Control.LockBit);
    pr_info("EnableVmxInsideSmx: %d", Control.EnableVmxInsideSmx);
    pr_info("EnableVmxOutsideSmx: %d", Control.EnableVmxOutsideSmx);

    // BIOS lock checking
    if (Control.LockBit == 0) // Check if lock exists
    {
        Control.LockBit = true;
        Control.EnableVmxInsideSmx = true; 

        // Write the MSR with lock bit set to 1 and EnableVmxInsideSmx to 1
        _writemsr(IA32_FEATURE_CONTROL, Control.AsUInt);
    }
    else
    {
        pr_err_once("VMX locked off in BIOS");
        return false;
    }
    
    return true;
}

void AllocateVMRegionOnAllCPU()
{
    uint32_t current_cpu = get_cpu();
    put_cpu();

    //pr_info("currently executing in logical processor %d", current_cpu);

    // Enable VMX Operation - TODO: Own function
    CR4 cr4;
    cr4.AsUInt = _readcr4();
    cr4.VmxEnable = true;

    _writecr4(cr4.AsUInt);

    pr_info("vmx operation enabled on cpuid %d", current_cpu);

    // Adjust control register bits
    AdjustCR4AndCr0Bits();

    // Allocate vm regions

    uint32_t revisionId = _readmsr(IA32_VMX_BASIC);

    void* vmxon_region = kzalloc(4096, GFP_KERNEL);
   	if(vmxon_region==NULL){

		printk(KERN_INFO "Error allocating vmxon region\n");
        return;
      	//return false;
   	}

    long vmxon_phy_region = __pa(vmxon_region);
    *(uint32_t *)vmxon_region = revisionId; // set revision id

    pr_info("vmxon_region virt: %llx, phys: %llx", vmxon_region, vmxon_phy_region);

    // GP here because lockbit is set
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

    kfree(vmxon_region);
    pr_info("Freed vmx on region");

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
