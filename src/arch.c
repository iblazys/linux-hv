#include "arch.h"

#include <asm/errno.h> //
#include <asm/special_insns.h> // native_read_cr funcs

#include "asmdefs.h"
#include "../ia32-doc/out/ia32.h"

bool CpuHasVmxSupport(void)
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
    //Control.AsUInt = __rdmsr(IA32_FEATURE_CONTROL);

    pr_info("Lock Bit: %d", Control.LockBit);
    pr_info("EnableVmxInsideSmx: %d", Control.EnableVmxInsideSmx);
    pr_info("EnableVmxOutsideSmx: %d", Control.EnableVmxOutsideSmx);

    // BIOS lock checking
    if (Control.LockBit == 0)
    {
        Control.LockBit = true;
        Control.EnableVmxInsideSmx = true; 

        // Write the MSR with lock bit set to 1 and EnableVmxInsideSmx to 1
        _writemsr(IA32_FEATURE_CONTROL, Control.AsUInt);
    }
    else if(Control.EnableVmxOutsideSmx == false)
    {
        pr_err_once("VMX locked off in BIOS");
        return false;
    }
    
    return true;
}

// TODO: Remove duplicate code
bool CpuEnableVmxOperation(void)
{
    CR4 cr4;
    cr4.AsUInt = native_read_cr4();
    cr4.VmxEnable = true;

    _writecr4(cr4.AsUInt); //native_read_cr4 undef

    return true;
}

// TODO: Remove duplicate code
bool CpuDisableVmxOperation(void)
{
    CR4 cr4;
    cr4.AsUInt = native_read_cr4();
    cr4.VmxEnable = false;

    _writecr4(cr4.AsUInt);

    return true;
}
