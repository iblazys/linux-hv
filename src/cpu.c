#include "x86.h"
#include "cpu.h"

#include "ia32.h"


bool cpu_supports_vmx(void)
{
    cpuid_eax_01 cpu_info = { 0 };

    __get_cpuid(1, &cpu_info.cpuid_version_information.AsUInt,
        &cpu_info.cpuid_additional_information.AsUInt,
        &cpu_info.cpuid_feature_information_ecx.AsUInt,
        &cpu_info.cpuid_feature_information_edx.AsUInt);
    
     // bit 31 of ecx = hypervisor present bit
    
    if(cpu_info.cpuid_feature_information_ecx.Reserved2) 
    {
        pr_warn("linux-hv: detected a hypervisor running already");
        //return false;
    }

    if (cpu_info.cpuid_feature_information_ecx.virtual_machine_extensions == 0) 
    {
        pr_info("linux-hv: VMX is not supported on your processor.");
        return false;
    }

    // Load feature control register
    ia32_feature_control_register control = { 0 };
    control.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

    // BIOS lock checking
    if (control.lock_bit == 0)
    {
        control.lock_bit = true;
        control.enable_vmx_inside_smx = true; 

        // Write the MSR with lock bit set to 1 and EnableVmxInsideSmx to 1
        __writemsr(IA32_FEATURE_CONTROL, control.AsUInt);
    }
    else if(control.enable_vmx_outside_smx == false)
    {
        pr_err_once("VMX locked off in BIOS");
        return false;
    }

    return true;
}

void cpu_enable_vmx_operation(void)
{
    cr4 cr4;

    cr4.AsUInt = __readcr4();
    cr4.vmx_enable = true;

    __writecr4(cr4.AsUInt); //native_read_cr4 undef
}