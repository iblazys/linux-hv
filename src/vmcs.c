#include "vmcs.h"

#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags

#include "../ia32-doc/out/ia32.h"
#include "asmdefs.h"

bool VmcsInitRegion(GUEST_CPU_STATE *vcpu)
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
    vcpu->VmcsRegionVirtualAddress = (uint64_t)vmcs_region;

    return true;
}

void VmcsSetupControls()
{
    //IA32_VMX_PINBASED_CTLS_REGISTER PinbasedControls = { 0 };
    //IA32_VMX_PROCBASED_CTLS_REGISTER ProcbasedControls = { 0 };
    //IA32_VMX_PROCBASED_CTLS2_REGISTER SecondaryControls = { 0 };
    IA32_VMX_ENTRY_CTLS_REGISTER EntryControls = { 0 };
    //IA32_VMX_EXIT_CTLS_REGISTER ExitControls = { 0 };

    // ------------ VM Entry Controls ------------

    EntryControls.Ia32EModeGuest = true;

    SetEntryControls(&EntryControls);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, EntryControls.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    // ------------ VM Exit Controls ------------
}

IA32_VMX_BASIC_REGISTER GetBasicControls()
{
    // TODO: Add this to VMM State and refactor?
    IA32_VMX_BASIC_REGISTER BasicControls = { 0 };

    BasicControls.AsUInt = _readmsr(IA32_VMX_BASIC);

    return BasicControls;
}

void AdjustControlBits(UINT32 CapabilityMSR, UINT64* Value)
{
    IA32_VMX_TRUE_CTLS_REGISTER Capabilities = { 0 };

    Capabilities.AsUInt = _readmsr(CapabilityMSR);

    *Value |= Capabilities.Allowed0Settings;
    *Value &= Capabilities.Allowed1Settings;
}

void SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* entryControls) 
{
    IA32_VMX_BASIC_REGISTER basicControls = GetBasicControls();

    UINT32 CapabilityMSR = basicControls.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

    AdjustControlBits(CapabilityMSR, &entryControls->AsUInt);
}
