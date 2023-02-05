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

void VmcsSetup()
{
    VmcsSetupControls();
    VmcsSetupGuest(); // pass vmm to save gdt and ldt
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

void VmcsSetupGuest()
{
    // TODO: Save these
    SEGMENT_DESCRIPTOR_REGISTER_64  Gdtr = { 0 };
    SEGMENT_DESCRIPTOR_REGISTER_64  Idtr = { 0 };

    // need to write asm selectors for Fs, Gs, Ss etc
    
    // Selectors
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, _getcs());
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, _getds());
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, _getes());
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, _getfs());
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, _getgs());
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, _getss());
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, _getds());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, _getldtr());
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, _gettr());

    // Limits
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(_getcs()));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(_getds()));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(_getes()));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(_getfs()));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(_getgs()));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(_getss()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(_getldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(_gettr()));

    _sgdt(&Gdtr); // Get GDTR
    _sidt(&Idtr); // Get LDTR

    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, Gdtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, Idtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, Gdtr.BaseAddress);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, Idtr.BaseAddress);

    pr_info("gdtr base 0x%x, limit: 0x%x", Gdtr.BaseAddress, Gdtr.Limit);
    pr_info("idtr base 0x%x, limit: 0x%x", Gdtr.BaseAddress, Gdtr.Limit);

    //__sidt(Idtr);

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
