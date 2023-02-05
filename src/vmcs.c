#include "vmcs.h"

#include <linux/slab.h> // kalloc
#include <linux/gfp.h> // kalloc flags

#include "../ia32-doc/out/ia32.h"
#include "asmdefs.h"

bool VmcsInitRegion(VIRTUAL_CPU *vcpu)
{
    void* vmcs_region = kzalloc(PAGE_SIZE, GFP_KERNEL);

   	if(vmcs_region == NULL)
    {
        pr_err("failed to allocate vmcs region");
        return false;
   	}

    long vmxcs_phy_region = __pa(vmcs_region);
    uint32_t revisionId = __readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmcs_region = revisionId; 

    vcpu->VmcsRegionPhysicalAddress = vmxcs_phy_region;
    vcpu->VmcsRegionVirtualAddress = (uint64_t)vmcs_region;

    return true;
}

bool VmcsLoad(void *vmcsPhysAddr)
{
    uint8_t result;

    if(result = __vmx_vmptrld(vmcsPhysAddr))
    {
        pr_err("failed to load vmcs addr[%llx] with error %d", vmcsPhysAddr, result);
        return false;
    }
    
    return true;
}

bool VmcsClear(void *vmcsPhysAddr)
{
    uint8_t result;

    if(result = __vmx_vmclear(vmcsPhysAddr))
    {
        pr_err("failed to clear vmcs addr[%llx] with error %d", vmcsPhysAddr, result);
        return false;
    }
    
    return true;
}

//
//
//
void VmcsSetup(VIRTUAL_CPU* currentvCpu)
{
    pr_info("begin vmcs setup on vcpu[%d]", currentvCpu->ProcessorId);

    // todo error checking

    VmcsSetupControls();
    VmcsSetupGuest(currentvCpu); // pass vmm to save gdt and ldt
    VmcsSetupHost(currentvCpu);
}

//
//
//
void VmcsSetupControls()
{
    IA32_VMX_PINBASED_CTLS_REGISTER PinbasedControls = { 0 };
    IA32_VMX_PROCBASED_CTLS_REGISTER ProcbasedControls = { 0 };
    IA32_VMX_PROCBASED_CTLS2_REGISTER SecondaryControls = { 0 };
    IA32_VMX_ENTRY_CTLS_REGISTER EntryControls = { 0 };
    IA32_VMX_EXIT_CTLS_REGISTER ExitControls = { 0 };

    // ------------ VM Entry Controls ------------

    EntryControls.Ia32EModeGuest = true;

    SetEntryControls(&EntryControls);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, EntryControls.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    //__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);

    // ------------ VM Exit Controls ------------

    ExitControls.HostAddressSpaceSize = true;

    SetExitControls(&ExitControls);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, ExitControls.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    // ------------ Procbased Controls ------------

    ProcbasedControls.ActivateSecondaryControls = true;
    //ProcbasedControls.UseMsrBitmaps = TRUE;

    SetProcbasedControls(&ProcbasedControls);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ProcbasedControls.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    //SecondaryControls.EnableEpt = fa; // testing

    //SecondaryControls.EnableRdtscp = TRUE;
    //SecondaryControls.EnableInvpcid = TRUE;
    //SecondaryControls.EnableXsaves = TRUE;

    SetSecondaryControls(&SecondaryControls);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, SecondaryControls.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    SetPinbasedControls(&PinbasedControls);

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, PinbasedControls.AsUInt);

    // ------------ Other Controls ------------

    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

    /*
    * An execution of MOV to CR3 in VMX non-root operation does not cause a VM exit if its source operand matches one of these values
    */
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_0, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_1, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_2, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_3, 0);

    // testing
    __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0);
    __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);
    // end testing

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, 0);
}

//
//
//
void VmcsSetupGuest(VIRTUAL_CPU* currentvCpu)
{
    SEGMENT_DESCRIPTOR_REGISTER_64  Gdtr = { 0 };
    SEGMENT_DESCRIPTOR_REGISTER_64  Idtr = { 0 };

    // TODO: save selectors to elimnate unnecessary instructions

    // Maybe move segment setup to VmcsSetupSegmentation() ?
    
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

    // Bases
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _getes()));
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _getcs()));
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _getss()));
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _getds()));
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _getldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, VmcsGetSegmentBase(Gdtr.BaseAddress, _gettr()));

    // Access Rights
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getcs()));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getss()));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getds()));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getes()));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getfs()));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getgs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_getldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, VmcsGetSegmentAccessRights(_gettr()));
    // ------------ End Segmentation -----------------
    
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0); // Active state

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, currentvCpu->RFlags); // rflags are saved in virtsinglecpu

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_GUEST_RSP, currentvCpu->RSP);
    __vmx_vmwrite(VMCS_GUEST_RIP, currentvCpu->RIP);

    // TODO: Save these somewhere else
    currentvCpu->CpuState.Gdtr = Gdtr;
    currentvCpu->CpuState.Idtr = Idtr;
}

//
//
//
void VmcsSetupHost(VIRTUAL_CPU *currentvCpu)
{
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, _getes() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, _getcs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, _getss() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, _getds() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, _getfs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, _getgs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, _gettr() & 0xF8);

    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_HOST_TR_BASE, VmcsGetSegmentBase(currentvCpu->CpuState.Gdtr.BaseAddress, _gettr()));

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, currentvCpu->CpuState.Gdtr.BaseAddress);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, currentvCpu->CpuState.Idtr.BaseAddress);

    pr_err("did you allocate vmexitstack ptr?");
    __vmx_vmwrite(VMCS_HOST_RSP, (uint64_t)currentvCpu->VmExitHandler);
    __vmx_vmwrite(VMCS_HOST_RIP, (uint64_t)&currentvCpu->VmExitStack);

    //err |= hv_arch_vmwrite(VMCS_HOST_RIP, (u64)cpu->vmexit_handler);
    //err |= hv_arch_vmwrite(VMCS_HOST_RSP, (u64)&cpu->vmexit_stack->cpu);
}

uint64_t VmcsGetSegmentBase(uint64_t GdtBase, uint16_t SegmentSelector)
{
    uint64_t SegmentBase = 0;
    SEGMENT_SELECTOR Selector = { 0 };
    SEGMENT_DESCRIPTOR_32* Descriptor = { 0 };
    SEGMENT_DESCRIPTOR_32* DescsriptorTable = { 0 };

    Selector.AsUInt = SegmentSelector;

    if (Selector.Table == 0 && Selector.Index == 0)
    {
        return SegmentBase; // already 0;
    }

    DescsriptorTable = (SEGMENT_DESCRIPTOR_32*)GdtBase;
    Descriptor = &DescsriptorTable[Selector.Index];

    uint32_t BaseHigh = Descriptor->BaseAddressHigh << 24;
    uint32_t BaseMid = Descriptor->BaseAddressMiddle << 16;
    uint32_t BaseLow = Descriptor->BaseAddressLow;

    SegmentBase = (BaseHigh | BaseMid | BaseLow) & 0xFFFFFFFF;
    
    //
    // As mentioned in the discussion in the article, some system descriptors are expanded
    // to 16 bytes on Intel 64 architecture. We only need to pay attention to the TSS descriptors
    // and we'll use our expanded descriptor structure to adjust the segment base.
    //

    if ((Descriptor->System == 0) &&
        ((Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE) ||
            (Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)))
    {
        SEGMENT_DESCRIPTOR_64* ExpandedDescriptor;
        ExpandedDescriptor = (SEGMENT_DESCRIPTOR_64*)Descriptor;

        SegmentBase |= ((uint64_t)ExpandedDescriptor->BaseAddressUpper << 32);
    }

    return SegmentBase;
}

uint32_t VmcsGetSegmentAccessRights(uint16_t SegmentSelector)
{
    SEGMENT_SELECTOR Selector = { 0 };
    VMX_SEGMENT_ACCESS_RIGHTS VmxAccessRights = { 0 };

    Selector.AsUInt = SegmentSelector;

    //
    // Check for null selector use, if found set access right to unusable
    // and return. Otherwise, get access rights, modify format, return the
    // segment access rights.
    //
    if (Selector.Table == 0 && Selector.Index == 0) 
    {
        VmxAccessRights.AsUInt = 0;
        VmxAccessRights.Unusable = true;
        return VmxAccessRights.AsUInt;
    }

    //
    // Use our custom intrinsic to store our access rights, and
    // remember that the first byte of the access rights returned
    // are not used in VMX access right format.
    //
    
    VmxAccessRights.AsUInt = (__load_ar(Selector.AsUInt) >> 8);
    VmxAccessRights.Unusable = 0;
    VmxAccessRights.Reserved1 = 0;
    VmxAccessRights.Reserved2 = 0;

    return VmxAccessRights.AsUInt;
}

//
//
IA32_VMX_BASIC_REGISTER GetBasicControls()
{
    // TODO: Add this to VMM State and refactor?
    IA32_VMX_BASIC_REGISTER BasicControls = { 0 };

    BasicControls.AsUInt = __readmsr(IA32_VMX_BASIC);

    return BasicControls;
}

//
//
void AdjustControlBits(UINT32 CapabilityMSR, UINT64* Value)
{
    IA32_VMX_TRUE_CTLS_REGISTER Capabilities = { 0 };

    Capabilities.AsUInt = __readmsr(CapabilityMSR);

    *Value |= Capabilities.Allowed0Settings;
    *Value &= Capabilities.Allowed1Settings;
}

//
//
//
void SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* entryControls) 
{
    IA32_VMX_BASIC_REGISTER basicControls = GetBasicControls();

    UINT32 CapabilityMSR = basicControls.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

    AdjustControlBits(CapabilityMSR, &entryControls->AsUInt);
}

//
//
void SetExitControls(IA32_VMX_EXIT_CTLS_REGISTER *exitControls)
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS;

    AdjustControlBits(CapabilityMSR, &exitControls->AsUInt);
}

//
//
void SetPinbasedControls(IA32_VMX_PINBASED_CTLS_REGISTER *PinbasedControls)
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS;

    AdjustControlBits(CapabilityMSR, &PinbasedControls->AsUInt);
}

//
//
void SetProcbasedControls(IA32_VMX_PROCBASED_CTLS_REGISTER *ProcbasedControls)
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;

    AdjustControlBits(CapabilityMSR, &ProcbasedControls->AsUInt);
}

//
//
void SetSecondaryControls(IA32_VMX_PROCBASED_CTLS2_REGISTER *SecondaryControls)
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = IA32_VMX_PROCBASED_CTLS2;

    AdjustControlBits(CapabilityMSR, &SecondaryControls->AsUInt);
}
