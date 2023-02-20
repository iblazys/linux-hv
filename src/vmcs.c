#include "vmcs.h"
#include "ia32.h"
#include "vmx_asm.h"

int vmcs_allocate_vmcs_region(struct virtual_cpu* vcpu)
{
    void* vmcs_region = kzalloc(PAGE_SIZE, GFP_KERNEL);

   	if(vmcs_region == NULL)
    {
        pr_err("failed to allocate vmcs region");
        return 0;
   	}

    long vmxcs_phy_region = __pa(vmcs_region);
    uint32_t revisionId = __readmsr(IA32_VMX_BASIC);

    // set the first 30 bits to the revision id
    *(uint32_t *)vmcs_region = revisionId; 

    vcpu->vmcs_region_phys = vmxcs_phy_region;
    vcpu->vmcs_region_virt = (uint64_t)vmcs_region;

    return 1;
}

//
void vmcs_free_vmcs_region(struct virtual_cpu* vcpu)
{
    kfree((void*)vcpu->vmcs_region_virt);
}

//
void vmcs_setup_vmcs(struct virtual_cpu *vcpu)
{
    pr_info("setting up vmcs on procesor %d", vcpu->processor_id);

    // TODO: save controls in vmm_state somewhere
    vmcs_setup_controls(vcpu);

    vmcs_setup_guest(vcpu);
    vmcs_setup_host(vcpu);
}

//
void vmcs_setup_controls(struct virtual_cpu* vcpu)
{
    ia32_vmx_pinbased_ctls_register pinbased = { 0 };
    ia32_vmx_procbased_ctls_register procbased = { 0 };
    ia32_vmx_procbased_ctls2_register secondary = { 0 };
    ia32_vmx_entry_ctls_register entry = { 0 };
    ia32_vmx_exit_ctls_register exit = { 0 };

    // ------------ VM Entry Controls ------------

    entry.ia32e_mode_guest = true;

    vmcs_set_entry_controls(&entry);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entry.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    // ------------ VM Exit Controls ------------

    exit.host_address_space_size = true;

    vmcs_set_exit_controls(&exit);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, exit.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    // ------------ Procbased Controls ------------

    procbased.activate_secondary_controls = true;
    procbased.use_msr_bitmaps = true;

    vmcs_set_procbased_controls(&procbased);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procbased.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    secondary.enable_rdtscp = true;
    secondary.enable_invpcid = true;
    secondary.enable_xsaves = true;

    vmcs_set_secondary_controls(&secondary);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, secondary.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    vmcs_set_pinbased_controls(&pinbased);

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pinbased.AsUInt);

    // ------------ Other Controls ------------

    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

    /*
    An execution of MOV to CR3 in VMX non-root operation does not 
    cause a VM exit if its source operand matches one of these values
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

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, __pa(vcpu->vmm->msr_bitmap));
}

void vmcs_setup_guest(struct virtual_cpu* vcpu)
{
    segment_descriptor_register_64  gdtr = { 0 };
    segment_descriptor_register_64  idtr = { 0 };

    // TODO: save selectors to elimnate unnecessary instructions
    // Maybe move segment setup to VmcsSetupSegmentation() ?
    
    // Selectors
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, __readcs());
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, __readds());
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, __reades());
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, __readfs());
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, __readgs());
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, __readss());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, __readldtr());
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, __readtr());
    
    // Limits
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(__readcs()));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(__readds()));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(__reades()));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(__readfs()));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(__readgs()));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(__readss()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(__readldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(__readtr()));

    __sgdt(&gdtr); // Get GDTR
    __sidt(&idtr); // Get LDTR

    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.limit);
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.base_address);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.base_address);

    // Bases
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, vmcs_get_segment_base(gdtr.base_address, __readldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, vmcs_get_segment_base(gdtr.base_address, __readtr()));
    
    // Access rights
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readcs()));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readss()));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readds()));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__reades()));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readfs()));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readgs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readldtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, vmcs_get_segment_access_rights(__readtr()));
    // ------------ End Segmentation -----------------

     __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));

    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

    //__vmx_vmwrite(VMCS_GUEST_DR7, 0x400);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0); // Active state

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, (uint32_t)__readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, vcpu->rflags);
    __vmx_vmwrite(VMCS_GUEST_RSP, vcpu->rsp);
    __vmx_vmwrite(VMCS_GUEST_RIP, vcpu->rip);

    // TODO: Save this in a dedicated save_state function
    vcpu->saved_state->gdtr = gdtr;
    vcpu->saved_state->idtr = idtr;
}

void vmcs_setup_host(struct virtual_cpu *vcpu)
{
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, __reades() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, __readcs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, __readss() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, __readds() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, __readfs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, __readgs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, __readtr() & 0xF8);

    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    // TODO:
    __vmx_vmwrite(VMCS_HOST_TR_BASE, vmcs_get_segment_base(vcpu->saved_state->gdtr.base_address, __readtr()));

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, vcpu->saved_state->gdtr.base_address);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, vcpu->saved_state->idtr.base_address);

    __vmx_vmwrite(VMCS_HOST_RSP, (uint64_t)vcpu->stack + HOST_STACK_SIZE - 8);

    __vmx_vmwrite(VMCS_HOST_RIP, (uint64_t)__vmx_entrypoint);

}

uint64_t vmcs_get_segment_base(uint64_t gdt_base, uint16_t _selector)
{
    uint64_t segment_base = 0;
    segment_selector selector = { 0 };
    segment_descriptor_32* descriptor = { 0 };
    segment_descriptor_32* descriptor_table = { 0 };

    selector.AsUInt = _selector;
    
    if (selector.table == 0 && selector.index == 0)
    {
        return segment_base; // already 0;
    }

    descriptor_table = (segment_descriptor_32*)gdt_base;
    descriptor = &descriptor_table[selector.index];

    uint32_t base_high = descriptor->base_address_high << 24;
    uint32_t base_mid = descriptor->base_address_middle << 16;
    uint32_t base_low = descriptor->base_address_low;

    segment_base = (base_high | base_mid | base_low) & 0xFFFFFFFF;
    
    //
    // As mentioned in the discussion in the article, some system descriptors are expanded
    // to 16 bytes on Intel 64 architecture. We only need to pay attention to the TSS descriptors
    // and we'll use our expanded descriptor structure to adjust the segment base.
    //

    if ((descriptor->system == 0) &&
        ((descriptor->type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE) ||
            (descriptor->type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)))
    {
        segment_descriptor_64* expanded_descriptor;
        expanded_descriptor = (segment_descriptor_64*)descriptor;

        segment_base |= ((uint64_t)expanded_descriptor->base_address_upper << 32);
    }

    return segment_base;
}

uint32_t vmcs_get_segment_access_rights(uint16_t _segment_selector)
{
    segment_selector selector = { 0 };
    vmx_segment_access_rights vmx_access_rights = { 0 };

    selector.AsUInt = _segment_selector;

    //
    // Check for null selector use, if found set access right to unusable
    // and return. Otherwise, get access rights, modify format, return the
    // segment access rights.
    //
    if (selector.table == 0 && selector.index == 0) 
    {
        vmx_access_rights.AsUInt = 0;
        vmx_access_rights.unusable = true;
        return vmx_access_rights.AsUInt;
    }

    //
    // Use our custom intrinsic to store our access rights, and
    // remember that the first byte of the access rights returned
    // are not used in VMX access right format.
    //
    
    vmx_access_rights.AsUInt = (__loadar(selector.AsUInt) >> 8);
    vmx_access_rights.unusable = false;
    vmx_access_rights.Reserved1 = false;
    vmx_access_rights.Reserved2 = false;

    //vmx_access_rights.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE;
    //vmx_access_rights.granularity = true;

    return vmx_access_rights.AsUInt;
}

//
ia32_vmx_basic_register vmcs_get_basic_controls(void)
{
    // TODO: Add this to VMM State and refactor
    ia32_vmx_basic_register basic_controls = { 0 };

    basic_controls.AsUInt = __readmsr(IA32_VMX_BASIC);

    return basic_controls;
}

//
void vmcs_adjust_control_bits(uint32_t capability_msr, uint64_t* value)
{
    ia32_vmx_true_ctls_register capabilities = { 0 };

    capabilities.AsUInt = __readmsr(capability_msr);

    *value |= capabilities.allowed_0_settings;
    *value &= capabilities.allowed_1_settings;
}

//
void vmcs_set_entry_controls(ia32_vmx_entry_ctls_register* entry_controls)
{
    // TODO: save controls to elimate calls to vmcs_get_basic_controls
    ia32_vmx_basic_register basic_controls = vmcs_get_basic_controls();

    UINT32 capability_msr = basic_controls.vmx_controls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

    vmcs_adjust_control_bits(capability_msr, &entry_controls->AsUInt);
}

//
void vmcs_set_exit_controls(ia32_vmx_exit_ctls_register* exit_controls)
{
    ia32_vmx_basic_register basic_controls = vmcs_get_basic_controls();

    UINT32 capability_msr = basic_controls.vmx_controls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS;

    vmcs_adjust_control_bits(capability_msr, &exit_controls->AsUInt);
}

//
void vmcs_set_pinbased_controls(ia32_vmx_pinbased_ctls_register* pinbased_controls)
{
    ia32_vmx_basic_register basic_controls = vmcs_get_basic_controls();

    UINT32 capability_msr = basic_controls.vmx_controls ? IA32_VMX_TRUE_PINBASED_CTLS: IA32_VMX_PINBASED_CTLS;

    vmcs_adjust_control_bits(capability_msr, &pinbased_controls->AsUInt);
}

//
void vmcs_set_procbased_controls(ia32_vmx_procbased_ctls_register* procbased_controls)
{
    ia32_vmx_basic_register basic_controls = vmcs_get_basic_controls();

    UINT32 capability_msr = basic_controls.vmx_controls ? IA32_VMX_TRUE_PROCBASED_CTLS: IA32_VMX_PROCBASED_CTLS;

    vmcs_adjust_control_bits(capability_msr, &procbased_controls->AsUInt);
}

//
void vmcs_set_secondary_controls(ia32_vmx_procbased_ctls2_register* secondary_controls)
{
    UINT32 capability_msr = IA32_VMX_PROCBASED_CTLS2;

    vmcs_adjust_control_bits(capability_msr, &secondary_controls->AsUInt);
}
