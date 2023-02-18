#include "validate.h"

void validate_guest_entry_state(void)
{
    // WHY INTEL.... WHY

    vmentry_interrupt_information interrupt_info;
    ia32_vmx_entry_ctls_register entry_controls;
    ia32_vmx_pinbased_ctls_register pinbased_controls;
    ia32_vmx_procbased_ctls_register procbased_controls;
    ia32_vmx_procbased_ctls2_register secondary_controls;

    rflags rflags;

    bool unrestricted_guest;

    rflags.AsUInt = vmread(VMCS_GUEST_RFLAGS);

    interrupt_info.AsUInt = vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD);
    entry_controls.AsUInt = vmread(VMCS_CTRL_VMENTRY_CONTROLS);
    pinbased_controls.AsUInt = vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS);
    procbased_controls.AsUInt = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    secondary_controls.AsUInt = vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    unrestricted_guest = ((procbased_controls.activate_secondary_controls == 1) &&
                         (secondary_controls.unrestricted_guest == 1));

    //
    // 26.3.1.1 Checks on Guest Control Registers, Debug Registers, and MSRs
    //

    cr0 cr0 = { 0 };
    cr4 cr4 = { 0 };

    ia32_debugctl_register debug_controls;

    cr0.AsUInt = vmread(VMCS_GUEST_CR0);
    cr4.AsUInt = vmread(VMCS_GUEST_CR4);

    // The CR0 field must not set any bit to a value not supported in VMX operation (see Section 24.8).
    ASSERT(cr0.AsUInt == validate_adjust_guest_cr0(cr0).AsUInt);
    
    // Bit 0 (corresponding to CR0.PE) and bit 31 (PG) are not checked if the “unrestricted guest” VM-execution
    // control is 1
    if ((cr0.paging_enable == 1) && (unrestricted_guest == false))
    {
        ASSERT(cr0.protection_enable == 1);
    }

    // The CR4 field must not set any bit to a value not supported in VMX operation (see Section 24.8).
    ASSERT(cr4.AsUInt == validate_adjust_guest_cr4(cr4).AsUInt);

    // If bit 23 in the CR4 field (corresponding to CET) is 1, bit 16 in the
    // CR0 field (WP) must also be 1.
    if(cr4.control_flow_enforcement_enable == 1)
    {
        ASSERT(cr0.write_protect == 1);
    }

    // If the “load debug controls” VM-entry control is 1, bits reserved in the msr must be 0.
    if (entry_controls.load_debug_controls == 1)
    {
        debug_controls.AsUInt = vmread(VMCS_GUEST_DEBUGCTL);
        ASSERT(debug_controls.Reserved1 == 0);
        ASSERT(debug_controls.Reserved2 == 0);
    }

    //
    // The following checks are performed on processors that support Intel 64 architecture.
    //

    // If the “IA-32e mode guest” VM-entry control is 1, bit 31 in the CR0 field (corresponding to CR0.PG)
    // and bit 5 in the CR4 field (corresponding to CR4.PAE) must each be 1.
    if (entry_controls.ia32e_mode_guest == 1)
    {
        ASSERT(cr0.paging_enable == 1);
        ASSERT(cr4.physical_address_extension == 1);
    }

    // The CR3 field must be such that bits 63:52 and bits in the range 51:32 beyond the processor’s 
    // physical address width are 0.
    // TODO

    // If the “load debug controls” VM-entry control is 1, bits 63:32 in the DR7 field must be 0. The first processors
    // to support the virtual-machine extensions supported only the 1-setting of this control and thus performed
    // this check unconditionally
    if (entry_controls.load_debug_controls == 1)
    {
        dr7 dr7;

        dr7.AsUInt = vmread(VMCS_GUEST_DR7);
        ASSERT(dr7.Reserved4 == 0);
    }

    // The IA32_SYSENTER_ESP field and the IA32_SYSENTER_EIP field must each contain a canonical address
    // see 3.3.7 Address Calculations in 64-Bit Mode
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;

    sysenter_esp = __readmsr(IA32_SYSENTER_ESP);
    sysenter_eip = __readmsr(IA32_SYSENTER_EIP);

    validate_is_canonical_address((void*)sysenter_esp, __FILE__, __LINE__);
    validate_is_canonical_address((void*)sysenter_eip, __FILE__, __LINE__);

/*
    if(!is_canonical_address((void*)sysenter_eip, __FILE__, __LINE__))
    {
        pr_info("ADDRESS NOT CANONICAL: sysenter_esp: 0x%llx", sysenter_esp);
        ASSERT(false);
    }

    if(!is_canonical_address((void*)sysenter_esp, __FILE__, __LINE__))
    {
        pr_info("ADDRESS NOT CANONICAL: sysenter_eip: 0x%llx", sysenter_eip);
        ASSERT(false);
    }
*/

    // If the “load CET state” VM-entry control is 1, the IA32_S_CET field and the
    // IA32_INTERRUPT_SSP_TABLE_ADDR field must contain canonical addresses.
    ASSERT(entry_controls.load_cet_state == 0);

    //
    // End of checks performed on processors that support Intel 64 architecture.
    //

    // If the “load IA32_PERF_GLOBAL_CTRL” VM-entry control is 1, bits reserved in 
    // the IA32_PERF_GLOBAL_CTRL MSR must be 0 in the field for that register (see Figure 20-3).
    ASSERT(entry_controls.load_ia32_perf_global_ctrl == 0);


    // If the “load IA32_PAT” VM-entry control is 1, the value of the field for the IA32_PAT MSR must be one that could
    // be written by WRMSR without fault at CPL 0. Specifically, each of the 8 bytes in the field must have one of the
    // values 0 (UC), 1 (WC), 4 (WT), 5 (WP), 6 (WB), or 7 (UC-).
    // TODO

    // If the “load IA32_EFER” VM-entry control is 1 ...
    if (entry_controls.load_ia32_efer == 1)
    {
        ia32_efer_register efer;

        // Bits reserved in the IA32_EFER MSR must be 0.
        efer.AsUInt = vmread(VMCS_GUEST_EFER);
        ASSERT(efer.Reserved1 == 0);
        ASSERT(efer.Reserved2 == 0);
        ASSERT(efer.Reserved3 == 0);

        // Bit 10 (corresponding to IA32_EFER.LMA) must equal the value of the “IA-32e mode guest” VM-entry
        // control.
        ASSERT(efer.ia32e_mode_active == entry_controls.ia32e_mode_guest);

        // It must also be identical to bit 8 (LME) if bit 31 in the CR0 field (corresponding to CR0.PG) is 1.
        if (cr0.paging_enable == 1)
        {
            ASSERT(efer.ia32e_mode_active == efer.ia32e_mode_enable);
        }
    }

    //
    // If the “load IA32_BNDCFGS” VM-entry control is 1,
    //
    ASSERT(entry_controls.load_ia32_bndcfgs == 0);

    //
    // If the “load IA32_RTIT_CTL” VM-entry control is 1,
    //
    ASSERT(entry_controls.load_ia32_rtit_ctl == 0);

    //
    // If the “load CET state” VM-entry control is 1,
    //
    ASSERT(entry_controls.load_cet_state == 0);

    // If the “load guest IA32_LBR_CTL” VM-entry control is 1, bits reserved in the IA32_LBR_CTL MSR must be 0 in
    // the field for that register
    ASSERT(entry_controls.load_ia32_lbr_ctl == 0);

    // If the “load PKRS” VM-entry control is 1, bits 63:32 must be 0 in the IA32_PKRS field
    ASSERT(entry_controls.load_ia32_pkrs == 0);
    
    // If the “load UINV” VM-entry control is 1, bits 15:8 must be 0 in the guest UINV field.
    // TODO - not in ia32.h yet, need to check which bit it is



    //
    // 26.3.1.2 Checks on Guest Segment Registers
    //

    // This section specifies the checks on the fields for CS, SS, DS, ES, FS, GS, TR, and LDTR
    
    segment_selector selector;
    vmx_segment_access_rights accessRights;
    uint32_t segmentLimit;
    
    // Selectors ...

    // TR - The TI flag (bit 2) must be 0
    selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_TR_SELECTOR);
    ASSERT(selector.table == 0);

    // LDTR - If LDTR is usable, the TI flag (bit 2) must be 0.
    accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    if (accessRights.unusable == 0)
    {
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_LDTR_SELECTOR);
        ASSERT(selector.table == 0);
    }

    // SS - If the guest will not be virtual-8086 and the “unrestricted guest” VM-execution control is 0, the RPL
    // (bits 1:0) must equal the RPL of the selector field for CS
    if ((rflags.virtual_8086_mode_flag == 0) &&
        (unrestricted_guest == false))
    {
        segment_selector selectorCs;

        selectorCs.AsUInt = (uint16_t)vmread(VMCS_GUEST_CS_SELECTOR);
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_SS_SELECTOR);
        ASSERT(selector.request_privilege_level == selectorCs.request_privilege_level);
    }

    // Base addresses ...

    // If the guest will be virtual-8086, the address must be the selector field 
    // shifted left 4 bits (multiplied by 16)
    if (rflags.virtual_8086_mode_flag == 1)
    {
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_CS_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_CS_BASE) == ((uint64_t)selector.index << 4));
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_SS_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_SS_BASE) == ((uint64_t)selector.index << 4));
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_DS_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_DS_BASE) == ((uint64_t)selector.index << 4));
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_ES_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_ES_BASE) == ((uint64_t)selector.index << 4));
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_FS_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_FS_BASE) == ((uint64_t)selector.index << 4));
        selector.AsUInt = (uint16_t)vmread(VMCS_GUEST_GS_SELECTOR);
        ASSERT(vmread(VMCS_GUEST_GS_BASE) == ((uint64_t)selector.index << 4));
    }

    //
    // The following checks are performed on processors that support Intel 64
    // architecture:
    //

        // TR, FS, GS. The address must be canonical.
        uint64_t base_address;

        base_address = __readmsr(VMCS_GUEST_TR_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        base_address = __readmsr(VMCS_GUEST_FS_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        base_address = __readmsr(VMCS_GUEST_GS_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        // LDTR. If LDTR is usable, the address must be canonical
        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

        if(accessRights.unusable == 0)
        {
            base_address = __readmsr(VMCS_GUEST_LDTR_BASE);
            validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);
        }

        // CS. Bits 63:32 of the address must be zero.
        base_address = __readmsr(VMCS_GUEST_CS_BASE);    
        ASSERT((base_address >> 32) == 0);

        // SS, DS, ES. If the register is usable, bits 63:32 of the address must be zero.
        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = __readmsr(VMCS_GUEST_SS_BASE);
            ASSERT((base_address >> 32) == 0);
        }

        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = __readmsr(VMCS_GUEST_DS_BASE);
            ASSERT((base_address >> 32) == 0);
        }

        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = __readmsr(VMCS_GUEST_ES_BASE);
            ASSERT((base_address >> 32) == 0);
        }

    //
    // End of checks performed on processors that support Intel 64 architecture.
    //

    // Limit fields for CS, SS, DS, ES, FS, GS. If the guest will be virtual-8086, the field must be 0000FFFFH
    if (rflags.virtual_8086_mode_flag == 1)
    {
        ASSERT(vmread(VMCS_GUEST_CS_LIMIT) == 0xffff);
        ASSERT(vmread(VMCS_GUEST_SS_LIMIT) == 0xffff);
        ASSERT(vmread(VMCS_GUEST_DS_LIMIT) == 0xffff);
        ASSERT(vmread(VMCS_GUEST_ES_LIMIT) == 0xffff);
        ASSERT(vmread(VMCS_GUEST_FS_LIMIT) == 0xffff);
        ASSERT(vmread(VMCS_GUEST_GS_LIMIT) == 0xffff);
    }

    // Access Rights

    // If the guest will be virtual-8086, the field must be 000000F3H.
    if (rflags.virtual_8086_mode_flag == 1)
    {
        ASSERT(vmread(VMCS_GUEST_CS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(vmread(VMCS_GUEST_SS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(vmread(VMCS_GUEST_DS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(vmread(VMCS_GUEST_ES_ACCESS_RIGHTS) == 0xf3);
        ASSERT(vmread(VMCS_GUEST_FS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(vmread(VMCS_GUEST_GS_ACCESS_RIGHTS) == 0xf3);
    }
    else
    {
    // If the guest will not be virtual-8086, the different sub-fields are considered separately
    
        validate_segment_access_rights(SegmentCs,
                                (uint32_t)vmread(VMCS_GUEST_CS_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_CS_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_CS_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentSs,
                                (uint32_t)vmread(VMCS_GUEST_SS_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_SS_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_SS_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentDs,
                                (uint32_t)vmread(VMCS_GUEST_DS_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_DS_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_DS_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentEs,
                                (uint32_t)vmread(VMCS_GUEST_ES_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_ES_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_ES_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentFs,
                                (uint32_t)vmread(VMCS_GUEST_FS_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_FS_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_FS_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentGs,
                                (uint32_t)vmread(VMCS_GUEST_GS_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_GS_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_GS_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);
    }

    //
    // TR
    //
    accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);
    segmentLimit = (uint32_t)vmread(VMCS_GUEST_TR_LIMIT);
    if (entry_controls.ia32e_mode_guest == 0)
    {
        ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                  (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED));
    }
    else
    {
        ASSERT(accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED);
    }
    ASSERT(accessRights.descriptor_type == 0);
    ASSERT(accessRights.present == 1);
    ASSERT(accessRights.Reserved1 == 0);
    ASSERT(accessRights.Reserved2 == 0);
    if (!MV_IS_FLAG_SET(segmentLimit, 0xfff))
    {
        ASSERT(accessRights.granularity == 0);
    }
    if (MV_IS_FLAG_SET(segmentLimit, 0xfff00000))
    {
        ASSERT(accessRights.granularity == 1);
    }
    ASSERT(accessRights.unusable == 0);

    //
    // LDTR
    //
    accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    if (accessRights.unusable == 0)
    {
        segmentLimit = (uint32_t)vmread(VMCS_GUEST_LDTR_LIMIT);
        ASSERT(accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE);
        ASSERT(accessRights.descriptor_type == 0);
        ASSERT(accessRights.present == 1);
        ASSERT(accessRights.Reserved1 == 0);
        ASSERT(accessRights.Reserved2 == 0);
        if (!MV_IS_FLAG_SET(segmentLimit, 0xfff))
        {
            ASSERT(accessRights.granularity == 0);
        }
        if (MV_IS_FLAG_SET(segmentLimit, 0xfff00000))
        {
            ASSERT(accessRights.granularity == 1);
        }
    }

    //
    // 26.3.1.3 Checks on Guest Descriptor-Table Registers
    //
    // ------------ TODO ------------

    //
    // 26.3.1.4 Checks on Guest RIP, RFLAGS, and SSP
    //
    vmx_segment_access_rights csAccessRights;

    csAccessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    if ((entry_controls.ia32e_mode_guest == 0) ||
        (csAccessRights.long_mode == 0))
    {
        ASSERT((vmread(VMCS_GUEST_RIP) & ~__UINT16_MAX__) == 0);
    }

    ASSERT(rflags.Reserved1 == 0);
    ASSERT(rflags.Reserved2 == 0);
    ASSERT(rflags.Reserved3 == 0);
    ASSERT(rflags.Reserved4 == 0);
    ASSERT(rflags.read_as_1 == 1);
    if ((interrupt_info.valid == 1) &&
        (interrupt_info.interruption_type == external_interrupt))
    {
        ASSERT(rflags.interrupt_enable_flag == 1);
    }

    //
    // 26.3.1.5 Checks on Guest Non-Register State
    //
    vmx_interruptibility_state interruptibilityState;
    vmx_guest_activity_state activityState;
    vmx_segment_access_rights ssAccessRights;

    ssAccessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    activityState = vmread(VMCS_GUEST_ACTIVITY_STATE);
    interruptibilityState.AsUInt = (uint32_t)vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    //
    // Activity state
    //
    ASSERT((activityState == vmx_active) ||
              (activityState == vmx_hlt) ||
              (activityState == vmx_shutdown) ||
              (activityState == vmx_wait_for_sipi));
    if (ssAccessRights.descriptor_privilege_level != 0)
    {
        ASSERT(activityState != vmx_hlt);
    }
    if ((interruptibilityState.blocking_by_sti == 1) ||
        (interruptibilityState.blocking_by_mov_ss == 1))
    {
        ASSERT(activityState != vmx_active);
    }

    if (interrupt_info.valid == 1)
    {
        if (activityState == vmx_hlt)
        {
            if ((interrupt_info.interruption_type == external_interrupt) ||
                (interrupt_info.interruption_type == non_maskable_interrupt))
            {
                ;
            }
            else if ((interrupt_info.interruption_type == hardware_exception) &&
                     ((interrupt_info.vector == debug) ||
                      (interrupt_info.vector == machine_check)))
            {
                ;
            }
            else if ((interrupt_info.interruption_type == other_event) &&
                     (interrupt_info.vector == 0 /* pending MTF VM exit */ ))
            {
                ;
            }
            else
            {
                ASSERT(false);
            }
        }
        else if (activityState == vmx_shutdown)
        {
            ASSERT((interrupt_info.vector == nmi) ||
                      (interrupt_info.vector == machine_check));
        }
        else if (activityState == vmx_wait_for_sipi)
        {
            ASSERT(false);
        }
    }
    if (entry_controls.entry_to_smm == 1)
    {
        ASSERT(activityState != vmx_wait_for_sipi);
    }

    //
    // Interruptibility state
    //
    ASSERT(interruptibilityState.Reserved1 == 0);
    ASSERT((interruptibilityState.blocking_by_sti == false) ||
              (interruptibilityState.blocking_by_mov_ss == false));

    if (rflags.interrupt_enable_flag == 0)
    {
        ASSERT(interruptibilityState.blocking_by_sti == 0);
    }
    if ((interrupt_info.valid == 1) &&
        ((interrupt_info.interruption_type == external_interrupt) ||
         (interrupt_info.interruption_type == non_maskable_interrupt)))
    {
        ASSERT(interruptibilityState.blocking_by_sti == 0);
        ASSERT(interruptibilityState.blocking_by_mov_ss == 0);
    }
    ASSERT(interruptibilityState.blocking_by_smi == 0);
    if (entry_controls.entry_to_smm == 1)
    {
        ASSERT(interruptibilityState.blocking_by_smi == 1);
    }
    if ((pinbased_controls.virtual_nmi == 1) &&
        (interrupt_info.valid == 1) &&
        (interrupt_info.interruption_type == non_maskable_interrupt))
    {
        ASSERT(interruptibilityState.blocking_by_nmi == 0);
    }
    if (interruptibilityState.enclave_interruption == 1)
    {
        ASSERT(interruptibilityState.blocking_by_mov_ss == 0);
    }

    //
    // Pending debug exceptions checks not implemented
    // VMCS link pointer checks not implemented
    //
        // TODO

    //
    // 26.3.1.6 Checks on Guest Page-Directory-Pointer-Table Entries
    //
    if ((cr0.paging_enable == 1) &&
        (cr4.physical_address_extension == 1) &&
        (entry_controls.ia32e_mode_guest == 0))
    {
        // Those checks are not implemented.

        // TODO
    }
}

/**
 * @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied.
 *
 * @param cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
cr0 validate_adjust_cr0(cr0 _cr0)
{
    cr0 newCr0, fixed0Cr0, fixed1Cr0;

    newCr0 = _cr0;
    fixed0Cr0.AsUInt = __readmsr(IA32_VMX_CR0_FIXED0);
    fixed1Cr0.AsUInt = __readmsr(IA32_VMX_CR0_FIXED1);
    newCr0.AsUInt &= fixed1Cr0.AsUInt;
    newCr0.AsUInt |= fixed0Cr0.AsUInt;
    return newCr0;
}

/**
 * @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied
 *      for the guest.
 *
 * @param Cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
cr0 validate_adjust_guest_cr0(cr0 _cr0)
{
    cr0 new_cr0;
    ia32_vmx_procbased_ctls2_register secondary_controls;

    new_cr0 = validate_adjust_cr0(_cr0);

    //
    // When the UnrestrictedGuest bit is set, ProtectionEnable and PagingEnable
    // bits are allowed to be zero. Make this adjustment, by setting them 1 only
    // when the guest did indeed requested them to be 1 (ie,
    // Cr0.ProtectionEnable == 1) and the FIXED0 MSR indicated them to be 1 (ie,
    // newCr0.ProtectionEnable == 1).
    //
    secondary_controls.AsUInt = vmread(
                    VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if (secondary_controls.unrestricted_guest != false)
    {
        new_cr0.protection_enable &= _cr0.protection_enable;
        new_cr0.paging_enable &= _cr0.paging_enable;
    }

    return new_cr0;
}

cr4 validate_adjust_cr4(cr4 _cr4)
{
    cr4 newCr4, fixed0Cr4, fixed1Cr4;

    newCr4 = _cr4;
    fixed0Cr4.AsUInt = __readmsr(IA32_VMX_CR4_FIXED0);
    fixed1Cr4.AsUInt = __readmsr(IA32_VMX_CR4_FIXED1);
    newCr4.AsUInt &= fixed1Cr4.AsUInt;
    newCr4.AsUInt |= fixed0Cr4.AsUInt;
    return newCr4;
}

cr4 validate_adjust_guest_cr4(cr4 _cr4)
{
    return validate_adjust_cr4(_cr4);
}

void validate_segment_access_rights(segment_type segment_type,
    uint32_t access_rights_as_uint32,
    uint32_t segment_limit,
    uint16_t segment_selector_as_uint16,
    bool ia32e_mode_guest,
    bool unrestricted_guest)
{
    segment_selector selector;
    vmx_segment_access_rights accessRights;
    vmx_segment_access_rights accessRightsSs;
    vmx_segment_access_rights accessRightsCs;
    cr0 cr0;

    selector.AsUInt = segment_selector_as_uint16;
    accessRights.AsUInt = access_rights_as_uint32;
    accessRightsSs.AsUInt = (uint32_t)vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    accessRightsCs.AsUInt = (uint32_t)vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    cr0.AsUInt = vmread(VMCS_GUEST_CR0);

    //
    // Bits 3:0 (Type)
    //
    switch (segment_type)
    {
        case SegmentCs:

        if (unrestricted_guest == false)
        {
            ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        else
        {
            ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                      (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        break;

        case SegmentSs:

        if (unrestricted_guest == false)
        {
            ASSERT(accessRights.descriptor_privilege_level == selector.request_privilege_level);
        }
        if ((accessRightsCs.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
            (cr0.protection_enable == 1))
        {
            ASSERT(accessRights.descriptor_privilege_level == 0);
        }
        break;

        default:

        if ((unrestricted_guest == false) &&
            (accessRights.unusable == 0) &&
            (/*(accessRights.Type >= 0) &&*/
                (accessRights.type <= 11)))
        {
            ASSERT(accessRights.descriptor_privilege_level >= selector.request_privilege_level);
        }
        break;
    }

    //
    // Bit 7 (P)
    //
    if ((segment_type == SegmentCs) ||
        (accessRights.unusable == 0))
    {
        ASSERT(accessRights.present == 1);
    }

    //
    // Bits 11:8 (reserved) and bits 31:17 (reserved)
    //
    if ((segment_type == SegmentCs) ||
        (accessRights.unusable == 0))
    {
        ASSERT(accessRights.Reserved1 == 0);
        ASSERT(accessRights.Reserved2 == 0);
    }

    //
    // Bit 14 (D/B)
    //
    if (segment_type == SegmentCs)
    {
        if ((ia32e_mode_guest != false) &&
            (accessRights.long_mode == 1))
        {
            ASSERT(accessRights.default_big == 0);
        }
    }

    //
    // Bit 15 (G)
    //
    if ((segment_type == SegmentCs) ||
        (accessRights.unusable == 0))
    {
        if (!MV_IS_FLAG_SET(segment_limit, 0xfff))
        {
            ASSERT(accessRights.granularity == 0);
        }
        if (MV_IS_FLAG_SET(segment_limit, 0xfff00000))
        {
            ASSERT(accessRights.granularity == 1);
        }
    }
}