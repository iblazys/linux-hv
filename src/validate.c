#include "validate.h"

/**
 * @file validate.c
 * @author extended by Matt Blazys (https://github.com/iblazys)
 * 
 * originally written by Satoshi Tanda (tanda.sat@gmail.com)
 * 
 * @brief Checks validity of the guest VMCS fields for VM-entry as per
 *      26.3 CHECKING AND LOADING GUEST STATE
 * @version 0.1
 * @date 2023-02-18
 *
 * @details This file implements part of checks performed by a processor during
 *      VM-entry as CheckGuestVmcsFieldsForVmEntry(). This can be called on VM-exit
 *      reason 33 (0x21), VM-entry failure due to invalid guest state as below
 *      in order to find out exactly which checks failed. Code is written for
 *      linux based kernel modules.
 *
 * @code{.c}
 *      switch (vmExitReason)
 *      {
 *      case VMX_EXIT_REASON_ERROR_INVALID_GUEST_STATE:
 *          CheckGuestVmcsFieldsForVmEntry();
 *          // ...
 * @endcode
 */

void validate_guest_entry_state(void)
{
    // WHY INTEL.... WHY

    pr_info("linux-hv: validating guest entry state...");

    vmentry_interrupt_information interrupt_info;
    ia32_vmx_entry_ctls_register entry_controls;
    ia32_vmx_pinbased_ctls_register pinbased_controls;
    ia32_vmx_procbased_ctls_register procbased_controls;
    ia32_vmx_procbased_ctls2_register secondary_controls;

    rflags rflags;
    bool unrestricted_guest;
    uint32_t physical_address_width_in_bits;

    rflags.AsUInt = vmread(VMCS_GUEST_RFLAGS);

    interrupt_info.AsUInt = vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD);
    entry_controls.AsUInt = vmread(VMCS_CTRL_VMENTRY_CONTROLS);
    pinbased_controls.AsUInt = vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS);
    procbased_controls.AsUInt = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    secondary_controls.AsUInt = vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    unrestricted_guest = ((procbased_controls.activate_secondary_controls == 1) &&
                         (secondary_controls.unrestricted_guest == 1));

    cpuid_eax_80000008 cpuid;
    __get_cpuid(0x80000008, &cpuid.eax.AsUInt, &cpuid.ebx.AsUInt, &cpuid.ecx.AsUInt, &cpuid.edx.AsUInt);

    physical_address_width_in_bits = cpuid.eax.number_of_physical_address_bits;

    //
    // 27.3.1.1 Checks on Guest Control Registers, Debug Registers, and MSRs
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
    

    // If the “IA-32e mode guest” VM-entry control is 0, bit 17 in the CR4 field (corresponding to CR4.PCIDE)
    // must be 0 - not implemented


    // The CR3 field must be such that bits 63:52 and bits in the range 51:32 beyond the processor’s 
    // physical address width are 0.
    ASSERT(validate_is_within_physical_width(physical_address_width_in_bits, __readcr3()) == 1);

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
    ASSERT(entry_controls.load_ia32_pat == 0); // not implemented

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
    // 27.3.1.2 Checks on Guest Segment Registers
    //

    // This section specifies the checks on the fields for CS, SS, DS, ES, FS, GS, TR, and LDTR
    
    segment_selector selector;
    vmx_segment_access_rights accessRights;
    // uint32_t segmentLimit;
    
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

        base_address = vmread(VMCS_GUEST_TR_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        base_address = vmread(VMCS_GUEST_FS_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        base_address = vmread(VMCS_GUEST_GS_BASE);
        validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

        // LDTR. If LDTR is usable, the address must be canonical
        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

        if(accessRights.unusable == 0)
        {
            base_address = vmread(VMCS_GUEST_LDTR_BASE);
            validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);
        }

        // CS. Bits 63:32 of the address must be zero.
        base_address = vmread(VMCS_GUEST_CS_BASE);
        pr_info("CS_BASE: %llx", base_address);
           
        ASSERT((base_address >> 32) == 0);

        // SS, DS, ES. If the register is usable, bits 63:32 of the address must be zero.
        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = vmread(VMCS_GUEST_SS_BASE);
            ASSERT((base_address >> 32) == 0);
        }

        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = vmread(VMCS_GUEST_DS_BASE);
            ASSERT((base_address >> 32) == 0);
        }

        accessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);
        if(accessRights.unusable == 0)
        {
            base_address = vmread(VMCS_GUEST_ES_BASE);
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

    // Access Rights ...

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
        
        validate_segment_access_rights(SegmentTr,
                                (uint32_t)vmread(VMCS_GUEST_TR_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_TR_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_TR_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);

        validate_segment_access_rights(SegmentLdtr,
                                (uint32_t)vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS),
                                (uint32_t)vmread(VMCS_GUEST_LDTR_LIMIT),
                                (uint16_t)vmread(VMCS_GUEST_LDTR_SELECTOR),
                                (entry_controls.ia32e_mode_guest != false),
                                unrestricted_guest);
    }

    //
    // 27.3.1.3 Checks on Guest Descriptor-Table Registers
    //

    // The following checks are performed on the fields for GDTR and IDTR

    // On processors that support Intel 64 architecture, the base-address fields must contain canonical addresses

    base_address = vmread(VMCS_GUEST_GDTR_BASE);
    validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

    base_address = vmread(VMCS_GUEST_IDTR_BASE);
    validate_is_canonical_address((void*)base_address, __FILE__, __LINE__);

    // Bits 31:16 of each limit field must be 0
    uint64_t gdtr_limit = vmread(VMCS_GUEST_GDTR_LIMIT);
    uint64_t idtr_limit = vmread(VMCS_GUEST_IDTR_LIMIT);

    pr_info("gdtr limit: %llx", gdtr_limit); // WHY 0 DAFUQ
    pr_info("idtr limit: %llx", idtr_limit); // same here

        // TODO

    //
    // 26.3.1.4 Checks on Guest RIP, RFLAGS, and SSP
    //

    //
    // RIP
    //

    // Bits 63:32 must be 0 if the “IA-32e mode guest” VM-entry control is 0 or if the L bit (bit 13) in the access-
    // rights field for CS is 0
    vmx_segment_access_rights csAccessRights;
    csAccessRights.AsUInt = (uint32_t)vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((entry_controls.ia32e_mode_guest == 0) ||
        (csAccessRights.long_mode == 0))
    {
        ASSERT((vmread(VMCS_GUEST_RIP) & ~__UINT16_MAX__) == 0);
    }

    //
    // RFLAGS
    //

    // Reserved bits 63:22 (bits 31:22 on processors that do not support Intel 64 architecture), bit 15, bit 5 and
    // bit 3 must be 0 in the field, and reserved bit 1 must be 1.
    ASSERT(rflags.Reserved1 == 0);
    ASSERT(rflags.Reserved2 == 0);
    ASSERT(rflags.Reserved3 == 0);
    ASSERT(rflags.Reserved4 == 0);
    ASSERT(rflags.read_as_1 == 1);

    // The VM flag (bit 17) must be 0 either if the “IA-32e mode guest” VM-entry control is 1 or if bit 0 in the CR0
    // field (corresponding to CR0.PE) is 0.
    if((entry_controls.ia32e_mode_guest == 1) ||
        (cr0.protection_enable == 0))
    {
        ASSERT(rflags.virtual_8086_mode_flag == 0);
    }

    // The IF flag (RFLAGS[bit 9]) must be 1 if the valid bit (bit 31) in the VM-entry interruption-information field
    // is 1 and the interruption type (bits 10:8) is external interrupt
    if ((interrupt_info.valid == 1) &&
        (interrupt_info.interruption_type == external_interrupt))
    {
        ASSERT(rflags.interrupt_enable_flag == 1);
    }

    //
    // SSP. The following checks are performed if the “load CET state” VM-entry control is 1
    //
    ASSERT(entry_controls.load_cet_state == 0); // not implemented
    

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

    /*
    The activity-state field must contain a value in the range 0 – 3, indicating an activity state supported by the
    implementation (see Section 25.4.2). Future processors may include support for other activity states.
    Software should read the VMX capability MSR IA32_VMX_MISC (see Appendix A.6) to determine what
    activity states are supported
    */

    ASSERT((activityState == vmx_active) ||
              (activityState == vmx_hlt) ||
              (activityState == vmx_shutdown) ||
              (activityState == vmx_wait_for_sipi));

    /*
    The activity-state field must not indicate the HLT state if the DPL (bits 6:5) in the access-rights field for SS
    is not 0. 
    */
    if (ssAccessRights.descriptor_privilege_level != 0)
    {
        ASSERT(activityState != vmx_hlt);
    }

    /*
    The activity-state field must indicate the active state if the interruptibility-state field indicates blocking by
    either MOV-SS or by STI (if either bit 0 or bit 1 in that field is 1)
    */
    if ((interruptibilityState.blocking_by_sti == 1) ||
        (interruptibilityState.blocking_by_mov_ss == 1))
    {
        ASSERT(activityState != vmx_active);
    }

    /*
    If the valid bit (bit 31) in the VM-entry interruption-information field is 1, the interruption to be delivered
    (as defined by interruption type and vector) must not be one that would normally be blocked while a logical
    processor is in the activity state corresponding to the contents of the activity-state field. The following
    items enumerate the interruptions (as specified in the VM-entry interruption-information field) whose
    injection is allowed for the different activity states

    See Table 25-16 in Section 25.8.3 for details regarding the format of the VM-entry interruption-
    information field.
    */

    if (interrupt_info.valid == 1)
    {
        /*
        HLT. The only events allowed are the following:
        */
        if (activityState == vmx_hlt)
        {
            // Those with interruption type external interrupt or non-maskable interrupt (NMI)
            if ((interrupt_info.interruption_type == external_interrupt) ||
                (interrupt_info.interruption_type == non_maskable_interrupt))
            {
                ;
            }

            /*
            Those with interruption type hardware exception and vector 1 (debug exception) or vector 18
            (machine-check exception)
            */
            else if ((interrupt_info.interruption_type == hardware_exception) &&
                     ((interrupt_info.vector == debug) ||
                      (interrupt_info.vector == machine_check)))
            {
                ;
            }

            // Those with interruption type other event and vector 0 (pending MTF VM exit)
            else if ((interrupt_info.interruption_type == other_event) &&
                     (interrupt_info.vector == 0 /* pending MTF VM exit */ ))
            {
                ;
            }
            else
            {
                // Unallowed interrupt
                ASSERT(false);
            }
        }

        /*
        Shutdown. Only NMIs and machine-check exceptions are allowed
        */
        else if (activityState == vmx_shutdown)
        {
            ASSERT((interrupt_info.vector == nmi) ||
                      (interrupt_info.vector == machine_check));
        }

        /* 
        Wait-for-SIPI. No interruptions are allowed.
        */
        else if (activityState == vmx_wait_for_sipi)
        {
            ASSERT(false);
        }
    }

    // The activity-state field must not indicate the wait-for-SIPI state if the “entry to SMM” VM-entry control is 1
    if (entry_controls.entry_to_smm == 1)
    {
        ASSERT(activityState != vmx_wait_for_sipi);
    }

    //
    // Interruptibility state
    //

    // The reserved bits (bits 31:5) must be 0
    ASSERT(interruptibilityState.Reserved1 == 0);

    // The field cannot indicate blocking by both STI and MOV SS (bits 0 and 1 cannot both be 1)
    ASSERT((interruptibilityState.blocking_by_sti == false) ||
              (interruptibilityState.blocking_by_mov_ss == false));

    // Bit 0 (blocking by STI) must be 0 if the IF flag (bit 9) is 0 in the RFLAGS field
    if (rflags.interrupt_enable_flag == 0)
    {
        ASSERT(interruptibilityState.blocking_by_sti == 0);
    }

    /*
    Bit 0 (blocking by STI) and bit 1 (blocking by MOV-SS) must both be 0 if the valid bit (bit 31) in the
    VM-entry interruption-information field is 1 and the interruption type (bits 10:8) in that field has value 0,
    indicating external interrupt, or value 2, indicating non-maskable interrupt (NMI)
    */
    if ((interrupt_info.valid == 1) &&
        ((interrupt_info.interruption_type == external_interrupt) ||
         (interrupt_info.interruption_type == non_maskable_interrupt)))
    {
        ASSERT(interruptibilityState.blocking_by_sti == 0);
        ASSERT(interruptibilityState.blocking_by_mov_ss == 0);
    }

    // Bit 2 (blocking by SMI) must be 0 if the processor is not in SMM
    ASSERT(interruptibilityState.blocking_by_smi == 0);

    // Bit 2 (blocking by SMI) must be 1 if the “entry to SMM” VM-entry control is 1
    if (entry_controls.entry_to_smm == 1)
    {
        ASSERT(interruptibilityState.blocking_by_smi == 1);
    }

    /*
    Bit 3 (blocking by NMI) must be 0 if the “virtual NMIs” VM-execution control is 1, the valid bit (bit 31) in the
    VM-entry interruption-information field is 1, and the interruption type (bits 10:8) in that field has value 2
    (indicating NMI).
    */
    if ((pinbased_controls.virtual_nmi == 1) &&
        (interrupt_info.valid == 1) &&
        (interrupt_info.interruption_type == non_maskable_interrupt))
    {
        ASSERT(interruptibilityState.blocking_by_nmi == 0);
    }

    /*
    If bit 4 (enclave interruption) is 1, bit 1 (blocking by MOV-SS) must be 0 and the processor must support
    for SGX by enumerating CPUID.(EAX=07H,ECX=0):EBX.SGX[bit 2] as 1.
    */
    if (interruptibilityState.enclave_interruption == 1)
    {
        ASSERT(interruptibilityState.blocking_by_mov_ss == 0);

        // todo: cpuid
    }
    
    //
    // Pending debug exceptions
    //

    /*
    Bits 11:4, bit 13, bit 15, and bits 63:17 (bits 31:17 on processors that do not support Intel 64 archi-
    tecture) must be 0
    */

    //
    // VMCS link pointer checks
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

        // A VM entry to a guest that does not use PAE paging does not check the validity of any PDPTEs.
    }

    pr_info("linux-hv: reached end of guest validation.");

    // now wut
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

    // The intel manual jumps around alot here (as these checks can be performed in any order)
    // so I've tried to make it as clear as possible

    // The checks on each bit vary for each segment.

    switch (segment_type)
    {
        // ------ CS CHECKS -------
        case SegmentCs:
        {
            //
            // Bits 3:0 (Type)
            //

            // The values allowed depend on the setting of the “unrestricted guest” VM-execution control

            // If the control is 0, the Type must be 9, 11, 13, or 15 (accessed code segment)
            if (unrestricted_guest == false)
            {
                ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
            }
            else
            {

            // If the control is 1, the Type must be either 3 (read/write accessed expand-up data segment)
            // or one of 9, 11, 13, and 15 (accessed code segment)

                ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //

            ASSERT(accessRights.descriptor_type == 1);

            //
            // Bits 6:5 (DPL).
            //

            // If the Type is 3 (read/write accessed expand-up data segment) 
            if(accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED)
            {
                // The DPL must be 0.
                ASSERT(accessRights.descriptor_privilege_level == 0);

                // Type can be 3 only if the “unrestricted guest” VM-execution control is 1.
                ASSERT(unrestricted_guest == true);
            }

            // If the Type is 9 or 11 (non-conforming code segment), the DPL must equal the DPL in the
            // access-rights field for SS.
            if((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED))
            {
                ASSERT(accessRights.descriptor_privilege_level == accessRightsSs.descriptor_privilege_level);
            }

            // If the Type is 13 or 15 (conforming code segment), the DPL cannot be greater than the
            // DPL in the access-rights field for SS.
            if((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED))
            {
                ASSERT(accessRights.descriptor_privilege_level <= accessRightsSs.descriptor_privilege_level);
            }
            
            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //
            ASSERT(accessRights.present == 1);
            
            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //
            ASSERT(accessRights.Reserved1 == 0);

            //
            // Bit 14 (D/B). For CS, D/B must be 0 if the guest will be IA-32e mode and the L bit (bit 13) in the
            // access-rights field is 1.
            if((ia32e_mode_guest == true) &&
                (accessRights.long_mode == 1))
            {
                ASSERT(accessRights.default_big == 0);
            }

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //

            // If any bit in the limit field in the range 11:0 is 0, G must be 0.
            unsigned int mask = 0xFFF;

            if((segment_limit & mask) != mask)
            {
                // At least one bit in range 11:0 is 0
                ASSERT(accessRights.granularity == 0);
            }

            // If any bit in the limit field in the range 31:20 is 1, G must be 1
            mask = 0xFFFFF000;

            if((segment_limit & mask) != mask)
            {
                ASSERT(accessRights.granularity == 1);
            }

            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            mask = 0xFFFE0000;
            ASSERT((accessRights.Reserved2 & mask) == 0);

            break;
        }

        // ------ SS CHECKS -------
        case SegmentSs:
        {
            //
            // Bits 3:0 (Type)
            //
            
            // If SS is usable, the Type must be 3 or 7 (read/write, accessed data segment)
            if(accessRights.unusable == 0) 
            {
                ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED));
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.descriptor_type == 1);
            }

            //
            // Bits 6:5 (DPL).
            //

            // If the “unrestricted guest” VM-execution control is 0, the DPL must equal the RPL from the
            // selector field.
            if (unrestricted_guest == false)
            {
                ASSERT(accessRights.descriptor_privilege_level == selector.request_privilege_level);
            }

            // The DPL must be 0 either if the Type in the access-rights field for CS is 3 (read/write
            // accessed expand-up data segment) or if bit 0 in the CR0 field (corresponding to CR0.PE) is 0
            if ((accessRightsCs.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                (cr0.protection_enable == 0))
            {
                ASSERT(accessRights.descriptor_privilege_level == 0);
            }

            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.present == 1);
            }

            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.Reserved1 == 0);
            }

            //
            // Bit 14 (D/B). - Only checks for CS.
            //

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //
            if(accessRights.unusable == 0)
            {
                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }
            }

            //
            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            //
            
            if(accessRights.unusable == 0)
            {
                unsigned int mask = 0xFFFE0000;
                ASSERT((accessRights.Reserved2 & mask) == 0);
            }
            
            break;
        }

        // ------ DS CHECKS -------
        case SegmentDs:
        {
            //
            // Bits 3:0 (Type)
            //

            // The following checks apply if the register is usable
            if(accessRights.unusable == 0)
            {
                // Bit 0 of the Type must be 1 (accessed).
                ASSERT((accessRights.type >> 0) & 1);

                // If bit 3 of the Type is 1 (code segment), then bit 1 of the Type must be 1 (readable)
                if((accessRights.type >> 3) & 1) 
                {
                    ASSERT((accessRights.type >> 1) & 1);
                }
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.descriptor_type == 1);
            }

            //
            // Bits 6:5 (DPL).
            //

            // The DPL cannot be less than the RPL in the selector field if (1) the
            // “unrestricted guest” VM-execution control is 0; (2) the register is usable; and (3) the Type in
            // the access-rights field is in the range 0 – 11 (data segment or non-conforming code segment).
            if((unrestricted_guest == false) &&
                (accessRights.unusable == 0) &&
                (accessRights.type <= 11))
            {
                ASSERT(accessRights.descriptor_privilege_level >= selector.request_privilege_level);
            }

            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.present == 1);
            }

            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //
            
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.Reserved1 == 0);
            }

            //
            // Bit 14 (D/B). - Only checks for CS.
            //

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //
            if(accessRights.unusable == 0)
            {
                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }
            }

            //
            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            //
            
            if(accessRights.unusable == 0)
            {
                unsigned int mask = 0xFFFE0000;
                ASSERT((accessRights.Reserved2 & mask) == 0);
            }
            
            break;
        }

        // ------ ES CHECKS -------
        case SegmentEs:
        {
            //
            // Bits 3:0 (Type)
            //

            // The following checks apply if the register is usable
            if(accessRights.unusable == 0)
            {
                // Bit 0 of the Type must be 1 (accessed).
                ASSERT((accessRights.type >> 0) & 1);

                // If bit 3 of the Type is 1 (code segment), then bit 1 of the Type must be 1 (readable)
                if((accessRights.type >> 3) & 1) 
                {
                    ASSERT((accessRights.type >> 1) & 1);
                }
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.descriptor_type == 1);
            }

            ///
            // Bits 6:5 (DPL).
            //

            // The DPL cannot be less than the RPL in the selector field if (1) the
            // “unrestricted guest” VM-execution control is 0; (2) the register is usable; and (3) the Type in
            // the access-rights field is in the range 0 – 11 (data segment or non-conforming code segment).
            if((unrestricted_guest == false) &&
                (accessRights.unusable == 0) &&
                (accessRights.type <= 11))
            {
                ASSERT(accessRights.descriptor_privilege_level >= selector.request_privilege_level);
            }

            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.present == 1);
            }

            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //
            
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.Reserved1 == 0);
            }

            //
            // Bit 14 (D/B). - Only checks for CS.
            //

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //
            if(accessRights.unusable == 0)
            {
                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }
            }

            //
            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            //
            
            if(accessRights.unusable == 0)
            {
                unsigned int mask = 0xFFFE0000;
                ASSERT((accessRights.Reserved2 & mask) == 0);
            }

            break;
        }

        // ------ FS CHECKS -------
        case SegmentFs:
        {
            //
            // Bits 3:0 (Type)
            //

            // The following checks apply if the register is usable
            if(accessRights.unusable == 0)
            {
                // Bit 0 of the Type must be 1 (accessed).
                ASSERT((accessRights.type >> 0) & 1);

                // If bit 3 of the Type is 1 (code segment), then bit 1 of the Type must be 1 (readable)
                if((accessRights.type >> 3) & 1) 
                {
                    ASSERT((accessRights.type >> 1) & 1);
                }
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.descriptor_type == 1);
            }

            ///
            // Bits 6:5 (DPL).
            //

            // The DPL cannot be less than the RPL in the selector field if (1) the
            // “unrestricted guest” VM-execution control is 0; (2) the register is usable; and (3) the Type in
            // the access-rights field is in the range 0 – 11 (data segment or non-conforming code segment).
            if((unrestricted_guest == false) &&
                (accessRights.unusable == 0) &&
                (accessRights.type <= 11))
            {
                ASSERT(accessRights.descriptor_privilege_level >= selector.request_privilege_level);
            }

            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.present == 1);
            }

            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //
            
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.Reserved1 == 0);
            }

            //
            // Bit 14 (D/B). - Only checks for CS.
            //

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //
            if(accessRights.unusable == 0)
            {
                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }
            }

            //
            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            //
            
            if(accessRights.unusable == 0)
            {
                unsigned int mask = 0xFFFE0000;
                ASSERT((accessRights.Reserved2 & mask) == 0);
            }

            break;
        }

        // ------ GS CHECKS -------
        case SegmentGs:
        {
            //
            // Bits 3:0 (Type)
            //

            // The following checks apply if the register is usable
            if(accessRights.unusable == 0)
            {
                // Bit 0 of the Type must be 1 (accessed).
                ASSERT((accessRights.type >> 0) & 1);

                // If bit 3 of the Type is 1 (code segment), then bit 1 of the Type must be 1 (readable)
                if((accessRights.type >> 3) & 1) 
                {
                    ASSERT((accessRights.type >> 1) & 1);
                }
            }

            //
            // Bit 4 (S). If the register is CS or if the register is usable, S must be 1
            //
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.descriptor_type == 1);
            }

            ///
            // Bits 6:5 (DPL).
            //

            // The DPL cannot be less than the RPL in the selector field if (1) the
            // “unrestricted guest” VM-execution control is 0; (2) the register is usable; and (3) the Type in
            // the access-rights field is in the range 0 – 11 (data segment or non-conforming code segment).
            if((unrestricted_guest == false) &&
                (accessRights.unusable == 0) &&
                (accessRights.type <= 11))
            {
                ASSERT(accessRights.descriptor_privilege_level >= selector.request_privilege_level);
            }

            //
            // Bit 7 (P). If the register is CS or if the register is usable, P must be 1.
            //

            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.present == 1);
            }

            //
            // Bits 11:8 (reserved). If the register is CS or if the register is usable, these bits must all be 0.
            //
            
            if(accessRights.unusable == 0)
            {
                ASSERT(accessRights.Reserved1 == 0);
            }

            //
            // Bit 14 (D/B). - Only checks for CS.
            //

            //
            // Bit 15 (G). The following checks apply if the register is CS or if the register is usable
            //
            if(accessRights.unusable == 0)
            {
                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }
            }

            //
            // Bits 31:17 (reserved). If the register is CS or if the register is usable, these bits must all be 0
            //
            
            if(accessRights.unusable == 0)
            {
                unsigned int mask = 0xFFFE0000;
                ASSERT((accessRights.Reserved2 & mask) == 0);
            }

            break;
        }

        // ------ TR CHECKS -------
        case SegmentTr:
        {
            //
            // Bits 3:0 (Type)
            //

            // If the guest will not be IA-32e mode, the Type must be 3 (16-bit busy TSS) or 11 (32-bit busy TSS)
            if (ia32e_mode_guest == 0)
            {
                ASSERT((accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                        (accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED));
            }
            else
            {
                // If the guest will be IA-32e mode, the Type must be 11 (64-bit busy TSS)
                ASSERT(accessRights.type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED);
            }

            //
            // Bit 4 (S). S must be 0.
            //
            ASSERT(accessRights.descriptor_type == 0);

            //
            // Bit 7 (P). P must be 1.
            //
            ASSERT(accessRights.present == 1);
            
            //
            // Bits 11:8 (reserved). These bits must all be 0
            //
            ASSERT(accessRights.Reserved1 == 0);

            //
            // Bit 15 (G)
            //

            // If any bit in the limit field in the range 11:0 is 0, G must be 0.
            if (!MV_IS_FLAG_SET(segment_limit, 0xfff))
            {
                ASSERT(accessRights.granularity == 0);
            }

            // If any bit in the limit field in the range 31:20 is 1, G must be 1
            if (MV_IS_FLAG_SET(segment_limit, 0xfff00000))
            {
                ASSERT(accessRights.granularity == 1);
            }

            //
            // Bit 16 (Unusable). The unusable bit must be 0.
            //
            ASSERT(accessRights.unusable == 0);

            //
            // Bits 31:17 (reserved). These bits must all be 0
            //
            ASSERT(accessRights.Reserved2 == 0);

            break;
        }

        // ------ LDTR CHECKS -------
        case SegmentLdtr:
        {
            // The following checks on the different sub-fields apply only if LDTR is usable
            if(accessRights.unusable == 0)
            {
                //
                // Bits 3:0 (Type). The Type must be 2 (LDT)
                //
                ASSERT(accessRights.type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE);

                //
                // Bit 4 (S). S must be 0.
                //
                ASSERT(accessRights.descriptor_type == 0);

                //
                // Bit 7 (P). P must be 1.
                //
                ASSERT(accessRights.present == 1);

                //
                // Bits 11:8 (reserved). These bits must all be 0
                //
                ASSERT(accessRights.Reserved1 == 0);

                //
                // Bit 15 (G)
                //

                // If any bit in the limit field in the range 11:0 is 0, G must be 0.
                unsigned int mask = 0xFFF;

                if((segment_limit & mask) != mask)
                {
                    // At least one bit in range 11:0 is 0
                    ASSERT(accessRights.granularity == 0);
                }

                // If any bit in the limit field in the range 31:20 is 1, G must be 1
                mask = 0xFFFFF000;

                if((segment_limit & mask) != mask)
                {
                    ASSERT(accessRights.granularity == 1);
                }

                //
                // Bits 31:17 (reserved). These bits must all be 0
                //

                ASSERT(accessRights.Reserved2 == 0);
            }

            break;
        }

        default:
        {
            pr_err("UNHANDLED SEGMENT TYPE");
            ASSERT(false);
            break;
        }
    }
}