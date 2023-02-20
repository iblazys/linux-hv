#ifndef __LINUXHV_VMCS_H
#define __LINUXHV_VMCS_H

#include "vmm.h"
#include "ia32.h"

int vmcs_allocate_vmcs_region(struct virtual_cpu* vcpu);
void vmcs_free_vmcs_region(struct virtual_cpu* vcpu);

// The motherlode
void vmcs_setup_vmcs(struct virtual_cpu* vcpu);
void vmcs_setup_controls(struct virtual_cpu* vcpu);
void vmcs_setup_guest(struct virtual_cpu* vcpu);
void vmcs_setup_host(struct virtual_cpu* vcpu);

uint64_t vmcs_get_segment_base(uint64_t GdtBase, uint16_t SegmentSelector);
uint32_t vmcs_get_segment_access_rights(uint16_t SegmentSelector);

ia32_vmx_basic_register vmcs_get_basic_controls(void); //int64 return type?
void vmcs_adjust_control_bits(uint32_t capability_msr, uint64_t* value);

void vmcs_set_entry_controls(ia32_vmx_entry_ctls_register* entry_controls);
void vmcs_set_exit_controls(ia32_vmx_exit_ctls_register* exit_controls);
void vmcs_set_pinbased_controls(ia32_vmx_pinbased_ctls_register* pinbased_controls);
void vmcs_set_procbased_controls(ia32_vmx_procbased_ctls_register* procbased_controls);
void vmcs_set_secondary_controls(ia32_vmx_procbased_ctls2_register* secondary_controls);

#endif