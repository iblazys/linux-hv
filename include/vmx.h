#ifndef _LINUXHV_VMX_H
#define _LINUXHV_VMX_H

#include "vmm.h"

typedef union
{
	struct
	{
		unsigned long low;
		long          high;
	} fields;

    uint64_t as_uint;

} cr_fixed;

int vmx_allocate_vmxon_region(struct virtual_cpu* vcpu);
void vmx_free_vmxon_region(struct virtual_cpu* vcpu);

int vmx_prepare_to_launch(struct virtual_cpu* vcpu);

void vmx_adjust_control_registers(void);

#endif