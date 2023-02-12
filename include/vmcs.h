#ifndef __LINUXHV_VMCS_H
#define __LINUXHV_VMCS_H

#include "vmm.h"

int vmcs_allocate_vmcs_region(struct virtual_cpu* vcpu);
void vmcs_free_vmcs_region(struct virtual_cpu* vcpu);

#endif