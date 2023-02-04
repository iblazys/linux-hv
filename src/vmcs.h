#ifndef LINUXHV_VMCS_H
#define LINUXHV_VMCS_H
#include "vmm.h"

bool AllocVmcsRegion(GUEST_CPU_STATE* vcpu);

#endif