#ifndef LINUXHV_VMX_H
#define LINUXHV_VMX_H
#include "vmm.h"

bool VmxOnInitRegion(GUEST_CPU_STATE* vcpu);
bool VmxOn(void* vmxon_phys);
void VmxOff(void);
void LaunchCpu(void);

#endif