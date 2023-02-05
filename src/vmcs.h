#ifndef LINUXHV_VMCS_H
#define LINUXHV_VMCS_H

#include "vmm.h"
#include "../ia32-doc/out/ia32.h"

bool VmcsInitRegion(GUEST_CPU_STATE* vcpu); // VmcsInitRegion
bool VmcsLoad(void);
bool VmcsClear(void);

void VmcsSetup(void);
void VmcsSetupControls(void);
void VmcsSetupGuest(void);
void VmcsSetupHost(void);

IA32_VMX_BASIC_REGISTER GetBasicControls(void);
void AdjustControlBits(UINT32 CapabilityMSR, UINT64* Value);

void SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* entryControls);

void VmcsDestroy(void);

#endif