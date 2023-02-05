#ifndef LINUXHV_VMCS_H
#define LINUXHV_VMCS_H

#include "vmm.h"
#include "../ia32-doc/out/ia32.h"

bool VmcsInitRegion(VIRTUAL_CPU* currentvCpu); // VmcsInitRegion
bool VmcsLoad(void *vmcsPhysAddr);
bool VmcsClear(void* vmcsPhysAddr);

void VmcsSetup(VIRTUAL_CPU* currentvCpu);
void VmcsSetupControls(void);
void VmcsSetupGuest(VIRTUAL_CPU* currentvCpu);
void VmcsSetupHost(VIRTUAL_CPU* currentvCpu);

uint64_t VmcsGetSegmentBase(uint64_t GdtBase, uint16_t SegmentSelector);
uint32_t VmcsGetSegmentAccessRights(uint16_t SegmentSelector);

IA32_VMX_BASIC_REGISTER GetBasicControls(void);
void AdjustControlBits(UINT32 CapabilityMSR, UINT64* Value);

void SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* entryControls);
void SetExitControls(IA32_VMX_EXIT_CTLS_REGISTER* ExitControls);
void SetPinbasedControls(IA32_VMX_PINBASED_CTLS_REGISTER* PinbasedControls);
void SetProcbasedControls(IA32_VMX_PROCBASED_CTLS_REGISTER* ProcbasedControls);
void SetSecondaryControls(IA32_VMX_PROCBASED_CTLS2_REGISTER* SecondaryControls);

void VmcsDestroy(void);

#endif