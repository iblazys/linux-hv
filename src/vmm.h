#ifndef LINUXHV_VMM_H
#define LINUXHV_VMM_H

#include <linux/kernel.h>

typedef struct _VIRTUAL_CPU_STATE
{
    bool IsOnVmxRootMode;
    bool IncrementRip;

    uint64_t VmxonRegionPhysicalAddress;
    uint64_t VmxonRegionVirtualAddress;
    uint64_t VmcsRegionPhysicalAddress;	
    uint64_t VmcsRegionVirtualAddress;
    uint64_t MsrBitmapVirtualAddress; 
    uint64_t MsrBitmapPhysicalAddress;
                                                    
    uint64_t VmmStack;                                    
} VIRTUAL_CPU_STATE, * PVIRTUAL_CPU_STATE;

bool InitVMM(void);
bool CheckCPUFeatures(void);

#endif