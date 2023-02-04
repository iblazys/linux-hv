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

typedef union _CR_FIXED
{
	uint64_t Flags;

	struct
	{
		unsigned long Low;
		long          High;

	} Fields;

} CR_FIXED, * PCR_FIXED;

extern VIRTUAL_CPU_STATE* g_GuestState;

void testFunc(void);

bool InitVMM(void);
bool ShutdownVMM(void);
bool CheckCPUFeatures(void);

void AllocateVMRegionOnAllCPU(void); // current

void AdjustCR4AndCr0Bits(void);

// not complete
bool AllocateVMRegion(void);

#endif