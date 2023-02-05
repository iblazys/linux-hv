#ifndef LINUXHV_VMM_H
#define LINUXHV_VMM_H

#include <linux/kernel.h>

#define PAGE_SIZE 4096

typedef struct _GUEST_CPU_STATE
{
    bool IsOnVmxRootMode;
    bool LaunchFailed;

    uint64_t VmxonRegionPhysicalAddress;
    uint64_t VmxonRegionVirtualAddress;
    uint64_t VmcsRegionPhysicalAddress;	
    uint64_t VmcsRegionVirtualAddress;
    uint64_t MsrBitmapVirtualAddress; 
    uint64_t MsrBitmapPhysicalAddress;
                                                    
    uint64_t VmmStack;                                    
} GUEST_CPU_STATE, * PGUEST_CPU_STATE;

typedef struct VMM_STATE
{
    bool IsRunning;
    GUEST_CPU_STATE* GuestCPUs;
} VMM_STATE, * PVMM_STATE;

typedef union _CR_FIXED
{
	uint64_t Flags;

	struct
	{
		unsigned long Low;
		long          High;

	} Fields;

} CR_FIXED, * PCR_FIXED;

extern GUEST_CPU_STATE* g_VMMContext;

VMM_STATE* VmmInit(void); 
bool VmmShutdown(void* info);

void VmmDestroy(VMM_STATE* vmmState);

void InitSingleCPU(void* info, u64 ip, u64 sp, u64 flags);

void AdjustCR4AndCr0Bits(void); // complete


#endif