#ifndef LINUXHV_VMM_H
#define LINUXHV_VMM_H

#include <linux/kernel.h>
#include "../ia32-doc/out/ia32.h"

#define PAGE_SIZE 4096

typedef struct _VIRTUAL_CPU_STACK
{
    // The stack for the vm exit handler, must be at the top of the struct
    uint8_t VmExitHandlerStack[4096 - sizeof(struct VIRTUAL_CPU*)];

    // The virtual cpu this vm exit stack belongs to
    struct VIRTUAL_CPU* VirtualCPU;

} VIRTUAL_CPU_STACK, *PVIRTUAL_CPU_STACK;

typedef struct _CPU_STATE
{
    SEGMENT_DESCRIPTOR_REGISTER_64 Gdtr;
    SEGMENT_DESCRIPTOR_REGISTER_64 Idtr;

    SEGMENT_SELECTOR CS;

} CPU_STATE, *PCPU_STATE;

typedef struct _VIRTUAL_CPU
{
    // Pointer to the VM exit handler
    void* VmExitHandler;

    // The pointer to the stack for the vm exit handler
    VIRTUAL_CPU_STACK* VmExitStack;

    // Set if cpu failed during setup or launch
    bool LaunchFailed;

    // The current processor ID
    uint16_t ProcessorId;

    uint64_t RIP;
    uint64_t RSP;
    uint64_t RFlags;

    uint64_t VmxonRegionPhysicalAddress;
    uint64_t VmxonRegionVirtualAddress;
    uint64_t VmcsRegionPhysicalAddress;	// only needs to be 32 bit
    uint64_t VmcsRegionVirtualAddress;
    uint64_t MsrBitmapVirtualAddress; 
    uint64_t MsrBitmapPhysicalAddress;
                                                    
    uint64_t VmmStack;

    // The saved CPU state
    CPU_STATE CpuState;

    // Pointer to the VMM state
    void* VmmStatePtr;
} VIRTUAL_CPU, * PVIRTUAL_CPU;

typedef struct VMM_STATE
{
    bool IsRunning;
    VIRTUAL_CPU* GuestCPUs;
    
    // Controls
    // Capabilites
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

extern VIRTUAL_CPU* g_VMMContext;

VMM_STATE* VmmInit(void); 
bool VmmShutdown(void* info);

void VmmDestroy(VMM_STATE* vmmState);

void VmmVirtualizeSingleCpu(void* info, u64 ip, u64 sp, u64 flags);

void AdjustCR4AndCr0Bits(void); // complete


#endif